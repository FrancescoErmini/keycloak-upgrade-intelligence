"""Detection engine: executes approved rules against realm snapshots and runtime logs.

No LLM is involved here. Version awareness: a breaking change is only evaluated when
source_version < introduced_in <= target_version; rules that do not apply are reported
in the assessment summary with the reason.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from ..ingestion.logs import ANONYMOUS
from ..ingestion.realms import latest_snapshot
from ..store import FINDINGS, LOGS, REALMS, RULES, Store
from ..utils import is_applicable, stable_id
from . import scoring
from .rules import evaluate, matching_values, query_params

MAX_EVIDENCE = 25


def redirect_matches(registered: str, value: str, root_url: str | None = None) -> bool:
    """Approximation of Keycloak's redirect URI matching (exact, or prefix when ending with '*')."""
    if registered.startswith("/") and root_url:
        registered = root_url.rstrip("/") + registered
    value = value.split("#")[0]
    if registered.endswith("*"):
        return value.startswith(registered[:-1])
    return value.split("?")[0] == registered.split("?")[0]


def infer_client(log: dict, params: list[str], clients: list[dict]) -> str | None:
    """Attribute an anonymous log hit to a client if exactly one client owns the redirect target."""
    q = query_params(log.get("url", {}).get("query"))
    for p in params:
        for value in q.get(p, []):
            owners = {c["client_id"] for c in clients
                      for r in (c.get("redirect_uris") or []) + (c.get("post_logout_redirect_uris") or [])
                      if redirect_matches(r, value, c.get("root_url"))}
            if len(owners) == 1:
                return owners.pop()
    return None


def _log_evidence(log: dict, attribution: str) -> dict:
    url = log.get("url") or {}
    ev = {
        "type": "runtime",
        "log_id": log.get("log_id"),
        "timestamp": log.get("@timestamp"),
        "origin": (log.get("labels") or {}).get("origin"),
        "source_file": (log.get("labels") or {}).get("source_file"),
        "instance": (log.get("keycloak") or {}).get("instance"),
        "attribution": attribution,
        "client_id_source": log.get("client_id_source"),
    }
    if url:
        ev.update(method=(log.get("http") or {}).get("request", {}).get("method"), path=url.get("path"),
                  query=(url.get("query") or "")[:300],
                  status=(log.get("http") or {}).get("response", {}).get("status_code"))
    else:
        ev.update(event_action=(log.get("event") or {}).get("action"))
    return ev


def _suggest(rule: dict, value) -> dict:
    ev = {"type": "static", "value": value}
    if rule.get("category") == "redirect-uri-validation" and isinstance(value, str):
        m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*://[^/?#*]*)\*(.*)$", value)
        if m:
            ev["suggested_value"] = f"{m.group(1)}/*"
    if isinstance(value, dict) and value.get("type", "").endswith("role-mapper"):
        ev["suggested_value"] = {**value, "multivalued": True}
    return ev


class Assessment:
    def __init__(self, store: Store, source_version: str, target_version: str,
                 snapshot_id: str | None = None, log_origins: list[str] | None = None, label: str | None = None):
        self.store = store
        self.source = source_version
        self.target = target_version
        snap = {"snapshot_id": snapshot_id} if snapshot_id else latest_snapshot(store)
        if not snap:
            raise ValueError("no realm snapshot ingested: run the realm pipeline first")
        self.snapshot_id = snap["snapshot_id"]
        self.log_origins = sorted(log_origins) if log_origins else None
        self.label = label
        self.assessment_id = "asmt-" + stable_id(self.source, self.target, self.snapshot_id, self.log_origins, label, length=16)
        self.now = datetime.now(timezone.utc).isoformat()

    def run(self) -> dict:
        clients = self.store.find(REALMS, {"doc_type": "client", "snapshot_id": self.snapshot_id})
        by_id = {c["client_id"]: c for c in clients}
        rules = sorted(self.store.find(RULES, {"status": "approved"}), key=lambda r: r["bc_id"])
        logs = self.store.find(LOGS, {"labels.origin": self.log_origins} if self.log_origins else None)
        logs_by_client: dict[str, list[dict]] = defaultdict(list)
        for log in logs:
            logs_by_client[log["client_id"]].append(log)

        applicable, skipped = [], []
        for r in rules:
            if r["kind"] == "control" or is_applicable(r.get("introduced_in"), self.source, self.target):
                applicable.append(r)
            else:
                skipped.append({"bc_id": r["bc_id"], "introduced_in": r.get("introduced_in"),
                                "reason": f"not in ({self.source}, {self.target}]"})

        findings: list[dict] = []
        for rule in applicable:
            det = rule["detection"]
            static, runtime = det.get("static"), det.get("runtime")
            if static:
                findings.extend(self._static(rule, static, runtime, clients, logs_by_client))
            if runtime and runtime["mode"] == "detect":
                findings.extend(self._runtime_detect(rule, runtime, logs, clients, by_id))
            if runtime and runtime["mode"] == "aggregate":
                findings.extend(self._aggregate(rule, runtime, logs))

        findings.sort(key=lambda f: (-f["risk_score"], f["bc_id"], f["client_id"]))
        summary = self._summary(findings, clients, logs, applicable, skipped)
        self.store.delete(FINDINGS, {"assessment_id": self.assessment_id})
        self.store.upsert_many(FINDINGS, [(f["finding_id"], f) for f in findings] + [(self.assessment_id, summary)])
        return summary

    # ------------------------------------------------------------------------------------
    def _finding(self, rule: dict, client_id: str, client: dict | None, *, sources: list[str], evidence: list[dict],
                 evidence_count: int, conf: float, attribution: str, identified: bool) -> dict:
        inv = (client or {}).get("inventory") or {}
        return {
            "doc_type": "finding",
            "finding_id": stable_id(self.assessment_id, rule["bc_id"], client_id, length=24),
            "assessment_id": self.assessment_id,
            "snapshot_id": self.snapshot_id,
            "source_version": self.source,
            "target_version": self.target,
            "bc_id": rule["bc_id"],
            "bc_title": rule["title"],
            "kind": rule["kind"],
            "category": rule["category"],
            "category_label": rule.get("category_label") or rule["category"],
            "client_id": client_id,
            "client_identified": identified,
            "attribution": attribution,
            "severity": rule["severity"],
            "confidence": conf,
            "confidence_label": scoring.confidence_label(conf),
            "risk_score": scoring.risk_score(rule["severity"], conf, inv.get("business_criticality")),
            "detection_sources": sources,
            "evidence": evidence[:MAX_EVIDENCE],
            "evidence_count": evidence_count,
            "remediation": rule["remediation"],
            "inventory": inv,
            "status": "open",
            "created_at": self.now,
        }

    def _static(self, rule, static, runtime, clients, logs_by_client) -> list[dict]:
        out = []
        corroborate = runtime if runtime and runtime["mode"] == "corroborate" else None
        for c in clients:
            if not evaluate(static["condition"], c):
                continue
            static_ev = [{**_suggest(rule, v), "snapshot_id": self.snapshot_id, "field": "client configuration"}
                         for v in matching_values(static["condition"], c)]
            if not c.get("enabled", True):
                static_ev.append({"type": "static", "value": {"enabled": False},
                                  "note": "client is disabled: impact depends on whether it will be re-enabled"})
            hits = [l for l in logs_by_client.get(c["client_id"], [])
                    if corroborate and evaluate(corroborate["condition"], l)]
            evidence = static_ev + [_log_evidence(l, "explicit") for l in hits[:10]]
            conf = scoring.confidence(static=True, corroborated=bool(hits), runtime_hits=len(hits),
                                      inferred=False, client_enabled=c.get("enabled", True))
            out.append(self._finding(rule, c["client_id"], c, sources=["realm"] + (["runtime"] if hits else []),
                                     evidence=evidence, evidence_count=len(static_ev) + len(hits),
                                     conf=conf, attribution="explicit", identified=True))
        return out

    def _runtime_detect(self, rule, runtime, logs, clients, by_id) -> list[dict]:
        infer_params = (runtime.get("attribution") or {}).get("infer_from_params", [])
        groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for log in logs:
            if not evaluate(runtime["condition"], log):
                continue
            if log["client_identified"]:
                groups[(log["client_id"], "explicit")].append(log)
                continue
            inferred = infer_client(log, infer_params, clients) if infer_params else None
            groups[(inferred, "inferred-redirect-uri") if inferred else (ANONYMOUS, "none")].append(log)

        merged: dict[str, tuple[str, list[dict]]] = {}
        for (cid, attribution), hits in groups.items():
            if cid in merged:  # explicit + inferred for the same client: keep the stronger attribution
                prev_attr, prev_hits = merged[cid]
                attribution = "explicit" if "explicit" in (prev_attr, attribution) else attribution
                hits = prev_hits + hits
            merged[cid] = (attribution, hits)

        out = []
        for cid, (attribution, hits) in merged.items():
            client = by_id.get(cid)
            conf = scoring.confidence(static=False, corroborated=False, runtime_hits=len(hits),
                                      inferred=attribution == "inferred-redirect-uri",
                                      client_enabled=client.get("enabled", True) if client else None)
            evidence = [_log_evidence(l, attribution) for l in hits]
            if cid != ANONYMOUS and client is None:
                evidence.insert(0, {"type": "note", "note": "client id not present in the realm snapshot"})
            out.append(self._finding(rule, cid, client, sources=["runtime"], evidence=evidence,
                                     evidence_count=len(hits), conf=conf, attribution=attribution,
                                     identified=cid != ANONYMOUS))
        return out

    def _aggregate(self, rule, runtime, logs) -> list[dict]:
        hits = [l for l in logs if evaluate(runtime["condition"], l)]
        if not hits:
            return []
        by_path = Counter(re.sub(r"/realms/[^/]+", "/realms/{realm}", (l.get("url") or {}).get("path") or "-") for l in hits)
        by_origin = Counter((l.get("labels") or {}).get("origin") for l in hits)
        evidence = [{"type": "aggregate", "total": len(hits), "by_endpoint": dict(by_path.most_common(15)),
                     "by_origin": dict(by_origin)}] + [_log_evidence(l, "none") for l in hits[:10]]
        return [self._finding(rule, ANONYMOUS, None, sources=["runtime"], evidence=evidence, evidence_count=len(hits),
                              conf=scoring.confidence(static=False, corroborated=False, runtime_hits=len(hits),
                                                      inferred=False, client_enabled=None, control=True),
                              attribution="none", identified=False)]

    def _summary(self, findings, clients, logs, applicable, skipped) -> dict:
        bc = [f for f in findings if f["kind"] == "breaking-change"]
        impacted = {f["client_id"] for f in bc if f["client_identified"]}
        return {
            "doc_type": "assessment",
            "assessment_id": self.assessment_id,
            "snapshot_id": self.snapshot_id,
            "source_version": self.source,
            "target_version": self.target,
            "status": scoring.readiness(findings),
            "parameters": {"log_origins": self.log_origins, "label": self.label},
            "summary": {
                "clients_assessed": len(clients),
                "impacted_clients": len(impacted),
                "detected_bc": len({f["bc_id"] for f in bc}),
                "anonymous_calls": sum(1 for l in logs if not l.get("client_identified")),
                "runtime_records": len(logs),
                "findings_total": len(findings),
                "by_category": dict(Counter(f["category_label"] for f in bc)),
                "impacted_by_category": {k: len({f["client_id"] for f in bc if f["category_label"] == k and f["client_identified"]})
                                         for k in {f["category_label"] for f in bc}},
                "by_severity": dict(Counter(f["severity"] for f in bc)),
                "by_confidence": dict(Counter(f["confidence_label"] for f in bc)),
                "by_bc": dict(Counter(f["bc_id"] for f in bc)),
                "applicable_rules": [r["bc_id"] for r in applicable],
                "skipped_rules": skipped,
            },
            "created_at": self.now,
        }


def run_assessment(store: Store, source_version: str, target_version: str, **kw) -> dict:
    return Assessment(store, source_version, target_version, **kw).run()
