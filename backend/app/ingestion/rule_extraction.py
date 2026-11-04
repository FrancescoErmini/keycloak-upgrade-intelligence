"""LLM-assisted analysis of upgrading-guide entries into *checks*.

For each entry the LLM reasons freely and returns a list of checks: what to verify on a
live installation, how, what means "impacted", and the data source the check needs
(realm_export, access_log, event_log, server_log, server_info, server_config, ...).
Every check is kept, including those on sources we cannot read today; at detection time
only checks whose data source is available AND that map to an automated detector run.

Consistency (same filter => same rule => same label) is preserved where it matters,
i.e. for executable checks:
  * `data_source`, `detector` and enumerated params are enums in a strict JSON schema;
  * conditions, finding category and label come from the detector registry, not from text;
  * params are canonicalized and fingerprinted (detector + canonical params);
  * a detector forces its own data source (an access-log detector is an access_log check);
  * evidence quotes must be verbatim, identifier params must appear in the entry;
  * results are cached per (entry content hash, prompt version, registry version, model);
  * human-approved rules always win and are used as examples.
Free-text checks (detector "none") are not executed; they are grouped in the sync report
by data source, to show which sources/detectors would be worth adding.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

from packaging.version import Version

from ..detection.detectors import (CHANGE_TYPES, DATA_SOURCES, DETECTOR_IDS, DETECTORS, ENDPOINTS, GRANTS,
                                   MAPPER_TYPES, REGISTRY_VERSION, SEVERITIES, DetectorError, canonical_params,
                                   catalog_for_prompt, fingerprint)
from ..llm import prompts
from ..utils import stable_id

SCOPES = ("client", "realm", "server")


def _nullable_enum(values) -> dict:
    return {"type": ["string", "null"], "enum": [*values, None]}


def response_schema() -> dict:
    """Strict schema (OpenAI Structured Outputs): all properties required, no extras."""
    params = {
        "endpoint": _nullable_enum(ENDPOINTS),
        "param": {"type": ["string", "null"]},
        "grant": _nullable_enum(GRANTS),
        "mapper_types": {"type": ["array", "null"], "items": {"type": "string", "enum": list(MAPPER_TYPES)}},
        "attribute": {"type": ["string", "null"]},
        "event_type": {"type": ["string", "null"]},
        "text": {"type": ["string", "null"]},
    }
    check = {
        "check_id": {"type": "string", "description": "short snake_case name of the check"},
        "data_source": {"type": "string", "enum": list(DATA_SOURCES)},
        "what_to_check": {"type": "string"},
        "how_to_check": {"type": "string"},
        "impact_signal": {"type": "string"},
        "scope": {"type": "string", "enum": list(SCOPES)},
        "evidence_quote": {"type": "string"},
        "detector": {"type": "string", "enum": list(DETECTOR_IDS)},
        "params": {"type": "object", "additionalProperties": False, "required": list(params), "properties": params},
    }
    props = {
        "analysis": {"type": "string"},
        "change_type": {"type": "string", "enum": list(CHANGE_TYPES)},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "checks": {"type": "array", "items": {"type": "object", "additionalProperties": False,
                                              "required": list(check), "properties": check}},
        "remediation": {"type": "string"},
    }
    return {"type": "object", "additionalProperties": False, "required": list(props), "properties": props}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").replace("`", "")).strip().lower()


def quote_is_verbatim(quote: str, text: str) -> bool:
    return bool(quote) and len(quote) >= 20 and _norm(quote) in _norm(text)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")[:60] or "check"


def cache_key(entry: dict, model: str) -> str:
    return stable_id(entry["content_hash"], prompts.PROMPT_VERSION, REGISTRY_VERSION, model, length=24)


def candidate_bc_id(entry_id: str) -> str:
    return f"KC-AUTO-{stable_id(entry_id, length=8).upper()}"


def validate_check(check: dict, entry: dict) -> tuple[dict | None, list[str]]:
    errors: list[str] = []
    detector = check.get("detector") or "none"
    if detector not in DETECTORS:
        return None, [f"unknown detector {detector!r}"]
    if not quote_is_verbatim(check.get("evidence_quote", ""), entry["text"]):
        errors.append("evidence_quote is not a verbatim sentence of the entry")
    try:
        params = canonical_params(detector, check.get("params"), entry["text"])
    except DetectorError as exc:
        return None, errors + [str(exc)]
    det = DETECTORS[detector]
    data_source = check.get("data_source")
    notes = []
    if det.data_source:  # an executable detector determines the data source
        if data_source != det.data_source:
            notes.append(f"data_source {data_source!r} replaced by {det.data_source!r} (implied by {detector})")
        data_source = det.data_source
    if data_source not in DATA_SOURCES:
        errors.append(f"invalid data_source {data_source!r}")
    if errors:
        return None, errors
    executable = detector != "none"
    return {
        "check_id": _slug(check.get("check_id")),
        "data_source": data_source,
        "what_to_check": check.get("what_to_check", ""),
        "how_to_check": check.get("how_to_check", ""),
        "impact_signal": check.get("impact_signal", ""),
        "scope": check.get("scope") if check.get("scope") in SCOPES else ("client" if executable else "server"),
        "evidence_quote": check.get("evidence_quote"),
        "detector": detector,
        "params": params,
        "executable": executable,
        "fingerprint": fingerprint(detector, params) if executable else f"manual:{data_source}:{_slug(check.get('check_id'))}",
        "label": det.label if executable else (check.get("what_to_check") or "")[:120],
        "category": det.category,
        "notes": notes,
    }, []


def validate_spec(spec: dict, entry: dict) -> tuple[dict | None, list[str], list[dict]]:
    """Validate a rule spec (LLM output or approved rule).

    Returns (canonical spec or None, rule-level errors, rejected checks).
    The rule is kept when at least one check is valid; invalid checks are reported, not fatal.
    """
    errors: list[str] = []
    if spec.get("change_type") not in CHANGE_TYPES:
        errors.append(f"invalid change_type {spec.get('change_type')!r}")
    if spec.get("severity") not in SEVERITIES:
        errors.append(f"invalid severity {spec.get('severity')!r}")
    checks, rejected, seen = [], [], set()
    for raw in spec.get("checks") or []:
        c, errs = validate_check(raw, entry)
        if errs:
            rejected.append({"check_id": raw.get("check_id"), "data_source": raw.get("data_source"), "errors": errs})
            continue
        if c["fingerprint"] in seen:  # same filter twice in one answer: keep one
            continue
        seen.add(c["fingerprint"])
        checks.append(c)
    if spec.get("checks") and not checks:
        errors.append("no valid check")
    if errors:
        return None, errors, rejected
    # stable check ids within the rule
    for i, c in enumerate(checks):
        if sum(1 for x in checks if x["check_id"] == c["check_id"]) > 1:
            c["check_id"] = f"{c['check_id']}_{i + 1}"
    primary = next((c for c in checks if c["executable"]), None)
    return {
        "analysis": spec.get("analysis"),
        "change_type": spec["change_type"],
        "severity": spec["severity"],
        "remediation": spec.get("remediation") or "",
        "source_quote": spec.get("source_quote") or (checks[0]["evidence_quote"] if checks else None),
        "checks": checks,
        "category": primary["category"] if primary else "manual-review",
        "data_sources": sorted({c["data_source"] for c in checks}),
        "fingerprints": [c["fingerprint"] for c in checks if c["executable"]],
    }, [], rejected


def examples_from_approved(approved: list[dict], entries: dict[str, dict]) -> list[dict]:
    out = []
    for r in approved:
        e = entries.get(r["entry_id"])
        if not e:
            continue
        out.append({
            "entry": {"version": e["version"], "title": e["title"], "text": e["text"][:1200]},
            "answer": {"change_type": r["change_type"], "severity": r["severity"],
                       "checks": [{k: c.get(k) for k in ("check_id", "data_source", "what_to_check", "how_to_check",
                                                          "impact_signal", "scope", "detector", "params")}
                                  for c in r["checks"]]},
        })
    return out


def eligible(entry: dict, min_version: str, categories: tuple[str, ...]) -> bool:
    return Version(entry["version"]) >= Version(min_version) and entry["category"] in categories


def extract_rules(catalog: dict, llm, approved: list[dict], previous: dict[str, dict], *, min_version: str,
                  categories: tuple[str, ...], force: bool = False, max_entries: int | None = None) -> tuple[dict, dict]:
    """Return (results by entry_id, report). `previous` is the cache from the last sync."""
    entries = {e["entry_id"]: e for e in catalog["entries"]}
    approved_ids = {r["entry_id"] for r in approved}
    examples = examples_from_approved(approved, entries)
    registry = catalog_for_prompt()
    schema = response_schema()
    now = datetime.now(timezone.utc).isoformat()
    model = f"{llm.name}:{getattr(llm, 'model', llm.name)}"

    out: dict[str, dict] = {}
    stats: dict[str, int] = defaultdict(int)
    for entry in catalog["entries"]:
        if entry["entry_id"] in approved_ids or not eligible(entry, min_version, categories):
            continue
        key = cache_key(entry, model)
        cached = previous.get(entry["entry_id"])
        if cached and cached.get("cache_key") == key and not force:
            out[entry["entry_id"]] = cached
            stats["cached"] += 1
            continue
        if max_entries is not None and stats["called"] >= max_entries:
            stats["skipped_budget"] += 1
            continue
        stats["called"] += 1
        base = {"entry_id": entry["entry_id"], "bc_id": candidate_bc_id(entry["entry_id"]), "cache_key": key,
                "version": entry["version"], "title": entry["title"], "model": model,
                "prompt_version": prompts.PROMPT_VERSION, "registry_version": REGISTRY_VERSION, "extracted_at": now}
        try:
            raw = llm.complete_json([
                {"role": "system", "content": prompts.RULE_SYSTEM},
                {"role": "user", "content": prompts.rule_user_message(entry, registry, examples, DATA_SOURCES)},
            ], schema, "keycloak_upgrade_checks")
        except Exception as exc:  # network / refusal / invalid JSON: keep going, report it
            out[entry["entry_id"]] = {**base, "status": "error", "errors": [f"{type(exc).__name__}: {exc}"]}
            stats["error"] += 1
            continue
        spec, errors, rejected = validate_spec(raw or {}, entry)
        if errors:
            out[entry["entry_id"]] = {**base, "status": "rejected", "errors": errors, "rejected_checks": rejected,
                                      "raw": raw}
            stats["rejected"] += 1
            continue
        status = "candidate" if spec["checks"] else "no-checks"
        out[entry["entry_id"]] = {**base, **spec, "status": status, "errors": [], "rejected_checks": rejected}
        stats[status] += 1
        stats["checks"] += len(spec["checks"])
        stats["executable_checks"] += sum(c["executable"] for c in spec["checks"])
        stats["rejected_checks"] += len(rejected)

    return out, {"stats": dict(stats), **consistency_report(out.values(), approved)}


def consistency_report(results, approved: list[dict]) -> dict:
    """Executable filters shared by several BCs, and manual checks grouped by data source."""
    groups: dict[str, list[str]] = defaultdict(list)
    for r in approved:
        for c in r.get("checks", []):
            if c.get("detector", "none") != "none":
                groups[fingerprint(c["detector"], c.get("params", {}))].append(r["bc_id"])
    by_source: dict[str, int] = defaultdict(int)
    manual: dict[str, list[dict]] = defaultdict(list)
    for res in results:
        if res.get("status") != "candidate":
            continue
        for c in res["checks"]:
            by_source[c["data_source"]] += 1
            if c["executable"]:
                groups[c["fingerprint"]].append(res["bc_id"])
            else:
                manual[c["data_source"]].append({"bc_id": res["bc_id"], "check_id": c["check_id"],
                                                 "what_to_check": c["what_to_check"]})
    return {
        "checks_by_data_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
        "shared_filters": {fp: sorted(set(ids)) for fp, ids in groups.items() if len(set(ids)) > 1},
        "manual_checks_by_data_source": dict(manual),
    }
