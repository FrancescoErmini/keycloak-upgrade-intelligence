"""LLM-assisted mapping of upgrading-guide entries onto the closed detector registry.

Consistency guarantees (same filter => same rule => same label):
  1. Output is constrained by a strict JSON schema whose `detector`, `change_type`,
     `impact_area`, `severity` and enumerated params are enums (Structured Outputs).
  2. The LLM chooses *what* to detect; *how* (conditions) and the finding label come from
     the registry in code (detection/detectors.py).
  3. Parameters are canonicalized (unused ones dropped, lowercased, sorted) and the rule
     gets a fingerprint = detector + canonical params; equal fingerprints are equal filters.
  4. Grounding: the quote must be verbatim and identifier params must appear in the entry.
  5. Determinism: temperature 0 + seed, and results are cached by
     (entry content hash, prompt version, registry version, model): an unchanged entry is
     never re-asked, so a re-sync cannot relabel it.
  6. Few-shot examples come from the human-approved rules, and approved rules always win.
  7. When nothing fits, the model must say so (`proposed_detector`) -> review queue.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

from packaging.version import Version

from ..detection.detectors import (CHANGE_TYPES, DETECTOR_IDS, DETECTORS, ENDPOINTS, GRANTS, IMPACT_AREAS,
                                   MAPPER_TYPES, REGISTRY_VERSION, SEVERITIES, DetectorError, canonical_params,
                                   catalog_for_prompt, fingerprint)
from ..llm import prompts
from ..utils import stable_id

DECISIONS = ("rule", "not_detectable", "not_client_impacting")


def _nullable_enum(values) -> dict:
    return {"type": ["string", "null"], "enum": [*values, None]}


def response_schema() -> dict:
    """Strict schema: every property required, no extra properties, enums everywhere possible."""
    params = {
        "endpoint": _nullable_enum(ENDPOINTS),
        "param": {"type": ["string", "null"]},
        "grant": _nullable_enum(GRANTS),
        "mapper_types": {"type": ["array", "null"], "items": {"type": "string", "enum": list(MAPPER_TYPES)}},
        "attribute": {"type": ["string", "null"]},
        "event_type": {"type": ["string", "null"]},
    }
    props = {
        "decision": {"type": "string", "enum": list(DECISIONS)},
        "change_type": {"type": "string", "enum": list(CHANGE_TYPES)},
        "impact_area": {"type": "string", "enum": list(IMPACT_AREAS)},
        "detector": {"type": "string", "enum": list(DETECTOR_IDS)},
        "params": {"type": "object", "additionalProperties": False, "required": list(params), "properties": params},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "source_quote": {"type": "string"},
        "rationale": {"type": "string"},
        "remediation": {"type": "string"},
        "proposed_detector": {"type": ["string", "null"]},
    }
    return {"type": "object", "additionalProperties": False, "required": list(props), "properties": props}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").replace("`", "")).strip().lower()


def quote_is_verbatim(quote: str, text: str) -> bool:
    return bool(quote) and len(quote) >= 20 and _norm(quote) in _norm(text)


def cache_key(entry: dict, model: str) -> str:
    return stable_id(entry["content_hash"], prompts.PROMPT_VERSION, REGISTRY_VERSION, model, length=24)


def candidate_bc_id(entry_id: str) -> str:
    return f"KC-AUTO-{stable_id(entry_id, length=8).upper()}"


def examples_from_approved(approved: list[dict], entries: dict[str, dict]) -> list[dict]:
    out = []
    for r in approved:
        e = entries.get(r["entry_id"])
        if e:
            out.append({"entry_title": e["title"], "version": e["version"], "detector": r["detector"],
                        "params": r.get("params", {}), "change_type": r["change_type"], "severity": r["severity"]})
    return out


def validate_spec(spec: dict, entry: dict) -> tuple[dict | None, list[str]]:
    """Validate + canonicalize an LLM (or human) rule spec. Returns (canonical spec, errors)."""
    errors: list[str] = []
    detector = spec.get("detector")
    if detector not in DETECTORS:
        return None, [f"unknown detector {detector!r}"]
    if spec.get("change_type") not in CHANGE_TYPES:
        errors.append(f"invalid change_type {spec.get('change_type')!r}")
    if spec.get("severity") not in SEVERITIES:
        errors.append(f"invalid severity {spec.get('severity')!r}")
    if not quote_is_verbatim(spec.get("source_quote", ""), entry["text"]):
        errors.append("source_quote is not a verbatim sentence of the entry")
    try:
        params = canonical_params(detector, spec.get("params"), entry["text"])
    except DetectorError as exc:
        return None, errors + [str(exc)]
    if spec.get("decision", "rule") == "rule" and detector == "none":
        errors.append("decision 'rule' requires a detector other than 'none'")
    if spec.get("decision", "rule") != "rule" and detector != "none":
        errors.append(f"decision {spec.get('decision')!r} requires detector 'none'")
    if errors:
        return None, errors
    det = DETECTORS[detector]
    return {
        **{k: spec.get(k) for k in ("decision", "change_type", "impact_area", "severity", "source_quote",
                                    "rationale", "remediation", "proposed_detector")},
        "detector": detector,
        "params": params,
        "fingerprint": fingerprint(detector, params),
        "label": det.label,
        "category": det.category,
    }, []


def eligible(entry: dict, min_version: str, categories: tuple[str, ...]) -> bool:
    return Version(entry["version"]) >= Version(min_version) and entry["category"] in categories


def extract_rules(catalog: dict, llm, approved: list[dict], previous: dict[str, dict], *, min_version: str,
                  categories: tuple[str, ...], force: bool = False, max_entries: int | None = None) -> tuple[dict, dict]:
    """Return (candidates by entry_id, report). `previous` is the cache from the last sync."""
    entries = {e["entry_id"]: e for e in catalog["entries"]}
    approved_ids = {r["entry_id"] for r in approved}
    examples = examples_from_approved(approved, entries)
    registry = catalog_for_prompt()
    schema = response_schema()
    now = datetime.now(timezone.utc).isoformat()
    model = getattr(llm, "model", llm.name)

    out: dict[str, dict] = {}
    stats = defaultdict(int)
    for entry in catalog["entries"]:
        if entry["entry_id"] in approved_ids or not eligible(entry, min_version, categories):
            continue
        key = cache_key(entry, f"{llm.name}:{model}")
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
                "version": entry["version"], "title": entry["title"], "model": f"{llm.name}:{model}",
                "prompt_version": prompts.PROMPT_VERSION, "registry_version": REGISTRY_VERSION, "extracted_at": now}
        try:
            raw = llm.complete_json([
                {"role": "system", "content": prompts.RULE_SYSTEM},
                {"role": "user", "content": prompts.rule_user_message(entry, registry, examples)},
            ], schema, "keycloak_detection_rule")
        except Exception as exc:  # network / refusal / invalid JSON: keep going, report it
            out[entry["entry_id"]] = {**base, "status": "error", "errors": [f"{type(exc).__name__}: {exc}"]}
            stats["error"] += 1
            continue
        spec, errors = validate_spec(raw or {}, entry)
        if errors:
            out[entry["entry_id"]] = {**base, "status": "rejected", "errors": errors, "raw": raw}
            stats["rejected"] += 1
        elif spec["detector"] == "none":
            out[entry["entry_id"]] = {**base, **spec, "status": "not-detectable", "errors": []}
            stats["not_detectable"] += 1
        else:
            out[entry["entry_id"]] = {**base, **spec, "status": "candidate", "errors": []}
            stats["candidate"] += 1

    return out, {"stats": dict(stats), **consistency_report(out.values(), approved, entries)}


def consistency_report(candidates, approved: list[dict], entries: dict[str, dict]) -> dict:
    """Group rules by fingerprint and collect detector proposals for human review."""
    groups: dict[str, list[str]] = defaultdict(list)
    for r in approved:
        groups[fingerprint(r["detector"], r.get("params", {}))].append(r["bc_id"])
    proposals: dict[str, list[str]] = defaultdict(list)
    for c in candidates:
        if c.get("status") == "candidate":
            groups[c["fingerprint"]].append(c["bc_id"])
        if c.get("proposed_detector"):
            name = re.sub(r"[^a-z0-9]+", "_", c["proposed_detector"].lower()).strip("_")
            proposals[name].append(c["entry_id"])
    return {
        "shared_filters": {fp: ids for fp, ids in groups.items() if len(ids) > 1},
        "detector_proposals": dict(sorted(proposals.items(), key=lambda kv: -len(kv[1]))),
    }
