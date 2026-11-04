"""Pipeline A — Breaking Changes ingestion into Elasticsearch.

Input (produced by the manual sync job `python -m app.jobs.sync_breaking_changes`):
  data/breaking-changes/catalog.json                 entries parsed from the official HTML
  data/breaking-changes/rules/approved-rules.json    human-approved rules + controls
  data/breaking-changes/rules/llm-candidates.json   LLM proposals (never executed)

This step makes no network call and no LLM call: it indexes every catalog entry in
kc-bc-knowledge (original text + local embedding, with version/category metadata) and
the rules in kc-bc-rules. Only `approved` rules are executed by the detection engine.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..detection.detectors import CATEGORY_LABELS, DETECTORS, compile_detection
from ..detection.rules import validate_rule
from ..rag.embeddings import get_embedder
from ..store import KNOWLEDGE, RULES, Store
from ..utils import stable_id
from .rule_extraction import validate_spec

DOC_ID = "keycloak-upgrading-guide"
CHUNK_CHARS = 1500


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def bc_dir(data_dir: Path) -> Path:
    return data_dir / "breaking-changes"


def load_json(path: Path, default=None):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def load_catalog(data_dir: Path) -> dict:
    cat = load_json(bc_dir(data_dir) / "catalog.json")
    if cat is None:
        raise FileNotFoundError("catalog.json missing: run `python -m app.jobs.sync_breaking_changes` first")
    return cat


def load_approved(data_dir: Path) -> dict:
    return load_json(bc_dir(data_dir) / "rules" / "approved-rules.json", {"rules": [], "controls": []})


def load_candidates(data_dir: Path) -> dict[str, dict]:
    return load_json(bc_dir(data_dir) / "rules" / "llm-candidates.json", {"candidates": {}})["candidates"]


def chunk_text(text: str, max_chars: int = CHUNK_CHARS) -> list[str]:
    chunks, cur = [], ""
    for p in text.split("\n"):
        if cur and len(cur) + len(p) + 1 > max_chars:
            chunks.append(cur)
            cur = p
        else:
            cur = f"{cur}\n{p}" if cur else p
    return chunks + ([cur] if cur else []) or [""]


def compile_check(c: dict) -> dict:
    det = DETECTORS[c["detector"]]
    return {**{k: c.get(k) for k in ("check_id", "data_source", "what_to_check", "how_to_check", "impact_signal",
                                      "scope", "evidence_quote", "detector", "params", "fingerprint", "executable")},
            "label": det.label if c["executable"] else c.get("label"),
            "category": det.category,
            "detection": compile_detection(c["detector"], c["params"]) if c["executable"] else None}


def build_rule_doc(spec: dict, entry: dict, origin: str, status: str) -> dict:
    """Merge a validated rule spec with its catalog entry and the detector registry."""
    checks = [compile_check(c) for c in spec["checks"]]
    category = spec["category"]
    return {
        "bc_id": spec["bc_id"],
        "entry_id": entry["entry_id"],
        "title": entry["title"],
        "kind": "breaking-change",
        "change_type": spec["change_type"],
        # finding category and labels come from the registry (primary executable check), never from free text
        "category": category,
        "category_label": CATEGORY_LABELS[category],
        "checks": checks,
        "data_sources": spec["data_sources"],
        "detectors": sorted({c["detector"] for c in checks if c["executable"]}),
        "fingerprints": spec["fingerprints"],
        "introduced_in": entry["version"],
        "from_version": entry.get("from_version"),
        "severity": spec["severity"],
        "section_anchor": entry.get("anchor"),
        "source_url": entry.get("url"),
        "source_quote": spec.get("source_quote"),
        "analysis": spec.get("analysis"),
        "remediation": spec.get("remediation") or "",
        "testability": spec.get("testability"),
        "status": status if checks else "no-checks",
        "origin": origin,
        "review": spec.get("review") or {"approved_by": None},
        "validation": {"grounded": True, "validated_at": now()},
        "rule_hash": stable_id(spec["fingerprints"], entry["content_hash"], spec["severity"], length=40),
        "ingested_at": now(),
    }


def build_control_doc(ctrl: dict) -> dict:
    checks = [{**c, "evidence_quote": None, "detector": None, "params": None, "fingerprint": f"control:{c['check_id']}",
               "executable": True, "label": ctrl["title"], "category": ctrl["category"]} for c in ctrl["checks"]]
    return {
        "bc_id": ctrl["bc_id"], "entry_id": None, "title": ctrl["title"], "kind": "control", "change_type": None,
        "category": ctrl["category"], "category_label": CATEGORY_LABELS[ctrl["category"]], "checks": checks,
        "data_sources": sorted({c["data_source"] for c in checks}), "detectors": [],
        "fingerprints": [c["fingerprint"] for c in checks], "introduced_in": None, "from_version": None,
        "severity": ctrl["severity"], "section_anchor": None, "source_url": None, "source_quote": None,
        "analysis": None, "remediation": ctrl["remediation"], "testability": ctrl.get("testability"),
        "status": "approved", "origin": "approved-rules", "review": {"approved_by": "poc-curator"},
        "validation": {"grounded": None, "validated_at": now()}, "rule_hash": stable_id(ctrl, length=40),
        "ingested_at": now(),
    }


def build_rules(catalog: dict, approved: dict, candidates: dict[str, dict]) -> tuple[list[dict], list[dict]]:
    entries = {e["entry_id"]: e for e in catalog["entries"]}
    docs, rejected = [], []
    approved_entries = set()
    for spec in approved.get("rules", []):
        entry = entries.get(spec["entry_id"])
        if entry is None:
            rejected.append({"bc_id": spec["bc_id"], "origin": "approved-rules",
                             "errors": [f"entry {spec['entry_id']!r} not in catalog (renamed or removed upstream?)"]})
            continue
        canon, errors, bad_checks = validate_spec(spec, entry)
        if errors or bad_checks:
            rejected.append({"bc_id": spec["bc_id"], "origin": "approved-rules", "errors": errors,
                             "rejected_checks": bad_checks})
        if errors:
            continue
        approved_entries.add(entry["entry_id"])
        docs.append(build_rule_doc({**spec, **canon}, entry, "approved-rules", "approved"))
    for c in candidates.values():
        if c.get("status") != "candidate" or c["entry_id"] in approved_entries or c["entry_id"] not in entries:
            continue
        docs.append(build_rule_doc(c, entries[c["entry_id"]], c.get("model", "llm"), "candidate"))
    docs += [build_control_doc(c) for c in approved.get("controls", [])]
    for d in docs:
        errs = validate_rule(d)
        if errs:
            raise ValueError(f"rule {d['bc_id']} failed structural validation: {errs}")
    return docs, rejected


def ingest_breaking_changes(store: Store, settings, llm=None) -> dict:  # llm kept for API compatibility
    catalog = load_catalog(settings.data_dir)
    rule_docs, rejected = build_rules(catalog, load_approved(settings.data_dir), load_candidates(settings.data_dir))
    bc_by_entry: dict[str, list[str]] = {}
    for r in rule_docs:
        if r.get("entry_id"):
            bc_by_entry.setdefault(r["entry_id"], []).append(r["bc_id"])

    embedder = get_embedder(settings.embedding_backend, settings.embedding_dim, settings.embedding_model)
    chunks = []
    for e in catalog["entries"]:
        for pos, text in enumerate(chunk_text(e["text"])):
            cid = stable_id(DOC_ID, e["entry_id"], pos, text)
            chunks.append((cid, {
                "chunk_id": cid, "doc_id": DOC_ID, "entry_id": e["entry_id"], "source_url": e["url"],
                "section_anchor": e["anchor"], "section_title": e["title"], "version": e["version"],
                "from_version": e.get("from_version"), "change_type": e["category"], "position": pos,
                "bc_ids": bc_by_entry.get(e["entry_id"], []), "text": text, "content_hash": e["content_hash"],
                "embedding_model": embedder.name,
                "embedding": embedder.embed(f"{e['title']}\n{text}"),
                "ingested_at": now(),
            }))
    store.delete(KNOWLEDGE, {"doc_id": DOC_ID})
    store.upsert_many(KNOWLEDGE, chunks)
    store.delete(RULES, None)
    store.upsert_many(RULES, [(r["bc_id"], r) for r in rule_docs])
    return {
        "doc_id": DOC_ID,
        "source_url": catalog["source_url"],
        "catalog_fetched_at": catalog["fetched_at"],
        "versions": catalog["stats"]["versions"],
        "entries": catalog["stats"]["entries"],
        "chunks": len(chunks),
        "rules_indexed": len(rule_docs),
        "rules_by_status": {s: sum(1 for r in rule_docs if r["status"] == s) for s in {r["status"] for r in rule_docs}},
        "rejected": rejected,
    }
