"""Pipeline A — Breaking Changes ingestion (the only pipeline that may use an LLM).

1. Read the upgrading guide (local file, or the official URL when BC_SOURCE_URL is set).
2. Split it into sections (Asciidoctor structure) and paragraph-aligned chunks.
3. Embed chunks locally and index them in kc-bc-knowledge (original text is always kept).
4. Load the curated rules from the manifest, validate their grounding and index them
   in kc-bc-rules as `approved`.
5. Optionally ask an LLM to propose rules for sections without a curated rule; proposals
   are validated and stored as `candidate` (never used by detection until approved).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup, Tag

from ..detection.rules import validate_rule
from ..llm.providers import LLMProvider, NoLLM
from ..rag.embeddings import get_embedder
from ..store import KNOWLEDGE, RULES, Store
from ..utils import stable_id

_VERSION = re.compile(r"(\d+\.\d+\.\d+)")
CHUNK_CHARS = 900


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_html(data_dir: Path, manifest: dict, source_url: str = "") -> tuple[str, str]:
    if source_url:
        r = requests.get(source_url, timeout=30)
        r.raise_for_status()
        return r.text, source_url
    path = data_dir / "breaking-changes" / manifest["source"]["file"]
    return path.read_text(encoding="utf-8"), manifest["source"]["url"]


def parse_sections(html: str) -> list[dict]:
    """Return [{anchor, title, version, level, text, paragraphs}] for every h2-h4 with an id."""
    soup = BeautifulSoup(html, "html.parser")
    sections: list[dict] = []
    current_version: str | None = None
    for h in soup.find_all(["h2", "h3", "h4"]):
        if h.name == "h2":
            m = _VERSION.search(h.get_text(" ", strip=True))
            current_version = m.group(1) if m else current_version
        if not h.get("id"):
            continue
        paragraphs: list[str] = []
        for sib in h.next_siblings:
            if not isinstance(sib, Tag):
                continue
            if sib.name in ("h1", "h2", "h3", "h4") or sib.find(["h2", "h3", "h4"]):
                break
            txt = re.sub(r"\s+", " ", sib.get_text(" ", strip=True)).strip()
            if txt:
                paragraphs.append(txt)
        if not paragraphs:
            continue
        sections.append({
            "anchor": h["id"],
            "title": h.get_text(" ", strip=True),
            "version": current_version,
            "level": int(h.name[1]),
            "paragraphs": paragraphs,
            "text": "\n".join(paragraphs),
        })
    return sections


def chunk_section(section: dict, max_chars: int = CHUNK_CHARS) -> list[str]:
    chunks, cur = [], ""
    for p in section["paragraphs"]:
        if cur and len(cur) + len(p) + 1 > max_chars:
            chunks.append(cur)
            cur = p
        else:
            cur = f"{cur}\n{p}" if cur else p
    if cur:
        chunks.append(cur)
    return chunks


def load_manifest(data_dir: Path) -> dict:
    return json.loads((data_dir / "breaking-changes" / "breaking-changes-manifest.json").read_text(encoding="utf-8"))


def ingest_breaking_changes(store: Store, settings, llm: LLMProvider | None = None) -> dict:
    llm = llm or NoLLM()
    manifest = load_manifest(settings.data_dir)
    html, source_url = load_html(settings.data_dir, manifest, settings.bc_source_url)
    doc_id = manifest["source"]["doc_id"]
    sections = parse_sections(html)
    by_anchor = {s["anchor"]: s for s in sections}
    anchor_to_bc: dict[str, list[str]] = {}
    for r in manifest["rules"]:
        if r.get("section_anchor"):
            anchor_to_bc.setdefault(r["section_anchor"], []).append(r["bc_id"])

    # ---- knowledge chunks (idempotent: deterministic ids + replace per source doc) ----
    embedder = get_embedder(settings.embedding_backend, settings.embedding_dim, settings.embedding_model)
    chunks = []
    for s in sections:
        for pos, text in enumerate(chunk_section(s)):
            cid = stable_id(doc_id, s["anchor"], pos, text)
            chunks.append((cid, {
                "chunk_id": cid,
                "doc_id": doc_id,
                "source_url": f"{source_url}#{s['anchor']}",
                "section_anchor": s["anchor"],
                "section_title": s["title"],
                "version": s["version"],
                "position": pos,
                "bc_ids": anchor_to_bc.get(s["anchor"], []),
                "text": text,
                "content_hash": stable_id(text, length=40),
                "embedding_model": embedder.name,
                "embedding": embedder.embed(f"{s['title']}\n{text}"),
                "ingested_at": now(),
            }))
    store.delete(KNOWLEDGE, {"doc_id": doc_id})
    store.upsert_many(KNOWLEDGE, chunks)

    # ---- curated rules ----
    rule_docs, rejected = [], []
    for rule in manifest["rules"]:
        errors = validate_rule(rule, by_anchor)
        if errors:
            rejected.append({"bc_id": rule.get("bc_id"), "origin": "manifest", "errors": errors})
            continue
        rule_docs.append((rule["bc_id"], _rule_doc(rule, source_url, "manifest", rule.get("status", "approved"))))

    # ---- optional LLM proposals for sections without curated rules ----
    candidates = 0
    if llm.available():
        for s in sections:
            if s["anchor"] in anchor_to_bc:
                continue
            proposal = llm.extract_rule(s)
            if not proposal or proposal.get("skip"):
                continue
            proposal.update(bc_id=f"KC-BC-CAND-{stable_id(s['anchor'], length=8)}", kind="breaking-change",
                            section_anchor=s["anchor"])
            proposal.setdefault("introduced_in", s["version"])
            errors = validate_rule(proposal, by_anchor)
            if errors:
                rejected.append({"bc_id": proposal["bc_id"], "origin": f"llm:{llm.name}", "errors": errors})
                continue
            rule_docs.append((proposal["bc_id"], _rule_doc(proposal, source_url, f"llm:{llm.name}", "candidate")))
            candidates += 1

    store.upsert_many(RULES, rule_docs)
    return {
        "doc_id": doc_id,
        "source_url": source_url,
        "sections": len(sections),
        "chunks": len(chunks),
        "rules_indexed": len(rule_docs),
        "llm_candidates": candidates,
        "rejected": rejected,
    }


def _rule_doc(rule: dict, source_url: str, origin: str, status: str) -> dict:
    keys = ("bc_id", "title", "kind", "category", "category_label", "introduced_in", "severity", "section_anchor",
            "source_quote", "evidence_terms", "detection", "remediation", "testability", "review")
    doc = {k: rule.get(k) for k in keys}
    doc.update(
        source_url=f"{source_url}#{rule['section_anchor']}" if rule.get("section_anchor") else None,
        status=status,
        origin=origin,
        validation={"grounded": True, "validated_at": now()},
        rule_hash=stable_id({k: rule.get(k) for k in keys}, length=40),
        ingested_at=now(),
    )
    doc["category_label"] = doc["category_label"] or doc["category"]
    return doc
