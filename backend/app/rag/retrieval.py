"""Retrieval-augmented explanations.

Every explanation is anchored to the breaking change of the finding: passages are
retrieved from kc-bc-knowledge filtered by bc_id (semantic ranking inside it), and the
result always carries explicit citations (bc_id, section anchor, source URL, quote).
If an LLM answer does not cite the bc_id it is discarded in favour of the
deterministic template.
"""
from __future__ import annotations

from ..llm.providers import LLMProvider, NoLLM
from ..store import KNOWLEDGE, RULES, Store
from .embeddings import get_embedder


def search(store: Store, settings, query: str, k: int = 5, bc_id: str | None = None) -> list[dict]:
    emb = get_embedder(settings.embedding_backend, settings.embedding_dim, settings.embedding_model)
    hits = store.knn(KNOWLEDGE, "embedding", emb.embed(query), k, {"bc_ids": bc_id} if bc_id else None)
    return [{"score": round(score, 4), "chunk_id": d["chunk_id"], "bc_ids": d.get("bc_ids", []),
             "section_anchor": d["section_anchor"], "section_title": d["section_title"], "version": d.get("version"),
             "source_url": d["source_url"], "text": d["text"]} for score, d in hits]


def _template(finding: dict, rule: dict) -> str:
    ev = finding.get("evidence") or []
    static = [e for e in ev if e.get("type") == "static" and e.get("value") is not None]
    runtime = [e for e in ev if e.get("type") == "runtime"]
    parts = [f"{finding['bc_id']} — {rule['title']} (introduced in Keycloak {rule.get('introduced_in')})."]
    if rule.get("source_quote"):
        parts.append(f"The upgrading guide states: \"{rule['source_quote']}\"")
    if static:
        parts.append(f"Client '{finding['client_id']}' has a matching configuration: {static[0]['value']}.")
    if runtime:
        parts.append(f"{finding['evidence_count']} runtime log record(s) confirm the behaviour "
                     f"(e.g. {runtime[0].get('method') or ''} {runtime[0].get('path') or runtime[0].get('event_action')}).")
    if finding.get("attribution") == "inferred-redirect-uri":
        parts.append("The client was attributed by matching the redirect URI against the realm configuration.")
    if not finding.get("client_identified"):
        parts.append("The calls could not be attributed to a Keycloak client (client_id = anonymous).")
    parts.append(f"Remediation: {finding['remediation']}")
    return " ".join(parts)


def explain_finding(store: Store, settings, finding: dict, llm: LLMProvider | None = None) -> dict:
    llm = llm or NoLLM()
    rule = store.get(RULES, finding["bc_id"]) or {}
    query = f"{rule.get('title', '')} {finding.get('category_label', '')}"
    passages = search(store, settings, query, k=3, bc_id=finding["bc_id"]) if rule.get("section_anchor") else []
    for p in passages:
        p["bc_id"] = finding["bc_id"]
    citations = [{"bc_id": finding["bc_id"], "section_anchor": p["section_anchor"], "source_url": p["source_url"],
                  "chunk_id": p["chunk_id"]} for p in passages]
    if rule.get("source_quote"):
        citations.insert(0, {"bc_id": finding["bc_id"], "section_anchor": rule.get("section_anchor"),
                             "source_url": rule.get("source_url"), "quote": rule["source_quote"]})
    if not citations:
        citations = [{"bc_id": finding["bc_id"], "section_anchor": None, "source_url": None,
                      "note": "control rule, no documentation passage"}]

    text, generator = None, "template"
    if passages and llm.available():
        answer = llm.explain(finding, passages)
        if answer and finding["bc_id"] in answer:  # grounding guard: must cite the BC
            text, generator = answer, f"llm:{llm.name}"
    if text is None:
        text = _template(finding, rule or {"title": finding.get("bc_title"), "introduced_in": None})
    return {"finding_id": finding["finding_id"], "bc_id": finding["bc_id"], "explanation": text,
            "generator": generator, "citations": citations, "passages": passages}
