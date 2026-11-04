import pytest

from app.detection.analyzers import run_assessment
from app.rag.retrieval import explain_finding, search
from app.store import FINDINGS


@pytest.mark.parametrize("query,anchor_prefix", [
    ("valid redirect URIs wildcard hostname", "_valid_redirect_uris_for_clients_do_not_accept_wildcards"),
    ("legacy redirect_uri parameter logout removed", "_support_for_legacy_redirect_uri_parameter"),
    ("non-normalized paths double slashes rejected", "_accepting_only_normalized_paths"),
    ("single-valued role mapper claim multivalued", "_changes_to_the_value_format_of_claims"),
])
def test_semantic_search_finds_relevant_entry_in_top3(loaded_store, settings, query, anchor_prefix):
    # Default embeddings are a local hashing model: good enough for top-3 on the real guide (539 entries);
    # use EMBEDDING_BACKEND=sentence-transformers for better ranking.
    hits = search(loaded_store, settings, query, k=3)
    assert any(h["section_anchor"].startswith(anchor_prefix) for h in hits), [h["section_anchor"] for h in hits]


def test_every_explanation_cites_its_breaking_change(loaded_store, settings):
    s = run_assessment(loaded_store, "25.0.6", "26.6.3")
    for f in loaded_store.find(FINDINGS, {"doc_type": "finding", "assessment_id": s["assessment_id"]}):
        exp = explain_finding(loaded_store, settings, f)
        assert f["bc_id"] in exp["explanation"]
        assert exp["citations"] and all(c["bc_id"] == f["bc_id"] for c in exp["citations"])
        if f["kind"] == "breaking-change":
            assert exp["citations"][0]["quote"]
            assert all(p["bc_ids"] == [f["bc_id"]] for p in exp["passages"])


class UngroundedLLM:
    name = "ungrounded"

    def available(self):
        return True

    def extract_rule(self, section):
        return None

    def explain(self, finding, passages):
        return "Everything is fine, just upgrade."  # does not cite the BC -> must be discarded


def test_ungrounded_llm_answer_is_discarded(loaded_store, settings):
    s = run_assessment(loaded_store, "26.5.0", "26.6.3")
    f = next(x for x in loaded_store.find(FINDINGS, {"doc_type": "finding", "assessment_id": s["assessment_id"]})
             if x["bc_id"] == "KC-BC-001")
    exp = explain_finding(loaded_store, settings, f, UngroundedLLM())
    assert exp["generator"] == "template" and "KC-BC-001" in exp["explanation"]
