from app.detection.analyzers import run_assessment
from app.rag.retrieval import explain_finding, search
from app.store import FINDINGS


def test_semantic_search_ranks_relevant_section_first(loaded_store, settings):
    hits = search(loaded_store, settings, "wildcard in redirect uri host name", k=3)
    assert hits[0]["section_anchor"] == "redirect-uri-wildcard-hostname"
    hits = search(loaded_store, settings, "logout redirect_uri parameter removed", k=3)
    assert hits[0]["section_anchor"] == "legacy-logout-redirect-uri-removed"


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
