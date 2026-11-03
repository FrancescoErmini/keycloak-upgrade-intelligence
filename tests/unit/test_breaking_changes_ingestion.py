import copy

from app.detection.rules import validate_rule
from app.ingestion.breaking_changes import ingest_breaking_changes, parse_sections
from app.store import KNOWLEDGE, RULES


def _sections(settings):
    html = (settings.data_dir / "breaking-changes" / "keycloak-26-upgrading.html").read_text()
    return {s["anchor"]: s for s in parse_sections(html)}


def test_sections_are_version_aware(settings):
    secs = _sections(settings)
    assert secs["redirect-uri-wildcard-hostname"]["version"] == "26.6.3"
    assert secs["non-normalized-request-paths"]["version"] == "26.4.3"
    assert secs["legacy-logout-redirect-uri-removed"]["version"] == "26.0.0"
    assert secs["role-mappers-multivalued"]["version"] == "26.0.0"


def test_ingestion_indexes_chunks_and_rules_idempotently(store, settings):
    r1 = ingest_breaking_changes(store, settings)
    assert r1["rejected"] == []
    counts = (store.count(KNOWLEDGE), store.count(RULES))
    ingest_breaking_changes(store, settings)
    assert (store.count(KNOWLEDGE), store.count(RULES)) == counts
    assert counts[1] == 5
    chunk = store.find(KNOWLEDGE, {"bc_ids": "KC-BC-001"})[0]
    assert "https://example.com*" in chunk["text"]  # original text is preserved
    assert len(chunk["embedding"]) == settings.embedding_dim


def test_all_manifest_rules_are_grounded(settings, manifest):
    secs = _sections(settings)
    for rule in manifest["rules"]:
        assert validate_rule(rule, secs) == [], rule["bc_id"]


def test_validation_rejects_hallucinated_rules(settings, manifest):
    secs = _sections(settings)
    base = next(r for r in manifest["rules"] if r["bc_id"] == "KC-BC-002")

    invented_quote = copy.deepcopy(base)
    invented_quote["source_quote"] = "The logout endpoint has been moved to /protocol/openid-connect/signout."
    assert any("verbatim" in e for e in validate_rule(invented_quote, secs))

    invented_param = copy.deepcopy(base)
    invented_param["detection"]["runtime"]["condition"]["all"][1]["value"] = "return_to"
    assert any("return_to" in e for e in validate_rule(invented_param, secs))

    unknown_field = copy.deepcopy(base)
    unknown_field["detection"]["runtime"]["condition"]["all"][0]["field"] = "http.request.body"
    assert any("not allowed" in e for e in validate_rule(unknown_field, secs))

    wrong_version = copy.deepcopy(base)
    wrong_version["introduced_in"] = "26.6.3"
    assert any("differs from section version" in e for e in validate_rule(wrong_version, secs))


class FakeLLM:
    name = "fake"

    def __init__(self, proposal):
        self.proposal = proposal

    def available(self):
        return True

    def extract_rule(self, section):
        return copy.deepcopy(self.proposal)

    def explain(self, finding, passages):
        return None


def test_llm_proposals_are_validated_and_stored_as_candidates(store, settings, tmp_path):
    from dataclasses import replace
    import shutil

    data = tmp_path / "data"
    shutil.copytree(settings.data_dir, data)
    html = data / "breaking-changes" / "keycloak-26-upgrading.html"
    html.write_text(html.read_text().replace(
        "</div>\n</body>",
        '<div class="sect1"><h2 id="m-26-1-0">Migrating to 26.1.0</h2><div class="sectionbody">'
        '<div class="sect2"><h3 id="new-thing">Something new</h3><div class="paragraph"><p>The foo option was removed. '
        'Requests to the /realms/x/foo endpoint are rejected.</p></div></div></div></div>\n</div>\n</body>'))
    good = {"title": "Foo removed", "category": "other", "severity": "medium", "introduced_in": "26.1.0",
            "source_quote": "The foo option was removed.", "evidence_terms": ["foo"],
            "detection": {"runtime": {"mode": "detect", "condition": {"field": "url.path", "op": "regex", "value": "/foo$"}}},
            "remediation": "Stop calling foo."}
    res = ingest_breaking_changes(store, replace(settings, data_dir=data), FakeLLM(good))
    assert res["llm_candidates"] == 1
    cand = store.find(RULES, {"status": "candidate"})
    assert len(cand) == 1 and cand[0]["origin"] == "llm:fake"

    bad = dict(good, source_quote="The foo endpoint is now called bar.")
    store2 = type(store)()
    res = ingest_breaking_changes(store2, replace(settings, data_dir=data), FakeLLM(bad))
    assert res["llm_candidates"] == 0 and res["rejected"][0]["origin"] == "llm:fake"
