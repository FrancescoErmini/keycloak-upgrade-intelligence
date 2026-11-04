"""LLM mapping onto the closed detector registry: validation, canonicalization, caching, consistency."""
import copy
import json

import pytest

from app.detection.detectors import DETECTORS, canonical_params, compile_detection, fingerprint
from app.detection.rules import validate_rule
from app.ingestion.breaking_changes import build_rules, load_approved, load_catalog
from app.ingestion.rule_extraction import extract_rules, response_schema, validate_spec

WILDCARD = "kc-26.6.3-breaking-valid-redirect-uris-for-clients-do-not-accept-wildcards-for-hostname-anymore"
LOGOUT = "kc-26.0.0-uncategorized-support-for-legacy-redirect-uri-parameter-and-spi-options-has-been-removed"


@pytest.fixture(scope="module")
def catalog(settings):
    return load_catalog(settings.data_dir)


@pytest.fixture(scope="module")
def entries(catalog):
    return {e["entry_id"]: e for e in catalog["entries"]}


def _spec(**kw):
    base = {"decision": "rule", "change_type": "removed", "impact_area": "http-endpoints",
            "detector": "http.endpoint.query_param",
            "params": {"endpoint": "oidc-logout", "param": "redirect_uri", "grant": None, "mapper_types": None,
                       "attribute": None, "event_type": None},
            "severity": "critical",
            "source_quote": "This functionality was deprecated in Keycloak 18 and has been removed in this version "
                            "in favor of following the OpenID Connect specification.",
            "rationale": "r", "remediation": "m", "proposed_detector": None}
    base.update(kw)
    return base


def test_approved_rules_are_grounded_in_the_real_guide(settings, catalog):
    docs, rejected = build_rules(catalog, load_approved(settings.data_dir), {})
    assert rejected == []
    by_id = {d["bc_id"]: d for d in docs}
    assert {k: by_id[k]["introduced_in"] for k in ("KC-BC-001", "KC-BC-002", "KC-BC-003", "KC-BC-004")} == {
        "KC-BC-001": "26.6.3", "KC-BC-002": "26.0.0", "KC-BC-003": "26.4.3", "KC-BC-004": "23.0.0"}
    for d in docs:
        assert validate_rule(d) == []


def test_label_and_category_come_from_registry_not_from_llm(entries):
    spec, errors = validate_spec(_spec(impact_area="other"), entries[LOGOUT])
    assert errors == []
    assert spec["label"] == DETECTORS["http.endpoint.query_param"].label
    assert spec["category"] == "deprecated-http-endpoints"


def test_same_filter_same_fingerprint_regardless_of_llm_formatting(entries):
    a, _ = validate_spec(_spec(), entries[LOGOUT])
    b, _ = validate_spec(_spec(params={"endpoint": "OIDC-LOGOUT ", "param": "`redirect_uri`", "grant": "password",
                                       "mapper_types": None, "attribute": "junk", "event_type": None}), entries[LOGOUT])
    assert a["fingerprint"] == b["fingerprint"] and a["params"] == b["params"] == {"endpoint": "oidc-logout",
                                                                                   "param": "redirect_uri"}
    assert compile_detection(a["detector"], a["params"]) == compile_detection(b["detector"], b["params"])


@pytest.mark.parametrize("mutation,error", [
    ({"detector": "http.logout.legacy_param"}, "unknown detector"),
    ({"source_quote": "The logout endpoint was renamed to /signout in this version of Keycloak."}, "verbatim"),
    ({"params": {"endpoint": "oidc-signout", "param": "redirect_uri"}}, "not in"),
    ({"params": {"endpoint": "oidc-logout", "param": "return_to"}}, "does not appear"),
    ({"decision": "rule", "detector": "none"}, "requires a detector"),
    ({"decision": "not_detectable"}, "requires detector 'none'"),
])
def test_invalid_or_hallucinated_specs_are_rejected(entries, mutation, error):
    spec, errors = validate_spec(_spec(**mutation), entries[LOGOUT])
    assert spec is None and any(error in e for e in errors), errors


def test_mapper_types_are_canonical():
    p1 = canonical_params("client.protocol_mapper.single_valued",
                          {"mapper_types": ["oidc-usermodel-realm-role-mapper", "OIDC-USERMODEL-CLIENT-ROLE-MAPPER"]})
    p2 = canonical_params("client.protocol_mapper.single_valued",
                          {"mapper_types": ["oidc-usermodel-client-role-mapper", "oidc-usermodel-realm-role-mapper"]})
    assert p1 == p2 and fingerprint("client.protocol_mapper.single_valued", p1) == \
        fingerprint("client.protocol_mapper.single_valued", p2)


def test_response_schema_is_strict():
    s = response_schema()
    assert s["additionalProperties"] is False and set(s["required"]) == set(s["properties"])
    assert set(s["properties"]["detector"]["enum"]) == set(DETECTORS)
    p = s["properties"]["params"]
    assert p["additionalProperties"] is False and set(p["required"]) == set(p["properties"])


class FakeLLM:
    name, model = "fake", "fake-1"

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def available(self):
        return True

    def complete_json(self, messages, schema, name):
        entry = json.loads(messages[1]["content"])["entry"]
        self.calls.append(entry["title"])
        return copy.deepcopy(self.answers.get(entry["title"], _none_answer()))

    def explain(self, finding, passages):
        return None


def _none_answer(proposed=None):
    return {"decision": "not_detectable", "change_type": "notable", "impact_area": "server-configuration",
            "detector": "none", "params": {}, "severity": "low",
            "source_quote": "", "rationale": "server side", "remediation": "", "proposed_detector": proposed}


def test_extraction_caches_and_reports_consistency(catalog, entries):
    small = {**catalog, "entries": [entries[LOGOUT], entries[WILDCARD]]}
    logout = entries[LOGOUT]
    llm = FakeLLM({logout["title"]: _spec()})
    # approved rules cover nothing here -> both entries go to the LLM
    cands, report = extract_rules(small, llm, [], {}, min_version="22.0.0", categories=("breaking", "uncategorized"))
    assert cands[LOGOUT]["status"] == "candidate" and cands[LOGOUT]["detector"] == "http.endpoint.query_param"
    # wildcard entry: fake LLM answers "none" without a verbatim quote -> rejected, not silently accepted
    assert cands[WILDCARD]["status"] == "rejected"
    assert report["stats"] == {"called": 2, "candidate": 1, "rejected": 1}

    # second sync: unchanged entries are served from cache, the LLM is not called again
    llm2 = FakeLLM({})
    again, rep2 = extract_rules(small, llm2, [], cands, min_version="22.0.0", categories=("breaking", "uncategorized"))
    assert llm2.calls == [] and rep2["stats"] == {"cached": 2}
    assert again[LOGOUT] == cands[LOGOUT]

    # approved rules win: the entry is never sent to the LLM
    approved = [{"bc_id": "KC-BC-002", "entry_id": LOGOUT, "detector": "http.endpoint.query_param",
                 "params": {"endpoint": "oidc-logout", "param": "redirect_uri"}, "change_type": "removed",
                 "severity": "critical"}]
    llm3 = FakeLLM({})
    c3, rep3 = extract_rules(small, llm3, approved, {}, min_version="22.0.0", categories=("breaking", "uncategorized"),
                             force=True)
    assert logout["title"] not in llm3.calls and LOGOUT not in c3


def test_shared_filters_and_detector_proposals(catalog, entries):
    small = {**catalog, "entries": [entries[LOGOUT], entries[WILDCARD]]}
    wildcard_quote = ("The wildcard comparison for valid redirect URIs does not affect the hostname anymore.")
    answers = {
        entries[LOGOUT]["title"]: _spec(),
        entries[WILDCARD]["title"]: {**_none_answer("Redirect URI Host Wildcard"),
                                     "source_quote": wildcard_quote},
    }
    approved = [{"bc_id": "KC-BC-X", "entry_id": "other", "detector": "http.endpoint.query_param",
                 "params": {"endpoint": "oidc-logout", "param": "redirect_uri"}}]
    cands, report = extract_rules(small, FakeLLM(answers), approved, {}, min_version="22.0.0",
                                  categories=("breaking", "uncategorized"))
    fp = cands[LOGOUT]["fingerprint"]
    assert sorted(report["shared_filters"][fp]) == sorted(["KC-BC-X", cands[LOGOUT]["bc_id"]])
    assert cands[WILDCARD]["status"] == "not-detectable"
    assert report["detector_proposals"] == {"redirect_uri_host_wildcard": [WILDCARD]}


def test_candidates_are_indexed_but_never_executed(loaded_store, settings, catalog, entries):
    from app.detection.analyzers import run_assessment
    from app.store import FINDINGS, RULES

    spec, _ = validate_spec(_spec(), entries[LOGOUT])
    cand = {**spec, "bc_id": "KC-AUTO-TEST", "entry_id": LOGOUT, "status": "candidate", "model": "fake:1"}
    docs, _ = build_rules(catalog, load_approved(settings.data_dir), {LOGOUT + "-x": {**cand, "entry_id": LOGOUT}})
    # approved KC-BC-002 covers the same entry -> candidate dropped
    assert "KC-AUTO-TEST" not in {d["bc_id"] for d in docs}
    other = "kc-26.4.3-deprecated-accepting-http-requests-with-non-normalized-paths"
    cand2 = {**cand, "entry_id": other, "source_quote": "As this behavior can be problematic for URL filtering, "
             "it is deprecated and will be removed in a future release.", "detector": "http.path.non_normalized",
             "params": {}, "fingerprint": "http.path.non_normalized"}
    docs, _ = build_rules(catalog, load_approved(settings.data_dir), {other: cand2})
    loaded_store.upsert_many(RULES, [(d["bc_id"], d) for d in docs])
    assert loaded_store.get(RULES, "KC-AUTO-TEST")["status"] == "candidate"
    s = run_assessment(loaded_store, "26.3.0", "26.5.0")
    assert "KC-AUTO-TEST" not in s["summary"]["applicable_rules"]
    assert not loaded_store.find(FINDINGS, {"assessment_id": s["assessment_id"], "bc_id": "KC-AUTO-TEST"})
