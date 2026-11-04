"""LLM analysis of guide entries into checks: validation, data sources, canonicalization, caching."""
import copy
import json

import pytest

from app.detection.analyzers import run_assessment
from app.detection.detectors import DATA_SOURCES, DETECTORS, canonical_params, fingerprint
from app.detection.rules import validate_rule
from app.ingestion.breaking_changes import build_rules, load_approved, load_catalog
from app.ingestion.rule_extraction import extract_rules, response_schema, validate_spec
from app.store import FINDINGS, RULES

WILDCARD = "kc-26.6.3-breaking-valid-redirect-uris-for-clients-do-not-accept-wildcards-for-hostname-anymore"
LOGOUT = "kc-26.0.0-uncategorized-support-for-legacy-redirect-uri-parameter-and-spi-options-has-been-removed"
DEPRECATED_PATHS = "kc-26.4.3-deprecated-accepting-http-requests-with-non-normalized-paths"
LOGOUT_QUOTE = ("This functionality was deprecated in Keycloak 18 and has been removed in this version in favor of "
                "following the OpenID Connect specification.")
NULL_PARAMS = {"endpoint": None, "param": None, "grant": None, "mapper_types": None, "attribute": None,
               "event_type": None, "text": None}


@pytest.fixture(scope="module")
def catalog(settings):
    return load_catalog(settings.data_dir)


@pytest.fixture(scope="module")
def entries(catalog):
    return {e["entry_id"]: e for e in catalog["entries"]}


def _check(**kw):
    c = {"check_id": "logout_with_redirect_uri", "data_source": "access_log", "what_to_check": "w",
         "how_to_check": "h", "impact_signal": "i", "scope": "client", "evidence_quote": LOGOUT_QUOTE,
         "detector": "http.endpoint.query_param",
         "params": {**NULL_PARAMS, "endpoint": "oidc-logout", "param": "redirect_uri"}}
    c.update(kw)
    return c


def _spec(*checks, **kw):
    s = {"analysis": "a", "change_type": "removed", "severity": "critical", "remediation": "r",
         "checks": list(checks) or [_check()]}
    s.update(kw)
    return s


def test_approved_rules_are_grounded_in_the_real_guide(settings, catalog):
    docs, rejected = build_rules(catalog, load_approved(settings.data_dir), {})
    assert rejected == []
    by_id = {d["bc_id"]: d for d in docs}
    assert {k: by_id[k]["introduced_in"] for k in ("KC-BC-001", "KC-BC-002", "KC-BC-003", "KC-BC-004")} == {
        "KC-BC-001": "26.6.3", "KC-BC-002": "26.0.0", "KC-BC-003": "26.4.3", "KC-BC-004": "23.0.0"}
    assert set(by_id["KC-BC-003"]["data_sources"]) == {"access_log", "server_config", "server_log"}
    for d in docs:
        assert validate_rule(d) == []


def test_multiple_checks_with_different_data_sources(entries):
    spec, errors, rejected = validate_spec(_spec(
        _check(),
        _check(check_id="Legacy SPI option", data_source="server_config", detector="none", params=NULL_PARAMS,
               evidence_quote="As part of this change the following related configuration options for the SPI "
                              "have been removed:"),
    ), entries[LOGOUT])
    assert errors == [] and rejected == []
    assert [(c["check_id"], c["data_source"], c["executable"]) for c in spec["checks"]] == [
        ("logout_with_redirect_uri", "access_log", True), ("legacy_spi_option", "server_config", False)]
    assert spec["data_sources"] == ["access_log", "server_config"]
    assert spec["category"] == "deprecated-http-endpoints"  # from the executable check's detector


def test_detector_imposes_its_data_source(entries):
    spec, _, _ = validate_spec(_spec(_check(data_source="server_log")), entries[LOGOUT])
    c = spec["checks"][0]
    assert c["data_source"] == "access_log" and "replaced" in c["notes"][0]


def test_same_filter_same_fingerprint_and_label(entries):
    a, _, _ = validate_spec(_spec(), entries[LOGOUT])
    b, _, _ = validate_spec(_spec(_check(check_id="whatever name", params={
        **NULL_PARAMS, "endpoint": "OIDC-LOGOUT ", "param": "`redirect_uri`", "grant": "password", "text": "junk"})),
        entries[LOGOUT])
    ca, cb = a["checks"][0], b["checks"][0]
    assert ca["fingerprint"] == cb["fingerprint"] and ca["params"] == cb["params"] == {"endpoint": "oidc-logout",
                                                                                       "param": "redirect_uri"}
    assert ca["label"] == cb["label"] == DETECTORS["http.endpoint.query_param"].label


def test_duplicate_filters_in_one_answer_are_collapsed(entries):
    spec, _, _ = validate_spec(_spec(_check(), _check(check_id="again")), entries[LOGOUT])
    assert len(spec["checks"]) == 1


@pytest.mark.parametrize("mutation,error", [
    ({"detector": "http.logout.legacy_param"}, "unknown detector"),
    ({"evidence_quote": "The logout endpoint was renamed to /signout in this version of Keycloak."}, "verbatim"),
    ({"params": {**NULL_PARAMS, "endpoint": "oidc-signout", "param": "redirect_uri"}}, "not in"),
    ({"params": {**NULL_PARAMS, "endpoint": "oidc-logout", "param": "return_to"}}, "does not appear"),
    ({"detector": "none", "data_source": "telepathy"}, "invalid data_source"),
])
def test_invalid_checks_are_rejected_individually(entries, mutation, error):
    good = _check(check_id="spi", data_source="server_config", detector="none", params=NULL_PARAMS)
    spec, errors, rejected = validate_spec(_spec(good, _check(**mutation)), entries[LOGOUT])
    assert errors == [] and len(spec["checks"]) == 1          # the valid check survives
    assert any(error in e for e in rejected[0]["errors"]), rejected
    spec, errors, _ = validate_spec(_spec(_check(**mutation)), entries[LOGOUT])
    assert spec is None and errors == ["no valid check"]


def test_mapper_types_are_canonical():
    p1 = canonical_params("client.protocol_mapper.single_valued",
                          {"mapper_types": ["oidc-usermodel-realm-role-mapper", "OIDC-USERMODEL-CLIENT-ROLE-MAPPER"]})
    p2 = canonical_params("client.protocol_mapper.single_valued",
                          {"mapper_types": ["oidc-usermodel-client-role-mapper", "oidc-usermodel-realm-role-mapper"]})
    assert p1 == p2
    assert fingerprint("client.protocol_mapper.single_valued", p1) == fingerprint("client.protocol_mapper.single_valued", p2)


def test_response_schema_is_strict():
    s = response_schema()
    assert s["additionalProperties"] is False and set(s["required"]) == set(s["properties"])
    assert list(s["properties"])[0] == "analysis"  # the model reasons before deciding
    item = s["properties"]["checks"]["items"]
    assert item["additionalProperties"] is False and set(item["required"]) == set(item["properties"])
    assert set(item["properties"]["data_source"]["enum"]) == set(DATA_SOURCES)
    assert set(item["properties"]["detector"]["enum"]) == set(DETECTORS)


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
        return copy.deepcopy(self.answers.get(entry["title"], {**_spec(), "checks": []}))

    def explain(self, finding, passages):
        return None


def test_extraction_caching_and_report(catalog, entries):
    small = {**catalog, "entries": [entries[LOGOUT], entries[WILDCARD]]}
    spi = _check(check_id="spi_option", data_source="server_config", detector="none", params=NULL_PARAMS,
                 what_to_check="legacy SPI options")
    llm = FakeLLM({entries[LOGOUT]["title"]: _spec(_check(), spi)})
    res, rep = extract_rules(small, llm, [], {}, min_version="22.0.0", categories=("breaking", "uncategorized"))
    assert res[LOGOUT]["status"] == "candidate" and res[WILDCARD]["status"] == "no-checks"
    assert rep["stats"] == {"called": 2, "candidate": 1, "checks": 2, "executable_checks": 1, "rejected_checks": 0,
                            "no-checks": 1}
    assert rep["checks_by_data_source"] == {"access_log": 1, "server_config": 1}
    assert rep["manual_checks_by_data_source"]["server_config"][0]["check_id"] == "spi_option"

    llm2 = FakeLLM({})
    again, rep2 = extract_rules(small, llm2, [], res, min_version="22.0.0", categories=("breaking", "uncategorized"))
    assert llm2.calls == [] and rep2["stats"] == {"cached": 2} and again[LOGOUT] == res[LOGOUT]

    approved = [{"bc_id": "KC-BC-002", "entry_id": LOGOUT, "change_type": "removed", "severity": "critical",
                 "checks": [_check()]}]
    llm3 = FakeLLM({})
    res3, rep3 = extract_rules(small, llm3, approved, {}, min_version="22.0.0",
                               categories=("breaking", "uncategorized"), force=True)
    assert entries[LOGOUT]["title"] not in llm3.calls and LOGOUT not in res3
    fp = fingerprint("http.endpoint.query_param", {"endpoint": "oidc-logout", "param": "redirect_uri"})
    assert fp not in rep3["shared_filters"]  # only one BC uses it


def test_examples_contain_entry_text_and_checks(settings, catalog, entries):
    llm = FakeLLM({})
    extract_rules({**catalog, "entries": [entries[DEPRECATED_PATHS]]}, llm, load_approved(settings.data_dir)["rules"],
                  {}, min_version="22.0.0", categories=("deprecated",))
    assert llm.calls == [entries[DEPRECATED_PATHS]["title"]]


def test_candidates_are_indexed_but_never_executed(loaded_store, settings, catalog):
    quote = "As this behavior can be problematic for URL filtering, it is deprecated and will be removed in a future release."
    spec, errors, _ = validate_spec(_spec(_check(detector="http.path.non_normalized", params=NULL_PARAMS,
                                                 evidence_quote=quote), change_type="deprecated", severity="medium"),
                                    {"text": quote})
    cand = {**spec, "bc_id": "KC-AUTO-TEST", "entry_id": DEPRECATED_PATHS, "status": "candidate", "model": "fake:1"}
    docs, _ = build_rules(catalog, load_approved(settings.data_dir), {DEPRECATED_PATHS: cand})
    loaded_store.upsert_many(RULES, [(d["bc_id"], d) for d in docs])
    assert loaded_store.get(RULES, "KC-AUTO-TEST")["status"] == "candidate"
    s = run_assessment(loaded_store, "26.3.0", "26.5.0")
    assert "KC-AUTO-TEST" not in s["summary"]["applicable_rules"]
    assert not loaded_store.find(FINDINGS, {"assessment_id": s["assessment_id"], "bc_id": "KC-AUTO-TEST"})


# ---------------------------------------------------------------- data source filtering
def test_checks_on_unavailable_sources_are_reported_not_run(loaded_store):
    s = run_assessment(loaded_store, "22.0.5", "26.6.3")
    ne = {(c["bc_id"], c["check_id"]): c["reason"] for c in s["summary"]["checks_not_executed"]}
    assert ne[("KC-BC-002", "legacy_logout_spi_options")] == "manual check: no automated detector"
    assert s["summary"]["checks_not_executed_by_source"]["server_config"] == 2
    assert s["summary"]["data_sources_available"] == ["access_log", "event_log", "realm_export", "server_log"]


def test_only_realm_export_available(loaded_store):
    s = run_assessment(loaded_store, "22.0.5", "26.6.3", data_sources=["realm_export"])
    fs = loaded_store.find(FINDINGS, {"doc_type": "finding", "assessment_id": s["assessment_id"]})
    assert {f["bc_id"] for f in fs} == {"KC-BC-001", "KC-BC-004"}       # log-based BCs cannot run
    assert all(f["detection_sources"] == ["realm"] for f in fs)          # no runtime corroboration either
    reasons = {(c["bc_id"], c["check_id"]): c["reason"] for c in s["summary"]["checks_not_executed"]}
    assert reasons[("KC-BC-002", "logout_with_redirect_uri")] == "data source 'access_log' not available"
    assert reasons[("KC-BC-005", "unattributed_calls")] == "data source 'access_log' not available"


def test_only_logs_available(loaded_store):
    s = run_assessment(loaded_store, "22.0.5", "26.6.3", data_sources=["access_log", "event_log"])
    fs = loaded_store.find(FINDINGS, {"doc_type": "finding", "assessment_id": s["assessment_id"]})
    assert {f["bc_id"] for f in fs} == {"KC-BC-002", "KC-BC-003", "KC-BC-005"}
