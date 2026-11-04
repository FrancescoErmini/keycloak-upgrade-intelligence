"""Detection accuracy against the ground truth planted by scripts/generate_dataset.py."""
import pytest

from app.detection.analyzers import redirect_matches, run_assessment
from app.store import FINDINGS

SCENARIOS = ["s-26.5-to-26.6.3", "s-22.0-to-26.6.3", "s-25.0-to-26.6.3", "s-26.3-to-26.5"]


def _findings(store, summary):
    return store.find(FINDINGS, {"doc_type": "finding", "assessment_id": summary["assessment_id"]})


@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_all_known_positives_are_detected_with_expected_confidence(loaded_store, expected, scenario_id):
    sc = expected["scenarios"][scenario_id]
    summary = run_assessment(loaded_store, sc["source_version"], sc["target_version"], log_origins=expected["log_origins"])
    got = {(f["bc_id"], f["client_id"]): f for f in _findings(loaded_store, summary)}
    for e in sc["expected"]:
        key = (e["bc_id"], e["client_id"])
        assert key in got, f"missing finding {key}"
        assert got[key]["confidence_label"] == e["confidence"], key
        assert got[key]["attribution"] == e["attribution"], key
    assert set(got) == {(e["bc_id"], e["client_id"]) for e in sc["expected"]}


@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_compatible_clients_are_not_flagged(loaded_store, expected, scenario_id):
    sc = expected["scenarios"][scenario_id]
    summary = run_assessment(loaded_store, sc["source_version"], sc["target_version"], log_origins=expected["log_origins"])
    flagged = {f["client_id"] for f in _findings(loaded_store, summary) if f["kind"] == "breaking-change"}
    assert flagged.isdisjoint(sc["must_not_flag"])


def test_version_awareness(loaded_store):
    s = run_assessment(loaded_store, "26.5.0", "26.6.3")
    assert s["summary"]["applicable_rules"] == ["KC-BC-001", "KC-BC-005"]
    assert {r["bc_id"] for r in s["summary"]["skipped_rules"]} == {"KC-BC-002", "KC-BC-003", "KC-BC-004"}
    s = run_assessment(loaded_store, "26.6.3", "26.7.0")
    assert s["summary"]["detected_bc"] == 0 and s["status"] == "ready"


def test_assessment_is_idempotent(loaded_store):
    a = run_assessment(loaded_store, "25.0.6", "26.6.3")
    n = loaded_store.count(FINDINGS)
    b = run_assessment(loaded_store, "25.0.6", "26.6.3")
    assert a["assessment_id"] == b["assessment_id"] and loaded_store.count(FINDINGS) == n


def test_anonymous_handling(loaded_store):
    s = run_assessment(loaded_store, "25.0.6", "26.6.3", log_origins=["synthetic-fixture"])
    fs = _findings(loaded_store, s)
    anon = [f for f in fs if f["client_id"] == "anonymous"]
    assert anon and all(f["client_identified"] is False for f in anon)
    control = next(f for f in anon if f["bc_id"] == "KC-BC-005")
    assert control["evidence_count"] == s["summary"]["anonymous_calls"] - _non_realm_anonymous(loaded_store)
    # anonymous calls never count as impacted clients
    assert "anonymous" not in {f["client_id"] for f in fs if f["client_identified"]}


def _non_realm_anonymous(store):
    from app.store import LOGS

    return sum(1 for d in store.find(LOGS, {"client_identified": False})
               if not ((d.get("url") or {}).get("path") or "").startswith("/realms/"))


def test_findings_carry_evidence_and_remediation(loaded_store):
    s = run_assessment(loaded_store, "25.0.6", "26.6.3")
    for f in _findings(loaded_store, s):
        assert f["evidence"], f["finding_id"]
        assert f["remediation"]
        assert f["source_version"] == "25.0.6" and f["target_version"] == "26.6.3"
    portal = next(f for f in _findings(loaded_store, s) if (f["bc_id"], f["client_id"]) == ("KC-BC-001", "legacy-portal"))
    static = [e for e in portal["evidence"] if e["type"] == "static"]
    assert static[0]["value"] == "https://example.com*" and static[0]["suggested_value"] == "https://example.com/*"
    assert portal["detection_sources"] == ["realm", "runtime"]


def test_redirect_matching():
    assert redirect_matches("https://example.com*", "https://example.com.other.test/cb")
    assert redirect_matches("https://a.example.com/*", "https://a.example.com/x")
    assert not redirect_matches("https://a.example.com/*", "https://b.example.com/x")
    assert redirect_matches("/cb", "https://a.example.com/cb", "https://a.example.com")
