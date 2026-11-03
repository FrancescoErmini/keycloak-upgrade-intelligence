"""Scenario tests: each one has a reference BC, a purpose-built client, an HTTP call,
the expected outcome per version, the evidence, and the finding the engine must produce."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
import requests

from app.utils import version_matches

pytestmark = pytest.mark.live


def expected_outcome(test: dict, version: str) -> str:
    for row in test["expected"]:
        if version_matches(version, row["versions"]):
            return row["outcome"]
    raise AssertionError(f"no expectation for {version}")


def _response_evidence(r: requests.Response) -> dict:
    return {"status": r.status_code, "location": r.headers.get("Location"),
            "content_type": r.headers.get("Content-Type"), "body_excerpt": r.text[:600]}


def _call(instance, test, **overrides):
    req = test["request"]
    url = f"{instance['url']}{req['path']}"
    r = requests.request(req["method"], url, params=req.get("params"), data=overrides.get("data", req.get("data")),
                         allow_redirects=False, timeout=15)
    return r, {"method": req["method"], "url": url, "params": req.get("params"), "data": overrides.get("data", req.get("data"))}


def test_redirect_wildcard(instance, scenarios, evidence):
    t = scenarios["redirect-wildcard"]
    r, request = _call(instance, t)
    body = r.text.lower()
    if r.status_code == 400 or "invalid parameter: redirect_uri" in body or "invalid redirect" in body:
        outcome = "rejected"
    elif r.status_code == 200 and ("kc-form-login" in body or "username" in body):
        outcome = "accepted"
    else:
        outcome = f"unexpected:{r.status_code}"
    exp = expected_outcome(t, instance["version"])
    evidence(bc_id=t["bc_id"], client_id=t["client_id"], instance=instance, request=request,
             response=_response_evidence(r), outcome=outcome, expected=exp, matrix_verified=t["matrix_verified"],
             expected_finding={"bc_id": "KC-BC-001", "client_id": "legacy-portal", "source": "realm"})
    assert outcome == exp


def test_legacy_logout(instance, scenarios, evidence):
    t = scenarios["legacy-logout"]
    r, request = _call(instance, t)
    body = r.text.lower()
    if r.status_code >= 400 or "invalid parameter: redirect_uri" in body:
        outcome = "rejected"
    elif r.status_code in (200, 302):
        outcome = "accepted"
    else:
        outcome = f"unexpected:{r.status_code}"
    exp = expected_outcome(t, instance["version"])
    evidence(bc_id=t["bc_id"], client_id=t["client_id"], instance=instance, request=request,
             response=_response_evidence(r), outcome=outcome, expected=exp, matrix_verified=t["matrix_verified"],
             expected_finding={"bc_id": "KC-BC-002", "client_id": "legacy-portal", "attribution": "inferred-redirect-uri",
                               "source": "access log"})
    assert outcome == exp


def test_non_normalized_path(instance, scenarios, evidence):
    t = scenarios["non-normalized-path"]
    r, request = _call(instance, t)
    outcome = "rejected" if r.status_code == 400 else "accepted" if r.status_code == 200 else f"unexpected:{r.status_code}"
    exp = expected_outcome(t, instance["version"])
    evidence(bc_id=t["bc_id"], client_id=t["client_id"], instance=instance, request=request,
             response=_response_evidence(r), outcome=outcome, expected=exp, matrix_verified=t["matrix_verified"],
             expected_finding={"bc_id": "KC-BC-003", "client_id": "anonymous", "source": "access log + status"})
    assert outcome == exp


def _jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def test_role_mapper_multivalued(instance, scenarios, evidence):
    t = scenarios["role-mapper-multivalued"]
    secret = hashlib.sha256(f"poc-secret:{t['client_id']}".encode()).hexdigest()[:32]  # see generate_dataset.py
    url = f"{instance['url']}{t['request']['path']}"
    r = requests.post(url, data={"grant_type": "client_credentials", "client_id": t["client_id"], "client_secret": secret},
                      timeout=15)
    assert r.status_code == 200, r.text
    claims = _jwt_claims(r.json()["access_token"])
    value = claims.get(t["request"]["claim"])
    outcome = "array" if isinstance(value, list) else "string" if isinstance(value, str) else f"unexpected:{type(value).__name__}"
    exp = expected_outcome(t, instance["version"])
    evidence(bc_id=t["bc_id"], client_id=t["client_id"], instance=instance,
             request={"method": "POST", "url": url, "grant_type": "client_credentials"},
             response={"status": r.status_code, "claim": t["request"]["claim"], "claim_value": value},
             outcome=outcome, expected=exp, matrix_verified=t["matrix_verified"],
             expected_finding={"bc_id": "KC-BC-004", "client_id": "svc-reporting", "source": "realm + token"})
    assert outcome == exp


def test_anonymous_client(instance, scenarios, evidence):
    t = scenarios["anonymous-client"]
    r, request = _call(instance, t)
    outcome = "rejected" if r.status_code in (400, 401) else f"unexpected:{r.status_code}"
    evidence(bc_id=t["bc_id"], client_id="anonymous", instance=instance, request=request,
             response=_response_evidence(r), outcome=outcome, expected="rejected",
             expected_finding={"bc_id": "KC-BC-005", "client_id": "anonymous", "client_identified": False})
    assert outcome == "rejected"
