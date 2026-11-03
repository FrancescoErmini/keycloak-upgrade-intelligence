"""Live breaking-change suite: real HTTP traffic against the Keycloak containers.

Instances are configured with KC_SOURCE_URL, KC_TARGET_URL and (optional) KC_LEGACY_URL.
Each test records request, response, server version, outcome and evidence as JSON in
EVIDENCE_DIR, so every run is reproducible and auditable.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests
import yaml

from app.config import REPO_ROOT

INSTANCES = {
    "source": os.environ.get("KC_SOURCE_URL", "http://localhost:8080"),
    "target": os.environ.get("KC_TARGET_URL", "http://localhost:8081"),
    "legacy": os.environ.get("KC_LEGACY_URL", ""),
}
EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", REPO_ROOT / "tests" / ".evidence"))


def _reachable(url: str) -> bool:
    if not url:
        return False
    try:
        return requests.get(f"{url}/realms/demo/.well-known/openid-configuration", timeout=5).status_code == 200
    except requests.RequestException:
        return False


def server_version(url: str, name: str) -> str:
    """Version reported by the server itself (admin serverinfo), falling back to env."""
    try:
        tok = requests.post(f"{url}/realms/master/protocol/openid-connect/token", timeout=10, data={
            "grant_type": "password", "client_id": "admin-cli",
            "username": os.environ.get("KC_ADMIN_USER", "admin"),
            "password": os.environ.get("KC_ADMIN_PASSWORD", "admin")}).json()["access_token"]
        info = requests.get(f"{url}/admin/serverinfo", headers={"Authorization": f"Bearer {tok}"}, timeout=10).json()
        return re.sub(r"[^0-9.].*$", "", info["systemInfo"]["version"])
    except Exception:
        env = os.environ.get(f"KC_{name.upper()}_VERSION")
        if env:
            return env
        pytest.skip(f"cannot determine version of {name} instance")


@pytest.fixture(scope="session")
def scenarios() -> dict:
    data = yaml.safe_load((REPO_ROOT / "data" / "scenarios" / "upgrade-scenarios.yaml").read_text())
    return {t["id"]: t for t in data["live_tests"]}


@pytest.fixture(scope="session", params=["source", "target", "legacy"])
def instance(request) -> dict:
    name = request.param
    url = INSTANCES[name]
    if not _reachable(url):
        pytest.skip(f"Keycloak '{name}' not reachable at {url or '(not configured)'}")
    return {"name": name, "url": url, "version": server_version(url, name)}


@pytest.fixture
def evidence(request):
    records = []

    def record(**kw):
        records.append({"recorded_at": datetime.now(timezone.utc).isoformat(), **kw})

    yield record
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.nodeid.split("::")[-1])
    outcome = "failed" if getattr(request.node, "rep_call", None) and request.node.rep_call.failed else "passed"
    (EVIDENCE_DIR / f"{name}.json").write_text(json.dumps(
        {"test": request.node.nodeid, "result": outcome, "records": records}, indent=2, default=str))


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)
