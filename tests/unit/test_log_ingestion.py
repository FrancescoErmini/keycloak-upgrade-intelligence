import shutil

from app.ingestion.logs import ANONYMOUS, ingest_files, ingest_fixture_logs, ingest_runtime_logs, parse_record
from app.store import LOGS
from tests.conftest import fixture_path


def _access(target: str, mdc=None):
    rec = {"@timestamp": "2026-11-02T10:00:00Z", "log.logger": "http-access-log",
           "message": f'10.0.0.1 - - [02/Nov/2026:10:00:00 +0000] "GET {target} HTTP/1.1" 200 12 "-" "ua"'}
    if mdc:
        rec["mdc"] = mdc
    return rec


def test_anonymous_rule_when_client_missing():
    d = parse_record(_access("/realms/demo/.well-known/openid-configuration"), "synthetic-fixture", "f")
    assert d["client_id"] == ANONYMOUS
    assert d["client_identified"] is False
    assert d["client"]["id"] == ANONYMOUS
    assert d["keycloak"]["realm"] == "demo"


def test_client_from_query_and_mdc_precedence():
    d = parse_record(_access("/realms/demo/protocol/openid-connect/auth?client_id=app-a"), "o", "f")
    assert (d["client_id"], d["client_id_source"], d["client_identified"]) == ("app-a", "query", True)
    d = parse_record(_access("/realms/demo/protocol/openid-connect/auth?client_id=app-a", {"kc.clientId": "app-b"}), "o", "f")
    assert (d["client_id"], d["client_id_source"]) == ("app-b", "mdc")


def test_event_record_parsing():
    rec = {"log.logger": "org.keycloak.events",
           "message": 'type="CODE_TO_TOKEN", realmId="x", realmName="demo", clientId="crm-web", userId="u1", ipAddress="10.1.1.1"'}
    d = parse_record(rec, "o", "f")
    assert d["event"]["action"] == "CODE_TO_TOKEN"
    assert d["client_id"] == "crm-web" and d["client_id_source"] == "event"
    rec["message"] = 'type="CLIENT_LOGIN_ERROR", realmName="demo", clientId="null", error="invalid_client_credentials"'
    d = parse_record(rec, "o", "f")
    assert d["client_id"] == ANONYMOUS and d["keycloak"]["error"] == "invalid_client_credentials"


def test_non_normalized_path_is_kept_verbatim():
    d = parse_record(_access("/realms/demo//protocol/openid-connect/auth?client_id=x"), "o", "f")
    assert d["url"]["path"] == "/realms/demo//protocol/openid-connect/auth"


def test_fixture_ingestion_is_idempotent(store, settings):
    first = ingest_fixture_logs(store, settings)
    n = store.count(LOGS)
    ingest_fixture_logs(store, settings)
    assert store.count(LOGS) == n == first["records"]
    assert first["anonymous"] > 0
    assert store.count(LOGS, {"client_id": ANONYMOUS}) == store.count(LOGS, {"client_identified": False})


def test_runtime_logs_are_labelled_and_non_json_lines_skipped(store, settings, tmp_path):
    inst = tmp_path / "source"
    inst.mkdir()
    shutil.copy(fixture_path("sample-runtime.log"), inst / "keycloak.log")
    from dataclasses import replace

    res = ingest_runtime_logs(store, replace(settings, keycloak_log_dir=tmp_path))
    assert res["records"] == 5
    docs = store.find(LOGS, {"labels.origin": "keycloak-runtime"})
    assert {d["keycloak"]["instance"] for d in docs} == {"source"}
    assert {d["keycloak"]["version"] for d in docs} == {settings.instance_versions["source"]}
    assert sum(1 for d in docs if d["client_id"] == ANONYMOUS) == 3
    # synthetic fixtures are never mixed with server-produced logs
    assert store.count(LOGS, {"labels.origin": "synthetic-fixture"}) == 0


def test_ingest_files_counts(store):
    res = ingest_files(store, [fixture_path("sample-runtime.log")], "keycloak-runtime", "target", "26.6.3")
    assert res["records"] == 5 and res["anonymous"] == 3
