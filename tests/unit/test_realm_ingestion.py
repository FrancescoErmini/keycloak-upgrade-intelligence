from collections import Counter

from app.ingestion.realms import analyze_redirect_uri, ingest_realm
from app.store import REALMS

EXPECTED_DISTRIBUTION = {"authorization_code": 35, "client_credentials": 25, "public_spa": 15, "saml": 15, "legacy": 10}


def test_realm_has_100_clients_with_expected_distribution(store, settings):
    res = ingest_realm(store, settings)
    assert res["clients"] == 100
    clients = store.find(REALMS, {"doc_type": "client"})
    assert Counter(c["client_type"] for c in clients) == EXPECTED_DISTRIBUTION


def test_realm_ingestion_is_idempotent(store, settings):
    first = ingest_realm(store, settings)
    n = store.count(REALMS)
    second = ingest_realm(store, settings)
    assert first["snapshot_id"] == second["snapshot_id"]
    assert store.count(REALMS) == n == 101  # 100 clients + 1 snapshot summary


def test_normalization_and_inventory(store, settings):
    ingest_realm(store, settings)
    snap = store.find(REALMS, {"doc_type": "snapshot"})[0]["snapshot_id"]
    portal = store.get(REALMS, f"{snap}:legacy-portal")
    assert portal["client_type"] == "legacy"
    assert "implicit" in portal["grant_types"]
    assert portal["redirect_uri_analysis"][0]["host_wildcard"] is True
    assert portal["inventory"]["business_criticality"] == "critical"
    svc = store.get(REALMS, f"{snap}:svc-reporting")
    assert svc["grant_types"] == ["client_credentials"]
    assert svc["protocol_mappers"][0]["multivalued"] is False


def test_redirect_uri_analysis():
    assert analyze_redirect_uri("https://example.com*")["host_wildcard"] is True
    a = analyze_redirect_uri("https://example.com/*")
    assert a["host_wildcard"] is False and a["path_wildcard"] is True
    assert analyze_redirect_uri("/callback", "https://app.example.com")["authority"] == "app.example.com"
    assert analyze_redirect_uri("*")["kind"] == "special"
