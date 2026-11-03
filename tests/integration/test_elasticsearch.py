"""Integration with a real Elasticsearch (ES_URL). Skipped when the cluster is not reachable."""
from __future__ import annotations

import os
from dataclasses import replace

import pytest

from app.store import ALL_INDICES, KNOWLEDGE, LOGS, ElasticStore

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def es_store(settings):
    url = os.environ.get("ES_URL", "http://localhost:9200")
    st = ElasticStore(url, settings.es_assets_dir, settings.embedding_dim)
    if not st.ping():
        pytest.skip(f"Elasticsearch not reachable at {url}")
    st.ensure_indices()
    return st


def test_five_indices_exist(es_store):
    for index in ALL_INDICES:
        assert es_store.es.indices.exists(index=index)


def test_ingestion_is_idempotent_on_elasticsearch(es_store, settings):
    from app.services import ingest_all

    cfg = replace(settings, store_backend="elasticsearch")
    ingest_all(es_store, cfg, include_runtime=False)
    counts = {i: es_store.count(i) for i in ALL_INDICES}
    ingest_all(es_store, cfg, include_runtime=False)
    assert {i: es_store.count(i) for i in ALL_INDICES} == counts
    assert counts[KNOWLEDGE] > 0 and counts[LOGS] > 0


def test_ingest_pipeline_applies_anonymous_rule(es_store):
    es_store.es.index(index=LOGS, id="pipeline-test", refresh="wait_for",
                      document={"@timestamp": "2026-11-01T00:00:00Z", "message": "external shipper",
                                "labels": {"origin": "pipeline-test"}})
    doc = es_store.get(LOGS, "pipeline-test")
    assert doc["client_id"] == "anonymous" and doc["client_identified"] is False and doc["client"]["id"] == "anonymous"
    es_store.es.index(index=LOGS, id="pipeline-test-2", refresh="wait_for",
                      document={"message": "x", "mdc": {"kc.clientId": "crm-web"}, "labels": {"origin": "pipeline-test"}})
    assert es_store.get(LOGS, "pipeline-test-2")["client_id"] == "crm-web"
    es_store.delete(LOGS, {"labels.origin": "pipeline-test"})


def test_knn_retrieval(es_store, settings):
    from app.rag.retrieval import search

    hits = search(es_store, settings, "wildcard in redirect uri host name", k=2)
    assert hits[0]["section_anchor"] == "redirect-uri-wildcard-hostname"
