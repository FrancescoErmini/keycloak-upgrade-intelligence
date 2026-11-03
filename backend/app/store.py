"""Storage abstraction over the five Elasticsearch indices.

`ElasticStore` is used in Docker; `MemoryStore` implements the same contract
in-process so that pipelines and detection can be unit-tested without a cluster.
Filters are exact-match on (possibly dotted) fields; list values match if they
contain the filter value.
"""
from __future__ import annotations

import copy
import json
import math
from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .utils import get_path

KNOWLEDGE = "kc-bc-knowledge"
RULES = "kc-bc-rules"
REALMS = "kc-realm-snapshots"
LOGS = "kc-runtime-logs"
FINDINGS = "kc-impact-findings"
ALL_INDICES = (KNOWLEDGE, RULES, REALMS, LOGS, FINDINGS)
LOG_PIPELINE = "kc-runtime-logs-normalize"

Filters = dict[str, Any] | None


def load_mapping(assets_dir: Path, index: str, embedding_dim: int | None = None) -> dict:
    body = json.loads((assets_dir / "mappings" / f"{index}.json").read_text(encoding="utf-8"))
    if embedding_dim and index == KNOWLEDGE:
        body["mappings"]["properties"]["embedding"]["dims"] = embedding_dim
    return body


def _matches(doc: dict, filters: Filters) -> bool:
    if not filters:
        return True
    for field, expected in filters.items():
        value = get_path(doc, field)
        expected_values = expected if isinstance(expected, (list, tuple, set)) else [expected]
        if isinstance(value, list):
            if not any(v in value for v in expected_values):
                return False
        elif value not in expected_values:
            return False
    return True


class Store(ABC):
    @abstractmethod
    def ensure_indices(self) -> None: ...

    @abstractmethod
    def upsert_many(self, index: str, docs: Iterable[tuple[str, dict]]) -> int: ...

    @abstractmethod
    def get(self, index: str, doc_id: str) -> dict | None: ...

    @abstractmethod
    def find(self, index: str, filters: Filters = None) -> list[dict]: ...

    @abstractmethod
    def count(self, index: str, filters: Filters = None) -> int: ...

    @abstractmethod
    def delete(self, index: str, filters: Filters) -> int: ...

    @abstractmethod
    def knn(self, index: str, field: str, vector: list[float], k: int, filters: Filters = None) -> list[tuple[float, dict]]: ...

    def refresh(self, index: str) -> None:  # pragma: no cover - only meaningful for ES
        return None

    def ping(self) -> bool:
        return True


class MemoryStore(Store):
    def __init__(self) -> None:
        self.data: dict[str, dict[str, dict]] = {i: {} for i in ALL_INDICES}

    def ensure_indices(self) -> None:
        for i in ALL_INDICES:
            self.data.setdefault(i, {})

    def upsert_many(self, index: str, docs: Iterable[tuple[str, dict]]) -> int:
        n = 0
        for doc_id, doc in docs:
            self.data[index][doc_id] = copy.deepcopy(doc)
            n += 1
        return n

    def get(self, index: str, doc_id: str) -> dict | None:
        doc = self.data[index].get(doc_id)
        return copy.deepcopy(doc) if doc is not None else None

    def find(self, index: str, filters: Filters = None) -> list[dict]:
        return [copy.deepcopy(d) for d in self.data[index].values() if _matches(d, filters)]

    def count(self, index: str, filters: Filters = None) -> int:
        return sum(1 for d in self.data[index].values() if _matches(d, filters))

    def delete(self, index: str, filters: Filters) -> int:
        ids = [k for k, d in self.data[index].items() if _matches(d, filters)]
        for k in ids:
            del self.data[index][k]
        return len(ids)

    def knn(self, index: str, field: str, vector: list[float], k: int, filters: Filters = None) -> list[tuple[float, dict]]:
        def cos(a: list[float], b: list[float]) -> float:
            na = math.sqrt(sum(x * x for x in a)) or 1.0
            nb = math.sqrt(sum(x * x for x in b)) or 1.0
            return sum(x * y for x, y in zip(a, b)) / (na * nb)

        scored = [(cos(vector, d[field]), copy.deepcopy(d)) for d in self.data[index].values()
                  if field in d and _matches(d, filters)]
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:k]


class ElasticStore(Store):
    def __init__(self, url: str, assets_dir: Path, embedding_dim: int = 384) -> None:
        from elasticsearch import Elasticsearch

        self.es = Elasticsearch(url, request_timeout=60)
        self.assets_dir = assets_dir
        self.embedding_dim = embedding_dim

    def ping(self) -> bool:
        try:
            return bool(self.es.ping())
        except Exception:
            return False

    def ensure_indices(self) -> None:
        pipeline = json.loads((self.assets_dir / "ingest-pipelines" / f"{LOG_PIPELINE}.json").read_text(encoding="utf-8"))
        self.es.ingest.put_pipeline(id=LOG_PIPELINE, **pipeline)
        for index in ALL_INDICES:
            if not self.es.indices.exists(index=index):
                body = load_mapping(self.assets_dir, index, self.embedding_dim)
                self.es.indices.create(index=index, settings=body.get("settings"), mappings=body["mappings"])

    @staticmethod
    def _query(filters: Filters) -> dict:
        if not filters:
            return {"match_all": {}}
        clauses = []
        for field, value in filters.items():
            if isinstance(value, (list, tuple, set)):
                clauses.append({"terms": {field: list(value)}})
            else:
                clauses.append({"term": {field: value}})
        return {"bool": {"filter": clauses}}

    def upsert_many(self, index: str, docs: Iterable[tuple[str, dict]]) -> int:
        from elasticsearch import helpers

        actions = ({"_op_type": "index", "_index": index, "_id": doc_id, "_source": doc} for doc_id, doc in docs)
        ok, _ = helpers.bulk(self.es, actions, chunk_size=500, refresh="wait_for")
        return ok

    def get(self, index: str, doc_id: str) -> dict | None:
        res = self.es.options(ignore_status=404).get(index=index, id=doc_id)
        return res.get("_source") if res.get("found") else None

    def find(self, index: str, filters: Filters = None) -> list[dict]:
        from elasticsearch import helpers

        return [h["_source"] for h in helpers.scan(self.es, index=index, query={"query": self._query(filters)}, size=1000)]

    def count(self, index: str, filters: Filters = None) -> int:
        return int(self.es.count(index=index, query=self._query(filters))["count"])

    def delete(self, index: str, filters: Filters) -> int:
        res = self.es.delete_by_query(index=index, query=self._query(filters), refresh=True, conflicts="proceed")
        return int(res.get("deleted", 0))

    def knn(self, index: str, field: str, vector: list[float], k: int, filters: Filters = None) -> list[tuple[float, dict]]:
        knn: dict[str, Any] = {"field": field, "query_vector": vector, "k": k, "num_candidates": max(50, k * 10)}
        if filters:
            knn["filter"] = self._query(filters)
        res = self.es.search(index=index, knn=knn, size=k, source_excludes=[field])
        return [(float(h["_score"]), h["_source"]) for h in res["hits"]["hits"]]

    def refresh(self, index: str) -> None:
        self.es.indices.refresh(index=index)


def build_store(settings) -> Store:
    if settings.store_backend == "memory":
        return MemoryStore()
    return ElasticStore(settings.es_url, settings.es_assets_dir, settings.embedding_dim)
