from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.config import REPO_ROOT, Settings
from app.store import MemoryStore

DATA = REPO_ROOT / "data"


@pytest.fixture(scope="session")
def settings(tmp_path_factory) -> Settings:
    return replace(Settings(), store_backend="memory", data_dir=DATA, llm_provider="none",
                   embedding_backend="hash", keycloak_log_dir=tmp_path_factory.mktemp("runtime-logs"))


@pytest.fixture
def store() -> MemoryStore:
    s = MemoryStore()
    s.ensure_indices()
    return s


@pytest.fixture
def loaded_store(store, settings):
    from app.services import ingest_all

    ingest_all(store, settings)
    return store


@pytest.fixture(scope="session")
def expected() -> dict:
    return json.loads((DATA / "scenarios" / "expected-findings.json").read_text())



def fixture_path(name: str) -> Path:
    return Path(__file__).parent / "fixtures" / name
