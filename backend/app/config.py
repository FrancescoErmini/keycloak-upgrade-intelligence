"""Runtime configuration, read from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    store_backend: str = field(default_factory=lambda: _env("STORE_BACKEND", "elasticsearch"))
    es_url: str = field(default_factory=lambda: _env("ES_URL", "http://localhost:9200"))
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", str(REPO_ROOT / "data"))))
    es_assets_dir: Path = field(default_factory=lambda: Path(_env("ES_ASSETS_DIR", str(REPO_ROOT / "elasticsearch"))))
    keycloak_log_dir: Path = field(default_factory=lambda: Path(_env("KEYCLOAK_LOG_DIR", str(REPO_ROOT / "runtime-logs"))))
    # Optional download of the official upgrading guide (Pipeline A). Empty = use local file.
    bc_source_url: str = field(default_factory=lambda: _env("BC_SOURCE_URL", ""))
    embedding_backend: str = field(default_factory=lambda: _env("EMBEDDING_BACKEND", "hash"))
    embedding_model: str = field(default_factory=lambda: _env("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"))
    embedding_dim: int = field(default_factory=lambda: int(_env("EMBEDDING_DIM", "384")))
    llm_provider: str = field(default_factory=lambda: _env("LLM_PROVIDER", "none"))
    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_URL", "http://ollama:11434"))
    ollama_model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "llama3.1:8b"))
    auto_bootstrap: bool = field(default_factory=lambda: _env("AUTO_BOOTSTRAP", "false").lower() == "true")
    # Maps runtime log sub-directories (instance name) to the Keycloak version they run.
    instance_versions: dict[str, str] = field(default_factory=lambda: {
        "source": _env("KC_SOURCE_VERSION", "26.5.0"),
        "target": _env("KC_TARGET_VERSION", "26.6.3"),
        "legacy": _env("KC_LEGACY_VERSION", "25.0.6"),
    })


def get_settings() -> Settings:
    return Settings()
