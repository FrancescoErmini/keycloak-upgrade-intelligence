"""High-level orchestration shared by the API and the CLI."""
from __future__ import annotations

from pathlib import Path

import yaml

from .detection.analyzers import run_assessment
from .ingestion.breaking_changes import ingest_breaking_changes
from .ingestion.logs import ingest_fixture_logs, ingest_runtime_logs
from .ingestion.realms import ingest_realm
from .llm.providers import get_provider
from .store import Store


def load_scenarios(data_dir: Path) -> dict:
    return yaml.safe_load((data_dir / "scenarios" / "upgrade-scenarios.yaml").read_text(encoding="utf-8"))


def ingest_all(store: Store, settings, include_runtime: bool = True) -> dict:
    store.ensure_indices()
    out = {
        "breaking_changes": ingest_breaking_changes(store, settings, get_provider(settings)),
        "realm": ingest_realm(store, settings),
        "fixture_logs": ingest_fixture_logs(store, settings),
    }
    if include_runtime:
        out["runtime_logs"] = ingest_runtime_logs(store, settings)
    return out


def bootstrap(store: Store, settings) -> dict:
    """Ingest everything and run every assessment defined in upgrade-scenarios.yaml."""
    result = ingest_all(store, settings)
    scenarios = load_scenarios(settings.data_dir)
    result["assessments"] = []
    for a in scenarios["assessments"]:
        s = run_assessment(store, a["source_version"], a["target_version"], label=a["id"])
        result["assessments"].append({"id": a["id"], "assessment_id": s["assessment_id"], "status": s["status"],
                                      **{k: s["summary"][k] for k in ("impacted_clients", "detected_bc", "anonymous_calls")}})
    return result
