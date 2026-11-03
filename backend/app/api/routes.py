"""REST API consumed by the dashboard and by the test-runner."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..detection.analyzers import run_assessment
from ..ingestion.breaking_changes import ingest_breaking_changes
from ..ingestion.logs import ingest_fixture_logs, ingest_runtime_logs
from ..ingestion.realms import ingest_realm
from ..llm.providers import get_provider
from ..rag.retrieval import explain_finding, search
from ..services import bootstrap, ingest_all, load_scenarios
from ..store import ALL_INDICES, FINDINGS, LOGS, REALMS, RULES, Store
from ..utils import parse_version

router = APIRouter()


def store_dep(request: Request) -> Store:
    return request.app.state.store


def settings_dep(request: Request):
    return request.app.state.settings


class AssessmentRequest(BaseModel):
    source_version: str = Field(examples=["26.5.0"])
    target_version: str = Field(examples=["26.6.3"])
    snapshot_id: str | None = None
    log_origins: list[str] | None = Field(default=None, examples=[["synthetic-fixture", "keycloak-runtime"]])
    label: str | None = None


@router.get("/health")
def health(store: Store = Depends(store_dep)):
    ok = store.ping()
    return {"status": "ok" if ok else "degraded", "store": type(store).__name__, "store_reachable": ok}


@router.get("/stats")
def stats(store: Store = Depends(store_dep)):
    return {i: store.count(i) for i in ALL_INDICES}


# ---------------- ingestion ----------------
@router.post("/ingest/all")
def ingest_everything(store: Store = Depends(store_dep), settings=Depends(settings_dep)):
    return ingest_all(store, settings)


@router.post("/ingest/breaking-changes")
def ingest_bc(store: Store = Depends(store_dep), settings=Depends(settings_dep)):
    return ingest_breaking_changes(store, settings, get_provider(settings))


@router.post("/ingest/realm")
def ingest_realm_ep(store: Store = Depends(store_dep), settings=Depends(settings_dep)):
    return ingest_realm(store, settings)


@router.post("/ingest/logs")
def ingest_logs_ep(store: Store = Depends(store_dep), settings=Depends(settings_dep)):
    return ingest_fixture_logs(store, settings)


@router.post("/ingest/logs/runtime")
def ingest_runtime_ep(store: Store = Depends(store_dep), settings=Depends(settings_dep)):
    return ingest_runtime_logs(store, settings)


@router.post("/bootstrap")
def bootstrap_ep(store: Store = Depends(store_dep), settings=Depends(settings_dep)):
    return bootstrap(store, settings)


# ---------------- knowledge / rules ----------------
@router.get("/rules")
def rules(status: str | None = None, store: Store = Depends(store_dep)):
    return sorted(store.find(RULES, {"status": status} if status else None), key=lambda r: r["bc_id"])


@router.get("/rag/search")
def rag_search(q: str, k: int = 5, bc_id: str | None = None, store: Store = Depends(store_dep),
               settings=Depends(settings_dep)):
    return search(store, settings, q, k, bc_id)


@router.get("/scenarios")
def scenarios(settings=Depends(settings_dep)):
    return load_scenarios(settings.data_dir)


# ---------------- assessments ----------------
@router.post("/assessments")
def create_assessment(req: AssessmentRequest, store: Store = Depends(store_dep)):
    if parse_version(req.source_version) is None or parse_version(req.target_version) is None:
        raise HTTPException(422, "invalid version")
    if parse_version(req.source_version) >= parse_version(req.target_version):
        raise HTTPException(422, "source_version must be lower than target_version")
    try:
        return run_assessment(store, req.source_version, req.target_version, snapshot_id=req.snapshot_id,
                              log_origins=req.log_origins, label=req.label)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/assessments")
def list_assessments(store: Store = Depends(store_dep)):
    return sorted(store.find(FINDINGS, {"doc_type": "assessment"}), key=lambda a: a["created_at"], reverse=True)


def _assessment(store: Store, assessment_id: str) -> dict:
    a = store.get(FINDINGS, assessment_id)
    if not a or a.get("doc_type") != "assessment":
        raise HTTPException(404, "assessment not found")
    return a


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str, store: Store = Depends(store_dep)):
    return _assessment(store, assessment_id)


@router.get("/assessments/{assessment_id}/findings")
def get_findings(assessment_id: str, bc_id: str | None = None, client_id: str | None = None,
                 severity: str | None = None, store: Store = Depends(store_dep)):
    _assessment(store, assessment_id)
    filters = {"doc_type": "finding", "assessment_id": assessment_id}
    for k, v in (("bc_id", bc_id), ("client_id", client_id), ("severity", severity)):
        if v:
            filters[k] = v
    return sorted(store.find(FINDINGS, filters), key=lambda f: (-f["risk_score"], f["bc_id"], f["client_id"]))


@router.get("/assessments/{assessment_id}/clients/{client_id}")
def client_detail(assessment_id: str, client_id: str, store: Store = Depends(store_dep)):
    a = _assessment(store, assessment_id)
    client = store.get(REALMS, f"{a['snapshot_id']}:{client_id}")
    findings = store.find(FINDINGS, {"doc_type": "finding", "assessment_id": assessment_id, "client_id": client_id})
    if not client and not findings:
        raise HTTPException(404, "client not found")
    return {"client": client, "findings": findings}


@router.get("/findings/{finding_id}/explanation")
def explanation(finding_id: str, store: Store = Depends(store_dep), settings=Depends(settings_dep)):
    f = store.get(FINDINGS, finding_id)
    if not f or f.get("doc_type") != "finding":
        raise HTTPException(404, "finding not found")
    return explain_finding(store, settings, f, get_provider(settings))


# ---------------- logs ----------------
@router.get("/logs/summary")
def logs_summary(origin: str | None = None, client_id: str | None = None, store: Store = Depends(store_dep)):
    filters = {}
    if origin:
        filters["labels.origin"] = origin
    if client_id:
        filters["client_id"] = client_id
    docs = store.find(LOGS, filters or None)
    return {
        "records": len(docs),
        "anonymous": sum(1 for d in docs if not d.get("client_identified")),
        "by_origin": dict(Counter((d.get("labels") or {}).get("origin") for d in docs)),
        "by_kind": dict(Counter((d.get("event") or {}).get("kind") for d in docs)),
        "by_client_id_source": dict(Counter(d.get("client_id_source") for d in docs)),
        "top_clients": Counter(d["client_id"] for d in docs).most_common(10),
    }
