from fastapi.testclient import TestClient

from app.main import create_app
from app.store import MemoryStore


def test_end_to_end_api(settings):
    app = create_app(MemoryStore(), settings)
    with TestClient(app) as c:
        assert c.get("/api/health").json()["status"] == "ok"
        boot = c.post("/api/bootstrap").json()
        assert len(boot["assessments"]) == 4
        r = c.post("/api/assessments", json={"source_version": "26.5.0", "target_version": "26.6.3",
                                             "log_origins": ["synthetic-fixture"]})
        assert r.status_code == 200
        a = r.json()
        assert a["summary"]["clients_assessed"] == 100
        findings = c.get(f"/api/assessments/{a['assessment_id']}/findings").json()
        assert findings and findings == sorted(findings, key=lambda f: -f["risk_score"])
        detail = c.get(f"/api/assessments/{a['assessment_id']}/clients/legacy-portal").json()
        assert detail["client"]["client_id"] == "legacy-portal" and detail["findings"]
        exp = c.get(f"/api/findings/{findings[0]['finding_id']}/explanation").json()
        assert findings[0]["bc_id"] in exp["explanation"]
        assert c.post("/api/assessments", json={"source_version": "26.6.3", "target_version": "26.5.0"}).status_code == 422
        assert c.get("/api/logs/summary", params={"client_id": "anonymous"}).json()["anonymous"] > 0
        assert c.get("/api/stats").json()["kc-realm-snapshots"] == 101
