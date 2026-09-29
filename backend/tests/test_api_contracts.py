"""
RansomShield AI — API Contracts & Endpoints Comprehensive Tests
Phase 3A: Backend Foundation
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings
from backend.repositories.agent_repository import get_agent_repository
from backend.repositories.alert_repository import get_alert_repository
from backend.repositories.incident_repository import get_incident_repository
from backend.repositories.detection_repository import get_detection_repository
from backend.schemas.alert import AlertResponse
from backend.schemas.incident import IncidentResponse


@pytest.fixture
def client():
    # Clear in-memory repositories before each test
    get_agent_repository().clear()
    get_alert_repository().clear()
    get_incident_repository().clear()
    get_detection_repository().clear()

    test_settings = Settings(
        app_name="RansomShield AI Test Backend",
        app_version="0.1.0-test",
        environment="testing",
        mongodb_uri=None,
    )
    app = create_app(settings=test_settings)
    with TestClient(app) as test_client:
        yield test_client


# --- AGENTS API TESTS ---

def test_register_agent(client: TestClient):
    payload = {
        "agent_id": "endpoint-win11-01",
        "hostname": "WORKSTATION-01",
        "os_name": "Windows",
        "os_version": "11 Pro",
        "agent_version": "0.1.0",
        "ip_address": "10.0.0.15",
        "monitored_directories": ["C:\\Users\\Analyst\\Documents"],
    }
    response = client.post("/api/v1/agents/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert data["data"]["agent_id"] == "endpoint-win11-01"
    assert data["data"]["status"] == "online"


def test_list_agents(client: TestClient):
    # Register 2 agents
    client.post("/api/v1/agents/register", json={"agent_id": "agent-1", "hostname": "HOST-1"})
    client.post("/api/v1/agents/register", json={"agent_id": "agent-2", "hostname": "HOST-2"})

    response = client.get("/api/v1/agents")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]) == 2
    assert data["meta"]["count"] == 2


def test_get_agent_by_id(client: TestClient):
    client.post("/api/v1/agents/register", json={"agent_id": "agent-target", "hostname": "TARGET-HOST"})

    response = client.get("/api/v1/agents/agent-target")
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["hostname"] == "TARGET-HOST"

    # Unknown agent -> 404
    resp_404 = client.get("/api/v1/agents/non-existent-agent")
    assert resp_404.status_code == 404
    data_404 = resp_404.json()
    assert data_404["success"] is False
    assert data_404["error"]["code"] == "NOT_FOUND"


def test_get_agent_status(client: TestClient):
    client.post("/api/v1/agents/register", json={"agent_id": "agent-stat", "hostname": "STAT-HOST"})

    response = client.get("/api/v1/agents/agent-stat/status")
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["is_online"] is True
    assert "metrics" in data["data"]


# --- ALERTS API TESTS ---

def test_list_and_filter_alerts(client: TestClient):
    import asyncio
    alert_repo = get_alert_repository()
    now = time.time()
    asyncio.run(
        alert_repo.create(
            AlertResponse(
                alert_id="alt-1",
                endpoint_id="host-1",
                prediction="Ransomware",
                confidence=95.0,
                risk_score=90,
                severity="CRITICAL",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
    )
    asyncio.run(
        alert_repo.create(
            AlertResponse(
                alert_id="alt-2",
                endpoint_id="host-2",
                prediction="Goodware",
                confidence=70.0,
                risk_score=45,
                severity="LOW",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
    )

    # 1. List all
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    assert len(resp.json()["data"]) == 2

    # 2. Filter by severity
    resp_crit = client.get("/api/v1/alerts?severity=CRITICAL")
    assert len(resp_crit.json()["data"]) == 1
    assert resp_crit.json()["data"][0]["alert_id"] == "alt-1"

    # 3. Filter by endpoint
    resp_host2 = client.get("/api/v1/alerts?endpoint_id=host-2")
    assert len(resp_host2.json()["data"]) == 1
    assert resp_host2.json()["data"][0]["alert_id"] == "alt-2"


def test_alert_lifecycle_api(client: TestClient):
    import asyncio
    alert_repo = get_alert_repository()
    now = time.time()
    asyncio.run(
        alert_repo.create(
            AlertResponse(
                alert_id="alt-lifecycle",
                endpoint_id="host-1",
                prediction="Ransomware",
                confidence=92.0,
                risk_score=85,
                severity="HIGH",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
    )

    # 1. Acknowledge
    ack_resp = client.patch("/api/v1/alerts/alt-lifecycle/acknowledge", json={"note": "Investigating"})
    assert ack_resp.status_code == 200
    assert ack_resp.json()["data"]["status"] == "ACKNOWLEDGED"

    # 2. Resolve
    res_resp = client.patch("/api/v1/alerts/alt-lifecycle/resolve", json={"resolution_note": "False trigger cleaned"})
    assert res_resp.status_code == 200
    assert res_resp.json()["data"]["status"] == "RESOLVED"

    # 3. Non-existent alert
    resp_404 = client.patch("/api/v1/alerts/unknown-alt/acknowledge")
    assert resp_404.status_code == 404


# --- INCIDENTS API TESTS ---

def test_incident_lifecycle_and_state_machine_api(client: TestClient):
    import asyncio
    inc_repo = get_incident_repository()
    now = time.time()
    asyncio.run(
        inc_repo.create(
            IncidentResponse(
                incident_id="inc-soc-01",
                endpoint_id="host-1",
                severity="HIGH",
                status="OPEN",
                alert_ids=["alt-1"],
                detection_count=1,
                first_detection=now,
                last_detection=now,
                primary_prediction="Ransomware",
                highest_risk_score=85,
                created_at=now,
                updated_at=now,
            )
        )
    )

    # 1. Get incident
    get_resp = client.get("/api/v1/incidents/inc-soc-01")
    assert get_resp.status_code == 200
    assert get_resp.json()["data"]["status"] == "OPEN"

    # 2. Acknowledge: OPEN -> ACKNOWLEDGED
    ack_resp = client.patch("/api/v1/incidents/inc-soc-01/acknowledge")
    assert ack_resp.status_code == 200
    assert ack_resp.json()["data"]["status"] == "ACKNOWLEDGED"

    # 3. Resolve: ACKNOWLEDGED -> RESOLVED
    res_resp = client.patch("/api/v1/incidents/inc-soc-01/resolve", json={"resolution_note": "Remediated"})
    assert res_resp.status_code == 200
    assert res_resp.json()["data"]["status"] == "RESOLVED"

    # 4. Attempt invalid state transition: RESOLVED -> ACKNOWLEDGED must return 409 Conflict!
    invalid_resp = client.patch("/api/v1/incidents/inc-soc-01/acknowledge")
    assert invalid_resp.status_code == 409
    data = invalid_resp.json()
    assert data["success"] is False
    assert data["error"]["code"] == "INVALID_STATE_TRANSITION"


def test_incident_false_positive_transition(client: TestClient):
    import asyncio
    inc_repo = get_incident_repository()
    now = time.time()
    asyncio.run(
        inc_repo.create(
            IncidentResponse(
                incident_id="inc-fp-01",
                endpoint_id="host-1",
                severity="MEDIUM",
                status="OPEN",
                created_at=now,
                updated_at=now,
                first_detection=now,
                last_detection=now,
            )
        )
    )

    resp = client.patch("/api/v1/incidents/inc-fp-01/false-positive", json={"reason": "Benchmark stress test"})
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "FALSE_POSITIVE"
    assert "False Positive" in resp.json()["data"]["resolution_note"]


# --- DETECTIONS API TESTS ---

def test_detections_api(client: TestClient):
    payload = {
        "endpoint_id": "host-win11-01",
        "timestamp": time.time(),
        "window_seconds": 10,
        "prediction": "Ransomware",
        "confidence": 93.4,
        "risk_score": 89,
        "probabilities": {"Goodware": 0.066, "Ransomware": 0.934},
        "model_version": "xgb_ransomware_v2",
        "stage": 4,
        "features": {"File_Delete_archived": 3.0, "file_name_entropy": 4.1},
        "indicators": [{"label": "Archive file deletion", "feature_name": "File_Delete_archived", "weight": 95}],
        "explanation": "Critical rapid archive deletion detected.",
        "event_count": 140,
        "duration_ms": 320.5,
    }

    # 1. Ingest Detection
    post_resp = client.post("/api/v1/detections", json=payload)
    assert post_resp.status_code == 201
    data = post_resp.json()
    assert data["success"] is True
    det_id = data["data"]["detection_id"]
    assert det_id.startswith("det-")

    # 2. List detections
    list_resp = client.get("/api/v1/detections")
    assert list_resp.status_code == 200
    assert len(list_resp.json()["data"]) == 1

    # 3. Get detection by ID
    get_resp = client.get(f"/api/v1/detections/{det_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["data"]["risk_score"] == 89
    assert get_resp.json()["data"]["features"]["File_Delete_archived"] == 3.0
