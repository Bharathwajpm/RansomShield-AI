"""
RansomShield AI — Agent to Backend Integration Tests
Phase 3A: Backend Foundation

Verifies seamless compatibility between Phase 2 Agent domain objects and
Phase 3 Backend schemas without breaking the agent detection architecture.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.adapters.agent_adapter import AgentModelAdapter
from agent.inference.detection_result import DetectionResult
from agent.detection.severity import AlertSeverity, IncidentSeverity, AlertStatus, IncidentStatus
from agent.detection.alert_manager import DetectionAlert
from agent.detection.incident_manager import Incident
from agent.config import AgentConfig
from agent.service.agent import RansomShieldAgent


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def test_agent_detection_result_adapter_compatibility(client: TestClient):
    # Create real Agent Phase 2C DetectionResult
    det_result = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Ransomware",
        confidence=95.8,
        risk_score=94,
        probabilities={"Goodware": 0.042, "Ransomware": 0.958},
        model_version="xgb_ransomware_v2",
        stage=4,
        features={
            "File_Delete_archived": 5.0,
            "File_created": 12.0,
            "File_creation_time_changed": 2.0,
            "Pipe_Created": 1.0,
            "Process_Create": 4.0,
            "Registry_value_set": 3.0,
            "process-related": 8.0,
            "network-related": 15.0,
            "file-related": 25.0,
            "suspicious_path": 1.0,
            "system_executable": 0.0,
            "path_length": 62.0,
            "directory_depth": 5.0,
            "process_name_length": 18.0,
            "process_vs_parent_freq_ratio": 2.5,
            "executable_depth_diff": 2.0,
            "parent_is_system_executable": 1.0,
            "extension_similarity": 1.0,
            "file_name_entropy": 4.82,
        },
        indicators=[
            {"label": "Rapid archive deletion", "feature_name": "File_Delete_archived", "direction": "increases risk", "weight": 98},
            {"label": "Suspicious execution path", "feature_name": "suspicious_path", "direction": "increases risk", "weight": 90},
        ],
        explanation="High-risk ransomware activity detected across all evaluated indicators.",
        event_count=85,
        duration_ms=315.4,
    )

    # 1. Convert via Adapter to Pydantic Schema
    ingest_req = AgentModelAdapter.detection_result_to_ingest_request(det_result, endpoint_id="agent-soc-win11")
    assert ingest_req.endpoint_id == "agent-soc-win11"
    assert ingest_req.features["file_name_entropy"] == 4.82
    assert len(ingest_req.features) == 19
    assert len(ingest_req.indicators) == 2

    # 2. Ingest via Backend REST API
    response = client.post("/api/v1/detections", json=ingest_req.model_dump())
    assert response.status_code == 201
    resp_data = response.json()["data"]
    assert resp_data["prediction"] == "Ransomware"
    assert resp_data["risk_score"] == 94
    assert resp_data["features"]["File_Delete_archived"] == 5.0


def test_agent_alert_adapter_compatibility():
    now = time.time()
    agent_alert = DetectionAlert(
        alert_id="alt-agent-adapter-test",
        timestamp=now,
        endpoint_id="host-win11",
        prediction="Ransomware",
        confidence=91.5,
        risk_score=87,
        severity=AlertSeverity.CRITICAL,
        status=AlertStatus.ACTIVE,
        stage=3,
        model_version="xgb_ransomware_v2",
        window_seconds=10,
        reason="Elevated ransomware activity",
        indicators=[{"feature_name": "suspicious_path", "weight": 90}],
    )

    backend_alert = AgentModelAdapter.alert_to_response(agent_alert)
    assert backend_alert.alert_id == "alt-agent-adapter-test"
    assert backend_alert.severity == "CRITICAL"
    assert backend_alert.status == "ACTIVE"
    assert backend_alert.risk_score == 87


def test_agent_incident_adapter_compatibility():
    now = time.time()
    agent_incident = Incident(
        incident_id="inc-agent-adapter-test",
        created_at=now,
        updated_at=now,
        endpoint_id="host-win11",
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.OPEN,
        alert_ids=["alt-1", "alt-2"],
        detection_count=2,
        first_detection=now - 5.0,
        last_detection=now,
        primary_prediction="Ransomware",
        highest_risk_score=94,
        top_indicators=[{"feature_name": "File_Delete_archived", "weight": 98}],
        summary="Critical security incident on host-win11",
    )

    backend_incident = AgentModelAdapter.incident_to_response(agent_incident)
    assert backend_incident.incident_id == "inc-agent-adapter-test"
    assert backend_incident.severity == "CRITICAL"
    assert backend_incident.status == "OPEN"
    assert backend_incident.detection_count == 2


def test_agent_status_adapter_compatibility():
    cfg = AgentConfig(agent_id="host-status-test")
    agent = RansomShieldAgent(config=cfg)
    agent_status_dict = agent.status()

    backend_status = AgentModelAdapter.agent_status_to_response(agent_status_dict)
    assert backend_status.agent_id == "host-status-test"
    assert backend_status.is_online is False  # not started yet
    assert "sliding_windows" in backend_status.metrics
