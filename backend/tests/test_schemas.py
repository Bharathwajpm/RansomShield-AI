"""
RansomShield AI — Pydantic Schemas Validation Tests
Phase 3A: Backend Foundation
"""

import time
import pytest
from pydantic import ValidationError

from backend.schemas.common import ResponseEnvelope, ErrorDetail, HealthResponse, ReadinessResponse
from backend.schemas.agent import AgentRegisterRequest, AgentResponse, AgentStatusResponse
from backend.schemas.alert import AlertResponse, AlertAcknowledgeRequest, AlertResolveRequest
from backend.schemas.incident import (
    IncidentResponse,
    IncidentAcknowledgeRequest,
    IncidentResolveRequest,
    IncidentFalsePositiveRequest,
)
from backend.schemas.detection import DetectionIngestRequest, DetectionResponse
from backend.config.settings import Settings


def test_agent_register_request_validation():
    req = AgentRegisterRequest(
        agent_id="host-win11-01",
        hostname="DESKTOP-SEC01",
        os_name="Windows",
        os_version="10.0.22631",
        agent_version="0.1.0",
        ip_address="192.168.1.50",
        monitored_directories=["C:\\Users\\User\\Documents"],
    )
    assert req.agent_id == "host-win11-01"
    assert req.hostname == "DESKTOP-SEC01"
    assert len(req.monitored_directories) == 1

    # Missing mandatory field should raise ValidationError
    with pytest.raises(ValidationError):
        AgentRegisterRequest(hostname="DESKTOP-SEC01")  # missing agent_id


def test_alert_response_serialization():
    now = time.time()
    alert = AlertResponse(
        alert_id="alt-123456",
        endpoint_id="host-win11-01",
        prediction="Ransomware",
        confidence=94.5,
        risk_score=88,
        severity="CRITICAL",
        status="ACTIVE",
        stage=3,
        reason="Suspicious execution and rapid file modifications",
        indicators=[{"feature_name": "suspicious_path", "weight": 90}],
        created_at=now,
        updated_at=now,
    )
    dumped = alert.model_dump()
    assert dumped["alert_id"] == "alt-123456"
    assert dumped["severity"] == "CRITICAL"
    assert dumped["risk_score"] == 88


def test_incident_response_serialization():
    now = time.time()
    incident = IncidentResponse(
        incident_id="inc-789012",
        endpoint_id="host-win11-01",
        severity="HIGH",
        status="OPEN",
        alert_ids=["alt-1", "alt-2"],
        detection_count=2,
        first_detection=now - 10.0,
        last_detection=now,
        primary_prediction="Ransomware",
        highest_risk_score=85,
        top_indicators=[{"feature_name": "process_name_length", "weight": 95}],
        summary="High risk behavioral activity on host-win11-01",
        created_at=now - 10.0,
        updated_at=now,
    )
    assert incident.detection_count == 2
    assert len(incident.alert_ids) == 2


def test_detection_ingest_request():
    req = DetectionIngestRequest(
        endpoint_id="host-win11-01",
        timestamp=time.time(),
        window_seconds=10,
        prediction="Goodware",
        confidence=98.8,
        risk_score=2,
        probabilities={"Goodware": 0.988, "Ransomware": 0.012},
        features={"file_name_entropy": 3.75},
        event_count=50,
        duration_ms=350.0,
    )
    assert req.prediction == "Goodware"
    assert req.risk_score == 2
    assert req.probabilities["Goodware"] == 0.988


def test_response_envelope_generic():
    envelope = ResponseEnvelope[dict](
        success=True,
        data={"item": "value"},
        meta={"total": 1},
        request_id="req-abc-123",
    )
    dumped = envelope.model_dump()
    assert dumped["success"] is True
    assert dumped["data"]["item"] == "value"
    assert dumped["request_id"] == "req-abc-123"


def test_cors_origins_parsing_from_string():
    settings = Settings(cors_origins="http://localhost:5173,http://localhost:3000, https://soc.company.com")
    assert isinstance(settings.cors_origins, list)
    assert len(settings.cors_origins) == 3
    assert "https://soc.company.com" in settings.cors_origins
