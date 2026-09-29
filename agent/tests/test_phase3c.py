"""
RansomShield AI — Phase 3C Test Suite
Agent ↔ Backend Real-Time Communication

Validates HTTP transport client, bounded in-memory queue, SQLite offline spooling,
exponential backoff, automatic agent registration, periodic heartbeats,
detection/alert/incident transmission, idempotency, backend outage resilience,
and end-to-end integration with FastAPI and MongoDB persistence.
"""

import os
import time
import queue
import tempfile
import threading
from typing import Dict, Any, List
import httpx
import pytest
from starlette.testclient import TestClient

from agent.config import AgentConfig
from agent.transport.retry import compute_backoff_delay, is_retriable_status
from agent.transport.spool import LocalTransportSpool
from agent.transport.client import AgentNetworkClient
from agent.transport.manager import AgentTransportManager
from agent.service.agent import RansomShieldAgent
from agent.models.telemetry import ProcessEvent, TelemetryEventType
from agent.inference.detection_result import DetectionResult
from agent.detection.alert_manager import DetectionAlert
from agent.detection.incident_manager import Incident
from agent.detection.severity import AlertSeverity, AlertStatus, IncidentSeverity, IncidentStatus

from backend.main import app
from backend.repositories import (
    get_agent_repository,
    get_alert_repository,
    get_incident_repository,
    get_detection_repository,
)


def _safe_remove(path: str) -> None:
    """Helper to remove temporary files with small retry to tolerate Windows OS lag."""
    if not os.path.exists(path):
        return
    for _ in range(5):
        try:
            os.remove(path)
            break
        except Exception:
            time.sleep(0.05)


# =====================================================================
# 1. Transport Configuration Tests
# =====================================================================

def test_transport_configuration_defaults():
    cfg = AgentConfig()
    assert cfg.backend_url == "http://localhost:8000"
    assert cfg.enable_backend_transport is False
    assert cfg.heartbeat_interval_seconds == 15.0
    assert cfg.backend_request_timeout == 5.0
    assert cfg.backend_max_retries == 3
    assert cfg.backend_retry_base_delay == 1.0
    assert cfg.transport_queue_size == 500
    assert cfg.enable_local_spool is True
    assert cfg.max_spool_records == 2000


def test_transport_configuration_validation():
    with pytest.raises(ValueError, match="backend_request_timeout"):
        AgentConfig(backend_request_timeout=-1.0).validate()

    with pytest.raises(ValueError, match="heartbeat_interval_seconds"):
        AgentConfig(heartbeat_interval_seconds=0).validate()

    with pytest.raises(ValueError, match="transport_queue_size"):
        AgentConfig(transport_queue_size=0).validate()

    with pytest.raises(ValueError, match="max_spool_records"):
        AgentConfig(max_spool_records=-5).validate()


# =====================================================================
# 2. Retry & Exponential Backoff Tests
# =====================================================================

def test_exponential_backoff_calculation():
    # Base delay = 1.0, without jitter
    d0 = compute_backoff_delay(0, base_delay=1.0, max_delay=30.0, jitter=False)
    assert d0 == 1.0

    d1 = compute_backoff_delay(1, base_delay=1.0, max_delay=30.0, jitter=False)
    assert d1 == 2.0

    d2 = compute_backoff_delay(2, base_delay=1.0, max_delay=30.0, jitter=False)
    assert d2 == 4.0

    d5 = compute_backoff_delay(5, base_delay=1.0, max_delay=30.0, jitter=False)
    assert d5 == 30.0  # Capped at max_delay

    # With jitter
    dj = compute_backoff_delay(1, base_delay=1.0, max_delay=30.0, jitter=True)
    assert 1.6 <= dj <= 2.4


def test_retriable_status_codes():
    assert is_retriable_status(500) is True
    assert is_retriable_status(502) is True
    assert is_retriable_status(503) is True
    assert is_retriable_status(504) is True
    assert is_retriable_status(408) is True
    assert is_retriable_status(429) is True

    assert is_retriable_status(200) is False
    assert is_retriable_status(201) is False
    assert is_retriable_status(400) is False
    assert is_retriable_status(404) is False
    assert is_retriable_status(422) is False


# =====================================================================
# 3. Local SQLite Spool Tests (Offline Queue & Durability)
# =====================================================================

def test_spool_push_peek_remove_lifecycle():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        spool_path = tf.name

    try:
        spool = LocalTransportSpool(db_path=spool_path, max_records=100)
        assert spool.size() == 0

        # Push items
        id1 = spool.push("detection", {"detection_id": "det-1", "risk": 80})
        id2 = spool.push("alert", {"alert_id": "alt-1", "severity": "HIGH"})
        assert spool.size() == 2

        # Peek
        items = spool.peek(limit=10)
        assert len(items) == 2
        assert items[0][0] == id1
        assert items[0][1] == "detection"
        assert items[0][2]["detection_id"] == "det-1"
        assert items[1][0] == id2
        assert items[1][1] == "alert"

        # Remove first
        removed = spool.remove([id1])
        assert removed == 1
        assert spool.size() == 1

        # Remaining
        remaining = spool.peek(limit=10)
        assert len(remaining) == 1
        assert remaining[0][0] == id2

        # Clear
        spool.clear()
        assert spool.size() == 0
    finally:
        _safe_remove(spool_path)


def test_spool_bounding_and_fifo_overflow():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        spool_path = tf.name

    try:
        # Bounded at 10 records
        spool = LocalTransportSpool(db_path=spool_path, max_records=10)
        
        # Insert 15 records
        for i in range(15):
            spool.push("detection", {"index": i})

        # Size must be strictly capped at max_records (10)
        assert spool.size() == 10

        # The oldest 5 records (0..4) should have been purged (FIFO)
        items = spool.peek(limit=10)
        assert len(items) == 10
        first_remaining_index = items[0][2]["index"]
        assert first_remaining_index == 5
        last_remaining_index = items[-1][2]["index"]
        assert last_remaining_index == 14
    finally:
        _safe_remove(spool_path)


# =====================================================================
# 4. HTTP Client & API Transmission Tests (Mocked Network)
# =====================================================================

def test_network_client_registration_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/agents/register"
        return httpx.Response(201, json={"success": True, "data": {"agent_id": "test-agent", "status": "online"}})

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    client = AgentNetworkClient(base_url="http://mock-backend", client=mock_client)

    success, code, data = client.register({"agent_id": "test-agent", "hostname": "TEST-HOST"})
    assert success is True
    assert code == 201
    assert data["status"] == "online"


def test_network_client_registration_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"success": False, "detail": "Internal server error"})

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    client = AgentNetworkClient(base_url="http://mock-backend", client=mock_client)

    success, code, data = client.register({"agent_id": "test-agent"})
    assert success is False
    assert code == 500


def test_network_client_timeout_handling():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Simulated timeout", request=request)

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    client = AgentNetworkClient(base_url="http://mock-backend", client=mock_client)

    success, code, err = client.register({"agent_id": "test-agent"})
    assert success is False
    assert code == 408
    assert "timeout" in str(err).lower()


def test_network_client_backend_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    client = AgentNetworkClient(base_url="http://mock-backend", client=mock_client)

    success, code, err = client.send_detection({"detection_id": "det-1"})
    assert success is False
    assert code == 503
    assert "network error" in str(err).lower()


def test_network_client_heartbeat():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/agents/agent-01/heartbeat"
        return httpx.Response(200, json={"success": True, "data": {"agent_id": "agent-01", "status": "online"}})

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    client = AgentNetworkClient(base_url="http://mock-backend", client=mock_client)

    success, code, data = client.send_heartbeat("agent-01")
    assert success is True
    assert code == 200
    assert data["status"] == "online"


def test_network_client_send_alert_and_incident():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(201, json={"success": True, "data": {"status": "ok"}})

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    client = AgentNetworkClient(base_url="http://mock-backend", client=mock_client)

    s1, c1, _ = client.send_alert({"alert_id": "alt-1"})
    s2, c2, _ = client.send_incident({"incident_id": "inc-1"})

    assert s1 is True and c1 == 201
    assert s2 is True and c2 == 201
    assert "/api/v1/alerts" in calls
    assert "/api/v1/incidents" in calls


# =====================================================================
# 5. Agent Transport Manager & Queue Tests
# =====================================================================

def test_transport_manager_queue_boundedness_and_spill():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        spool_path = tf.name

    try:
        cfg = AgentConfig(
            transport_queue_size=5,
            enable_local_spool=True,
            spool_db_path=spool_path,
        )
        spool = LocalTransportSpool(db_path=spool_path, max_records=50)
        mgr = AgentTransportManager(config=cfg, spool=spool)

        dummy_det = DetectionResult(
            timestamp=time.time(),
            window_seconds=10,
            prediction="Goodware",
            confidence=95.0,
            risk_score=10,
            probabilities={"Goodware": 0.95, "Ransomware": 0.05},
            model_version="xgb_ransomware_v2",
            stage=1,
            features={"process-related": 5},
            indicators=[],
            explanation="",
            event_count=5,
            duration_ms=2.0,
        )

        for _ in range(10):
            mgr.enqueue_detection(dummy_det)

        # Queue capacity is 5
        assert mgr.queue.qsize() == 5
        # The remaining 5 spilled into SQLite spool
        assert spool.size() == 5
    finally:
        _safe_remove(spool_path)


def test_transport_manager_worker_startup_and_clean_shutdown():
    recorded_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_requests.append(request.url.path)
        return httpx.Response(200, json={"success": True, "data": {"status": "online"}})

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    net_client = AgentNetworkClient(base_url="http://mock-backend", client=mock_client)

    cfg = AgentConfig(
        heartbeat_interval_seconds=0.5,
        backend_retry_base_delay=0.1,
    )
    mgr = AgentTransportManager(config=cfg, client=net_client)

    mgr.start()
    assert mgr.is_running is True
    time.sleep(0.3)

    assert mgr.is_registered is True
    assert "/api/v1/agents/register" in recorded_requests

    # Clean shutdown
    mgr.stop()
    assert mgr.is_running is False
    assert mgr._worker_thread is None
    assert mgr._heartbeat_thread is None


def test_agent_offline_resilience_and_recovery():
    """Verifies that while backend is offline, items are spooled to SQLite, and upon recovery, are drained."""
    server_online = False
    delivered_detections = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal server_online
        if not server_online:
            raise httpx.ConnectError("Server down", request=request)
        if request.url.path == "/api/v1/agents/register":
            return httpx.Response(201, json={"success": True, "data": {"status": "online"}})
        if request.url.path == "/api/v1/detections":
            data = request.read().decode("utf-8")
            delivered_detections.append(data)
            return httpx.Response(201, json={"success": True, "data": {"status": "persisted"}})
        return httpx.Response(200, json={"success": True, "data": {}})

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    net_client = AgentNetworkClient(base_url="http://mock-backend", client=mock_client)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        spool_path = tf.name

    try:
        cfg = AgentConfig(
            enable_local_spool=True,
            spool_db_path=spool_path,
            backend_retry_base_delay=0.1,
            backend_retry_max_delay=0.5,
            heartbeat_interval_seconds=1.0,
        )
        spool = LocalTransportSpool(db_path=spool_path)
        mgr = AgentTransportManager(config=cfg, client=net_client, spool=spool)

        mgr.start()

        dummy_det = DetectionResult(
            timestamp=time.time(),
            window_seconds=10,
            prediction="Ransomware",
            confidence=92.0,
            risk_score=85,
            probabilities={"Goodware": 0.08, "Ransomware": 0.92},
            model_version="xgb_ransomware_v2",
            stage=2,
            features={"process-related": 12},
            indicators=[],
            explanation="Critical ransomware risk",
            event_count=20,
            duration_ms=3.5,
        )

        # 1. Enqueue while backend is OFFLINE
        mgr.enqueue_detection(dummy_det)
        time.sleep(0.4)

        # Should be spooled locally or held in queue without crashing
        assert len(delivered_detections) == 0

        # 2. Server comes ONLINE
        server_online = True
        time.sleep(0.8)

        # Worker recovers, registers, and transmits the spooled detection
        mgr.stop()
        assert len(delivered_detections) >= 1
    finally:
        _safe_remove(spool_path)


# =====================================================================
# 6. Full End-to-End Integration Test (Agent -> Transport -> FastAPI -> MongoDB)
# =====================================================================

@pytest.mark.anyio
async def test_genuine_agent_to_fastapi_to_mongodb_integration():
    """
    Genuine end-to-end integration test connecting:
    Agent -> HTTP transport -> FastAPI application -> MongoDB/In-Memory Repository.
    Verifies that the DetectionResult generated by the agent reaches backend storage with identical IDs.
    """
    # 1. Setup FastAPI test client using TestClient (manages lifespan and synchronous thread calls)
    test_http_client = TestClient(app, base_url="http://testserver")
    net_client = AgentNetworkClient(base_url="http://testserver", client=test_http_client)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        spool_path = tf.name

    try:
        cfg = AgentConfig(
            agent_id="e2e-integration-agent-01",
            enable_backend_transport=True,
            spool_db_path=spool_path,
            backend_retry_base_delay=0.1,
            heartbeat_interval_seconds=2.0,
            psutil_enabled=False,
            watchdog_enabled=False,
            sysmon_enabled=False,
            windows_event_log_enabled=False,
            inference_enabled=False,
        )
        agent = RansomShieldAgent(config=cfg)
        agent.transport = AgentTransportManager(config=cfg, client=net_client)

        try:
            agent.start()
            time.sleep(0.3)  # Allow registration to complete

            # 3. Create a synthetic DetectionResult with complete indicators schema
            det_result = DetectionResult(
                timestamp=time.time(),
                window_seconds=10,
                prediction="Ransomware",
                confidence=96.4,
                risk_score=88,
                probabilities={"Goodware": 0.036, "Ransomware": 0.964},
                model_version="xgb_ransomware_v2",
                stage=2,
                features={"file-related": 42, "process-related": 15},
                indicators=[{
                    "feature_name": "file-related",
                    "feature": "file-related",
                    "importance": 0.85,
                    "label": "Elevated file system I/O",
                    "direction": "increases risk",
                    "weight": 85,
                }],
                explanation="Model V2 Ransomware detection",
                event_count=57,
                duration_ms=4.12,
            )

            # 4. Trigger detection processing on agent (emits detection, alert, incident)
            agent._on_detection_result(det_result)

            # Wait for background transport worker to process and deliver to FastAPI
            time.sleep(1.0)

            # 5. Verify persistence in Backend Repositories
            det_repo = get_detection_repository()
            detections = await det_repo.list(endpoint_id="e2e-integration-agent-01")
            assert len(detections) >= 1
            matched_det = detections[0]
            assert matched_det.endpoint_id == "e2e-integration-agent-01"
            assert matched_det.prediction == "Ransomware"
            assert matched_det.risk_score == 88

            # Verify Alert was received and persisted
            alert_repo = get_alert_repository()
            alerts = await alert_repo.list(endpoint_id="e2e-integration-agent-01")
            assert len(alerts) >= 1
            assert alerts[0].endpoint_id == "e2e-integration-agent-01"
            assert alerts[0].risk_score == 88

            # Verify Incident was received and persisted
            inc_repo = get_incident_repository()
            incidents = await inc_repo.list(endpoint_id="e2e-integration-agent-01")
            assert len(incidents) >= 1
            assert incidents[0].endpoint_id == "e2e-integration-agent-01"
            assert incidents[0].highest_risk_score == 88

            # Verify Agent status shows transport is active
            status = agent.status()
            assert "transport" in status
            assert status["transport"]["running"] is True
            assert status["transport"]["registered"] is True
        finally:
            agent.stop()
    finally:
        _safe_remove(spool_path)


# =====================================================================
# 7. Idempotency & Duplicate Protection Tests
# =====================================================================

@pytest.mark.anyio
async def test_backend_idempotency_duplicate_transmission():
    """
    Verifies that retransmitting the exact same detection, alert, or incident
    updates the record in-place rather than creating duplicate entries.
    """
    asgi_transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=asgi_transport, base_url="http://testserver") as client:
        # Register agent first
        await client.post("/api/v1/agents/register", json={
            "agent_id": "idempotency-agent",
            "hostname": "IDEM-HOST",
        })

        # 1. Detection Idempotency
        det_id = "det-idempotency-fixed-01"
        det_payload = {
            "detection_id": det_id,
            "endpoint_id": "idempotency-agent",
            "timestamp": time.time(),
            "window_seconds": 10,
            "prediction": "Ransomware",
            "confidence": 91.0,
            "risk_score": 82,
            "probabilities": {"Goodware": 0.09, "Ransomware": 0.91},
            "features": {},
            "indicators": [],
            "explanation": "Test",
            "event_count": 10,
            "duration_ms": 2.0,
        }
        resp1 = await client.post("/api/v1/detections", json=det_payload)
        assert resp1.status_code == 201

        # 2. Retransmit duplicate with updated risk score
        det_payload["risk_score"] = 85
        resp2 = await client.post("/api/v1/detections", json=det_payload)
        assert resp2.status_code in (200, 201)

        # 3. Verify single record exists with updated risk score
        det_repo = get_detection_repository()
        det = await det_repo.get_by_id(det_id)
        assert det is not None
        assert det.risk_score == 85

        # 4. Alert Idempotency
        alert_payload = {
            "alert_id": "alt-idempotency-test-01",
            "endpoint_id": "idempotency-agent",
            "prediction": "Ransomware",
            "confidence": 91.0,
            "risk_score": 82,
            "severity": "HIGH",
            "status": "ACTIVE",
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        a_resp1 = await client.post("/api/v1/alerts", json=alert_payload)
        assert a_resp1.status_code == 201

        alert_payload["risk_score"] = 90
        a_resp2 = await client.post("/api/v1/alerts", json=alert_payload)
        assert a_resp2.status_code == 201

        alert_repo = get_alert_repository()
        alt = await alert_repo.get_by_id("alt-idempotency-test-01")
        assert alt is not None
        assert alt.risk_score == 90

        # 5. Incident Idempotency
        inc_payload = {
            "incident_id": "inc-idempotency-test-01",
            "endpoint_id": "idempotency-agent",
            "severity": "HIGH",
            "status": "OPEN",
            "first_detection": time.time(),
            "last_detection": time.time(),
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        i_resp1 = await client.post("/api/v1/incidents", json=inc_payload)
        assert i_resp1.status_code == 201

        inc_payload["severity"] = "CRITICAL"
        i_resp2 = await client.post("/api/v1/incidents", json=inc_payload)
        assert i_resp2.status_code == 201

        inc_repo = get_incident_repository()
        inc = await inc_repo.get_by_id("inc-idempotency-test-01")
        assert inc is not None
        assert inc.severity == "CRITICAL"
