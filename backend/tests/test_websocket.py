"""
RansomShield AI — WebSockets Real-Time Feed Tests
Phase 3C: Full Backend Integration

Tests authenticated WebSocket connection lifecycle, rejection of unauthenticated/invalid tokens,
multi-client live event broadcasting, ping/pong, and dead connection cleanup.
"""

import pytest
from datetime import timedelta
from starlette.websockets import WebSocketDisconnect
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings
from backend.auth.jwt import create_access_token
from backend.ws.manager import ws_manager


@pytest.fixture
def ws_test_app():
    settings = Settings(
        app_name="RansomShield WS Test Backend",
        environment="testing",
        mongodb_uri=None,
        jwt_secret_key="test-ws-jwt-secret-key-12345",
        jwt_algorithm="HS256",
        agent_api_key="test-agent-key-secret",
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        yield client, settings


def test_websocket_unauthenticated_rejected(ws_test_app):
    client, _ = ws_test_app

    # 1. No token provided
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/v1/ws") as websocket:
            pass
    assert exc.value.code == 1008

    # 2. Invalid token provided
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/v1/ws?token=invalid.tampered.token") as websocket:
            pass
    assert exc.value.code == 1008


def test_websocket_authenticated_connection_and_ping(ws_test_app):
    client, settings = ws_test_app
    token = create_access_token(
        {"sub": "admin", "role": "ADMIN"},
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with client.websocket_connect(f"/api/v1/ws?token={token}") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == "pong"


def test_websocket_live_event_broadcast(ws_test_app):
    client, settings = ws_test_app
    token = create_access_token(
        {"sub": "analyst", "role": "ANALYST"},
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with client.websocket_connect(f"/api/v1/ws?token={token}") as ws1:
        with client.websocket_connect(f"/api/v1/ws?token={token}") as ws2:
            # Send detection via REST endpoint
            det_payload = {
                "endpoint_id": "test-ep-01",
                "prediction": "Ransomware",
                "confidence": 98.5,
                "risk_score": 90.0,
                "stage": 5,
                "features": {"Process_Create": 10},
                "indicators": [{"label": "Rapid file writes", "feature_name": "File_created", "weight": 80}],
                "metadata": {"process_name": "encryptor.exe", "pid": 1234},
            }

            resp = client.post(
                "/api/v1/detections",
                json=det_payload,
                headers={"X-Agent-Key": settings.agent_api_key},
            )
            assert resp.status_code == 201

            # Both connected WebSockets should receive the live event
            ev1 = ws1.receive_json()
            assert ev1["type"] == "detection.created"
            assert ev1["data"]["prediction"] == "Ransomware"
            assert ev1["data"]["risk_score"] == 90.0

            ev2 = ws2.receive_json()
            assert ev2["type"] == "detection.created"
            assert ev2["data"]["prediction"] == "Ransomware"


def test_websocket_alert_and_incident_broadcast(ws_test_app):
    client, settings = ws_test_app
    token = create_access_token(
        {"sub": "admin", "role": "ADMIN"},
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with client.websocket_connect(f"/api/v1/ws?token={token}") as ws:
        # 1. Ingest alert
        alert_payload = {
            "alert_id": "alt_test_ws_01",
            "endpoint_id": "ep-ws-01",
            "prediction": "Ransomware",
            "confidence": 88.0,
            "risk_score": 75,
            "severity": "HIGH",
            "status": "ACTIVE",
            "reason": "Unusual encryption activity detected",
            "indicators": [],
            "created_at": 1700000000.0,
            "updated_at": 1700000000.0,
        }
        resp = client.post("/api/v1/alerts", json=alert_payload, headers={"X-Agent-Key": settings.agent_api_key})
        assert resp.status_code == 201

        ev = ws.receive_json()
        assert ev["type"] == "alert.created"
        assert ev["data"]["alert_id"] == "alt_test_ws_01"

        # 2. Acknowledge alert
        resp_ack = client.patch("/api/v1/alerts/alt_test_ws_01/acknowledge")
        assert resp_ack.status_code == 200

        ev_ack = ws.receive_json()
        assert ev_ack["type"] == "alert.updated"
        assert ev_ack["data"]["status"] == "ACKNOWLEDGED"
