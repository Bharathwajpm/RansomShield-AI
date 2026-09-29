"""
RansomShield AI — MongoDB Failure Handling & Error Resilience Tests
Phase 3B: MongoDB Persistence Layer

Verifies that MongoDB outages, unreachable nodes, malformed connection strings,
and database errors degrade gracefully without crashing the server or leaking stack traces.
"""

import asyncio
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings
from backend.database.mongodb import MongoDBManager


def test_invalid_mongodb_uri_handling():
    # Invalid scheme or port
    settings = Settings(
        mongodb_uri="invalid://not-a-mongo-uri:99999",
        mongodb_database="ransomshield_fail_test",
        mongodb_server_selection_timeout_ms=500,
        mongodb_connect_timeout_ms=500,
    )
    mgr = MongoDBManager(settings=settings)
    connected = asyncio.run(mgr.connect())
    assert connected is False
    assert mgr.is_connected is False

    status = asyncio.run(mgr.check_connection())
    assert status["status"] == "disconnected"


def test_unreachable_database_lifespan_does_not_crash_app():
    # Configure unreachable host
    test_settings = Settings(
        app_name="RansomShield Resilience Test",
        mongodb_uri="mongodb://127.0.0.1:27999",  # Unused port
        mongodb_database="ransomshield_unreachable_db",
        mongodb_server_selection_timeout_ms=500,
        mongodb_connect_timeout_ms=500,
    )

    # Server should start without throwing an unhandled exception
    app = create_app(settings=test_settings)
    with TestClient(app) as client:
        # Liveness check should still be alive
        live_resp = client.get("/api/v1/health/live")
        assert live_resp.status_code == 200
        assert live_resp.json()["data"]["status"] == "alive"

        # Readiness check should clearly report database is unreachable
        ready_resp = client.get("/api/v1/health/ready")
        assert ready_resp.status_code == 200
        data = ready_resp.json()["data"]
        assert data["dependencies"]["database"]["status"] == "disconnected"
        assert "unreachable" in data["dependencies"]["database"]["message"]


def test_sanitized_error_response_no_stack_trace_leak():
    test_settings = Settings(
        app_name="RansomShield Sanitization Test",
        mongodb_uri=None,
    )
    app = create_app(settings=test_settings)
    with TestClient(app) as client:
        # Send invalid payload (e.g. unknown types)
        bad_payload = {
            "endpoint_id": "agent-bad",
            "risk_score": "should-be-int-not-string",
        }
        res = client.post("/api/v1/detections", json=bad_payload)
        assert res.status_code == 422
        body = res.json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert "Traceback" not in res.text
