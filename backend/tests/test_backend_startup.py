"""
RansomShield AI — Backend Lifespan, Middleware & Error Handling Tests
Phase 3A: Backend Foundation
"""

import pytest
from fastapi.testclient import TestClient
from fastapi import APIRouter

from backend.main import create_app
from backend.config.settings import Settings


def test_cors_headers():
    test_settings = Settings(
        cors_origins=["http://localhost:5173", "http://soc.ransomshield.local"],
        environment="testing",
    )
    app = create_app(settings=test_settings)
    with TestClient(app) as client:
        # Preflight OPTIONS request
        headers = {
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        response = client.options("/api/v1/health", headers=headers)
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_custom_request_id_propagation():
    app = create_app()
    with TestClient(app) as client:
        custom_id = "custom-trace-id-98765"
        response = client.get("/api/v1/health", headers={"X-Request-ID": custom_id})
        assert response.status_code == 200
        assert response.headers.get("X-Request-ID") == custom_id
        data = response.json()
        assert data["request_id"] == custom_id


def test_validation_error_formatting():
    app = create_app()
    with TestClient(app) as client:
        # Send invalid type for risk_score (string instead of int)
        malformed_payload = {
            "endpoint_id": "test-host",
            "risk_score": "not-an-integer",
            "prediction": "Goodware",
        }
        response = client.post("/api/v1/detections", json=malformed_payload)
        assert response.status_code == 422
        data = response.json()
        assert data["success"] is False
        assert data["error"]["code"] == "VALIDATION_ERROR"
        assert "details" in data["error"]
        assert "request_id" in data


def test_internal_server_error_sanitization():
    # Route that triggers an unhandled exception
    faulty_router = APIRouter()

    @faulty_router.get("/faulty-route")
    async def faulty_route():
        raise ZeroDivisionError("Simulated secret database password leak in exception!")

    app = create_app()
    app.include_router(faulty_router)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/faulty-route")
        assert response.status_code == 500
        data = response.json()
        assert data["success"] is False
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
        assert data["error"]["message"] == "An internal server error occurred."
        # Verify stack trace or internal text is NEVER exposed
        assert "Simulated secret" not in response.text
