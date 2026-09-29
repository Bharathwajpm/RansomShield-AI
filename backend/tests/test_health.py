"""
RansomShield AI — Backend Health & Readiness Tests
Phase 3A: Backend Foundation
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import create_app
from backend.config.settings import Settings


@pytest.fixture
def client():
    test_settings = Settings(
        app_name="RansomShield AI Test Backend",
        app_version="0.1.0-test",
        environment="testing",
        mongodb_uri=None,
    )
    app = create_app(settings=test_settings)
    with TestClient(app) as test_client:
        yield test_client


def test_root_endpoint(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "RansomShield AI Test Backend"
    assert data["docs"] == "/docs"
    assert data["health"] == "/api/v1/health"


def test_health_endpoint(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["data"]["status"] == "ok"
    assert payload["data"]["service"] == "ransomshield-backend"
    assert payload["data"]["version"] == "0.1.0-test"
    assert "request_id" in payload
    assert response.headers.get("X-Request-ID") is not None


def test_liveness_endpoint(client: TestClient):
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["data"]["status"] == "alive"


def test_readiness_endpoint(client: TestClient):
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["data"]["status"] == "ready"
    assert "dependencies" in payload["data"]
    db_dep = payload["data"]["dependencies"]["database"]
    assert db_dep["status"] == "not_configured"  # Verifies honest unconfigured status
