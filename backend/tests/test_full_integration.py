"""
RansomShield AI — Full End-to-End Integration Test
Phase 3C: Full Backend Integration

Verifies the complete real-time path:
Windows Agent -> Agent Transport (HTTP + X-Agent-Key) -> FastAPI REST ->
Database Persistence -> WebSocket Broadcast -> Authenticated SOC Client.
"""

import pytest
import time
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings
from backend.auth.jwt import create_access_token
from agent.transport.client import AgentNetworkClient
from backend.repositories.factory import (
    get_agent_repository,
    get_alert_repository,
    get_detection_repository,
    get_incident_repository,
)


@pytest.fixture
def e2e_system():
    settings = Settings(
        app_name="RansomShield E2E Integration Backend",
        environment="testing",
        mongodb_uri=None,  # In-memory repository with real models & validation
        jwt_secret_key="integration-secret-key-98765",
        jwt_algorithm="HS256",
        agent_api_key="integration-agent-key-secret",
        enforce_agent_auth_in_test=True,
    )
    app = create_app(settings=settings)
    with TestClient(app) as test_client:
        yield test_client, settings


def test_agent_to_fastapi_to_db_to_websocket_e2e_flow(e2e_system):
    client, settings = e2e_system

    # 1. Generate JWT Token for SOC Analyst
    analyst_token = create_access_token(
        {"sub": "analyst", "role": "ANALYST"},
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    # 2. SOC Analyst connects via authenticated WebSocket
    with client.websocket_connect(f"/api/v1/ws?token={analyst_token}") as ws:
        # 3. Initialize Agent Network Client using the test client as transport
        agent_client = AgentNetworkClient(
            base_url="http://testserver",
            api_key=settings.agent_api_key,
            client=client,
        )

        # 4. Agent registers with backend
        reg_payload = {
            "agent_id": "endpoint-prod-win11",
            "hostname": "WORKSTATION-01",
            "os_name": "Windows",
            "os_version": "11.0.22631",
            "architecture": "x86_64",
            "agent_version": "2.0.0",
            "ip_addresses": ["192.168.1.105"],
            "mac_addresses": ["00:15:5D:01:02:03"],
            "monitoring_paths": ["C:\\Users\\SOC\\Documents"],
            "features_enabled": ["process", "filesystem", "network"],
        }
        ok, status_code, reg_resp = agent_client.register(reg_payload)
        assert ok is True
        assert status_code == 201
        assert reg_resp["agent_id"] == "endpoint-prod-win11"

        # WebSocket receives agent.status_changed event
        ws_reg = ws.receive_json()
        assert ws_reg["type"] == "agent.status_changed"
        assert ws_reg["data"]["agent_id"] == "endpoint-prod-win11"

        # 5. Agent sends periodic heartbeat
        ok_hb, hb_code, hb_resp = agent_client.send_heartbeat("endpoint-prod-win11")
        assert ok_hb is True
        assert hb_code == 200

        ws_hb = ws.receive_json()
        assert ws_hb["type"] == "agent.status_changed"
        assert ws_hb["data"]["agent_id"] == "endpoint-prod-win11"

        # 6. Agent sends Model V2 DetectionResult
        det_payload = {
            "endpoint_id": "endpoint-prod-win11",
            "prediction": "Ransomware",
            "confidence": 99.4,
            "risk_score": 96.0,
            "stage": 6,
            "features": {
                "File_created": 45,
                "file-related": 88,
                "suspicious_path": 1,
            },
            "indicators": [
                {"label": "High mass file entropy writes", "feature_name": "file_name_entropy", "weight": 95},
                {"label": "Suspicious execution from AppData", "feature_name": "suspicious_path", "weight": 85},
            ],
            "metadata": {
                "process_name": "lockbit_sim.exe",
                "pid": 4892,
            },
        }
        ok_det, det_code, det_resp = agent_client.send_detection(det_payload)
        assert ok_det is True
        assert det_code == 201

        ws_det = ws.receive_json()
        assert ws_det["type"] == "detection.created"
        assert ws_det["data"]["prediction"] == "Ransomware"
        assert ws_det["data"]["risk_score"] == 96.0
        assert ws_det["data"]["endpoint_id"] == "endpoint-prod-win11"

        # 7. Agent sends correlated Alert
        alert_payload = {
            "alert_id": "alt_e2e_001",
            "endpoint_id": "endpoint-prod-win11",
            "prediction": "Ransomware",
            "confidence": 99.4,
            "risk_score": 96,
            "severity": "CRITICAL",
            "status": "ACTIVE",
            "stage": 6,
            "reason": "Mass file encryption behavior detected across monitored directory",
            "indicators": [{"label": "High entropy writes", "weight": 95}],
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        ok_alt, alt_code, alt_resp = agent_client.send_alert(alert_payload)
        assert ok_alt is True
        assert alt_code == 201

        ws_alt = ws.receive_json()
        assert ws_alt["type"] == "alert.created"
        assert ws_alt["data"]["alert_id"] == "alt_e2e_001"
        assert ws_alt["data"]["severity"] == "CRITICAL"

        # 8. SOC Analyst acknowledges the alert via protected API using JWT Bearer token
        ack_resp = client.patch(
            "/api/v1/alerts/alt_e2e_001/acknowledge",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert ack_resp.status_code == 200
        assert ack_resp.json()["data"]["status"] == "ACKNOWLEDGED"

        # Live WebSocket receives alert.updated event
        ws_upd = ws.receive_json()
        assert ws_upd["type"] == "alert.updated"
        assert ws_upd["data"]["alert_id"] == "alt_e2e_001"
        assert ws_upd["data"]["status"] == "ACKNOWLEDGED"

        # 9. Verify database repository state
        agent_repo = get_agent_repository()
        alert_repo = get_alert_repository()

        # Both records persisted reliably
        saved_agent = client.get(
            "/api/v1/agents/endpoint-prod-win11",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert saved_agent.status_code == 200
        assert saved_agent.json()["data"]["agent_id"] == "endpoint-prod-win11"

        saved_alert = client.get(
            "/api/v1/alerts/alt_e2e_001",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert saved_alert.status_code == 200
        assert saved_alert.json()["data"]["status"] == "ACKNOWLEDGED"

        agent_client.close()
