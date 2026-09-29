"""
RansomShield AI — End-to-End Response & Containment Integration Test
Phase 4: Defensive Response & Endpoint Containment

Verifies the complete end-to-end defensive containment workflow:
Threat Detection -> Policy Recommendation -> Action Creation -> Multi-Person Approval
-> Dry-Run Containment Execution -> Cryptographic Verification -> Immutable Audit Trail
-> Live WebSocket Broadcasting.

All operations in this test enforce bounded timeouts and dry-run safety.
"""

import os
import tempfile
import concurrent.futures
import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings
from backend.auth.jwt import create_access_token
from agent.detection.severity import AlertSeverity
from agent.response.action_policy import ResponsePolicyEngine


def receive_json_with_timeout(ws, timeout: float = 5.0) -> dict:
    """
    Bounded timeout wrapper for Starlette WebSocket receive_json.
    Guarantees tests will never hang if an expected event is missing or delayed.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(ws.receive_json)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"WebSocket receive_json timed out after {timeout:.1f}s waiting for event")


@pytest.fixture
def e2e_client():
    settings = Settings(
        app_name="RansomShield E2E Response Test",
        environment="testing",
        mongodb_uri=None,
        database_backend="memory",
        jwt_secret_key="test-e2e-response-secret-123",
        jwt_algorithm="HS256",
        access_token_expire_minutes=60,
        agent_api_key="test-agent-key-secret",
        response_dry_run=True,
        require_two_person_approval=True,
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        # Generate tokens for analyst and admin
        analyst_tok = create_access_token(
            {"sub": "analyst", "role": "ANALYST"},
            secret_key=settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )
        admin_tok = create_access_token(
            {"sub": "admin", "role": "ADMIN"},
            secret_key=settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )
        yield client, analyst_tok, admin_tok, settings


def test_e2e_response_containment_pipeline(e2e_client):
    """
    Validates complete end-to-end response lifecycle from detection policy
    to multi-person approval, dry-run execution, verification, and audit logging.
    """
    client, analyst_tok, admin_tok, settings = e2e_client

    # Create temporary threat sample for safe quarantine dry-run verification
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(b"SAMPLE_TEST_PAYLOAD_FOR_DEFENSIVE_CONTAINMENT")
        temp_threat_file = tf.name

    try:
        # 1. Simulate Threat Detection -> Policy Engine evaluates recommended containment
        policy = ResponsePolicyEngine(require_approval_for_isolation=True, dry_run_default=True)
        recommendations = policy.evaluate_alert(
            severity=AlertSeverity.CRITICAL,
            pid=9184,
            process_name="invoice_update.exe",
            file_path=temp_threat_file,
            sha256="d5a6b7c8e9f0123456789abcdef0123456789abcdef0123456789abcdef01234",
        )
        assert len(recommendations) >= 3

        # 2. Connect live WebSocket feed as SOC analyst
        with client.websocket_connect(f"/api/v1/ws?token={analyst_tok}") as ws:

            # 3. Analyst executes Process Termination action
            proc_payload = {
                "action_type": "TERMINATE_PROCESS",
                "target": "9184",
                "parameters": {"pid": 9184, "process_name": "invoice_update.exe"},
                "risk_level": "HIGH",
                "dry_run": True,
                "requires_approval": False,
                "auto_execute": True,
            }
            proc_resp = client.post(
                "/api/v1/response/actions",
                json=proc_payload,
                headers={"Authorization": f"Bearer {analyst_tok}"},
            )
            assert proc_resp.status_code == 201, f"Process termination creation failed: {proc_resp.text}"
            proc_action = proc_resp.json()
            assert proc_action["status"] == "SUCCESS", f"Expected SUCCESS, got {proc_action['status']}"
            assert proc_action["verification_status"] == "VERIFIED_SUCCESS"

            # WebSocket receives: response.created and response.updated
            ws_proc_created = receive_json_with_timeout(ws, timeout=5.0)
            assert ws_proc_created["type"] == "response.created"
            ws_proc_updated = receive_json_with_timeout(ws, timeout=5.0)
            assert ws_proc_updated["type"] == "response.updated"
            assert ws_proc_updated["data"]["action_id"] == proc_action["action_id"]

            # 4. Analyst executes File Quarantine action
            quar_payload = {
                "action_type": "QUARANTINE_FILE",
                "target": temp_threat_file,
                "parameters": {"file_path": temp_threat_file},
                "risk_level": "HIGH",
                "dry_run": True,
                "requires_approval": False,
                "auto_execute": True,
            }
            quar_resp = client.post(
                "/api/v1/response/actions",
                json=quar_payload,
                headers={"Authorization": f"Bearer {analyst_tok}"},
            )
            assert quar_resp.status_code == 201, f"Quarantine creation failed: {quar_resp.text}"
            quar_action = quar_resp.json()
            assert quar_action["status"] == "SUCCESS", f"Expected SUCCESS for dry-run quarantine, got {quar_action['status']}"
            assert quar_action["verification_status"] == "VERIFIED_SUCCESS"

            # WebSocket receives: response.created and response.updated for quarantine
            ws_quar_created = receive_json_with_timeout(ws, timeout=5.0)
            assert ws_quar_created["type"] == "response.created"
            ws_quar_updated = receive_json_with_timeout(ws, timeout=5.0)
            assert ws_quar_updated["type"] == "response.updated"
            assert ws_quar_updated["data"]["action_id"] == quar_action["action_id"]

            # 5. Analyst requests Network Isolation (High-risk action requiring two-person approval)
            iso_payload = {
                "action_type": "ISOLATE_NETWORK",
                "target": "endpoint",
                "parameters": {"backend_host": "127.0.0.1", "backend_port": 8000},
                "risk_level": "CRITICAL",
                "dry_run": True,
                "requires_approval": True,
            }
            iso_resp = client.post(
                "/api/v1/response/actions",
                json=iso_payload,
                headers={"Authorization": f"Bearer {analyst_tok}"},
            )
            assert iso_resp.status_code == 201
            iso_action = iso_resp.json()
            iso_id = iso_action["action_id"]
            assert iso_action["status"] == "PENDING"
            assert iso_action["requires_approval"] is True

            # WebSocket receives: response.created (in PENDING state)
            ws_iso_created = receive_json_with_timeout(ws, timeout=5.0)
            assert ws_iso_created["type"] == "response.created"
            assert ws_iso_created["data"]["action_id"] == iso_id

            # 6. Admin approves Network Isolation (satisfies two-person rule)
            approve_resp = client.post(
                f"/api/v1/response/actions/{iso_id}/approve",
                json={"notes": "Approved for endpoint isolation due to active critical infection."},
                headers={"Authorization": f"Bearer {admin_tok}"},
            )
            assert approve_resp.status_code == 200, f"Approval failed: {approve_resp.text}"
            approved_iso = approve_resp.json()
            assert approved_iso["status"] == "SUCCESS"
            assert approved_iso["verification_status"] == "VERIFIED_SUCCESS"
            assert approved_iso["approved_by"] == "admin"

            # WebSocket receives: response.updated upon approval execution
            ws_iso_updated = receive_json_with_timeout(ws, timeout=5.0)
            assert ws_iso_updated["type"] == "response.updated"
            assert ws_iso_updated["data"]["action_id"] == iso_id
            assert ws_iso_updated["data"]["status"] == "SUCCESS"

            # 7. Verify all actions recorded in repository
            list_resp = client.get(
                "/api/v1/response/actions",
                headers={"Authorization": f"Bearer {analyst_tok}"},
            )
            assert list_resp.status_code == 200
            actions = list_resp.json()
            assert len(actions) >= 3

            # 8. Verify comprehensive audit trail
            audit_resp = client.get(
                "/api/v1/response/audit",
                headers={"Authorization": f"Bearer {analyst_tok}"},
            )
            assert audit_resp.status_code == 200
            audit_logs = audit_resp.json()
            assert len(audit_logs) >= 5
            events = [l["event"] for l in audit_logs]
            assert "CREATED" in events
            assert "APPROVED" in events
            assert "EXECUTED" in events

    finally:
        if os.path.exists(temp_threat_file):
            try:
                os.remove(temp_threat_file)
            except Exception:
                pass
