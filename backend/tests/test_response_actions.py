"""
RansomShield AI — Response Actions & Governance Backend Test Suite
Phase 4: Defensive Response & Endpoint Containment

Tests REST endpoints, server-side RBAC authorization, two-person approval workflows,
audit trails, and dry-run execution safety.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings


@pytest.fixture
def test_client():
    settings = Settings(
        app_name="RansomShield Response Test",
        environment="testing",
        mongodb_uri=None,
        database_backend="memory",
        jwt_secret_key="test-response-secret-key",
        jwt_algorithm="HS256",
        access_token_expire_minutes=60,
        agent_api_key="test-agent-key-secret",
        response_dry_run=True,
        require_two_person_approval=True,
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        # Get tokens for Admin, Analyst, and Viewer
        admin_tok = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"}).json()["access_token"]
        analyst_tok = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"}).json()["access_token"]
        viewer_tok = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer123"}).json()["access_token"]

        tokens = {
            "admin": admin_tok,
            "analyst": analyst_tok,
            "viewer": viewer_tok,
        }
        yield client, tokens, settings


def test_create_action_admin_allowed(test_client):
    """Confirms ADMIN role can create and execute containment actions."""
    client, tokens, _ = test_client

    payload = {
        "action_type": "TERMINATE_PROCESS",
        "target": "8888",
        "parameters": {"pid": 8888, "process_name": "malicious_ransom.exe"},
        "risk_level": "CRITICAL",
        "dry_run": True,
        "requires_approval": False,
        "auto_execute": True,
    }

    resp = client.post(
        "/api/v1/response/actions",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["action_id"] is not None
    assert data["action_type"] == "TERMINATE_PROCESS"
    assert data["status"] == "SUCCESS"
    assert data["verification_status"] == "VERIFIED_SUCCESS"
    assert data["created_by"] == "admin"


def test_create_action_analyst_allowed(test_client):
    """Confirms ANALYST role can create containment actions."""
    client, tokens, _ = test_client

    payload = {
        "action_type": "QUARANTINE_FILE",
        "target": "C:\\Users\\test\\invoice.exe",
        "parameters": {"file_path": "C:\\Users\\test\\invoice.exe"},
        "risk_level": "HIGH",
        "dry_run": True,
        "requires_approval": False,
        "auto_execute": True,
    }

    resp = client.post(
        "/api/v1/response/actions",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['analyst']}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["action_type"] == "QUARANTINE_FILE"
    assert data["created_by"] == "analyst"


def test_create_action_viewer_forbidden(test_client):
    """Confirms VIEWER role is strictly rejected with HTTP 403 Forbidden."""
    client, tokens, _ = test_client

    payload = {
        "action_type": "TERMINATE_PROCESS",
        "target": "1234",
        "parameters": {"pid": 1234},
    }

    resp = client.post(
        "/api/v1/response/actions",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert resp.status_code == 403
    assert "forbidden" in resp.text.lower()


def test_unauthenticated_request_rejected(test_client):
    """Confirms request without Bearer token is rejected with HTTP 401."""
    client, _, _ = test_client

    resp = client.get("/api/v1/response/actions")
    assert resp.status_code == 401


def test_list_actions_all_roles(test_client):
    """Confirms ADMIN, ANALYST, and VIEWER can all inspect recorded containment actions."""
    client, tokens, _ = test_client

    for role in ["admin", "analyst", "viewer"]:
        resp = client.get(
            "/api/v1/response/actions",
            headers={"Authorization": f"Bearer {tokens[role]}"},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


def test_two_person_approval_workflow(test_client):
    """
    Confirms two-person approval enforcement:
    1. Analyst creates an action requiring approval (network isolation).
    2. Status is set to PENDING.
    3. The SAME analyst attempts to approve it -> Rejected with HTTP 400 (two-person rule).
    4. A DIFFERENT user (Admin) approves it -> Accepted and executed!
    """
    client, tokens, _ = test_client

    # 1. Analyst initiates Network Isolation (high-risk, requires approval)
    payload = {
        "action_type": "ISOLATE_NETWORK",
        "target": "endpoint",
        "parameters": {"reason": "Lateral movement suspected"},
        "risk_level": "CRITICAL",
        "dry_run": True,
        "requires_approval": True,
    }

    create_resp = client.post(
        "/api/v1/response/actions",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['analyst']}"},
    )
    assert create_resp.status_code == 201
    action = create_resp.json()
    action_id = action["action_id"]
    assert action["status"] == "PENDING"
    assert action["requires_approval"] is True

    # 2. Self-approval attempt: Analyst tries to approve their own action -> 400 Bad Request
    self_approve_resp = client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        json={"notes": "Self approval attempt"},
        headers={"Authorization": f"Bearer {tokens['analyst']}"},
    )
    assert self_approve_resp.status_code == 400
    assert "two-person rule" in self_approve_resp.text.lower()

    # 3. Two-person approval: Admin approves the analyst's action -> Success!
    admin_approve_resp = client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        json={"notes": "Approved by SOC Lead"},
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    assert admin_approve_resp.status_code == 200
    approved_action = admin_approve_resp.json()
    assert approved_action["status"] in ("SUCCESS", "APPROVED")
    assert approved_action["approved_by"] == "admin"


def test_cancel_pending_action(test_client):
    """Confirms pending actions can be cancelled by authorized operators."""
    client, tokens, _ = test_client

    payload = {
        "action_type": "ISOLATE_NETWORK",
        "target": "endpoint",
        "requires_approval": True,
    }

    create_resp = client.post(
        "/api/v1/response/actions",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    action_id = create_resp.json()["action_id"]

    cancel_resp = client.post(
        f"/api/v1/response/actions/{action_id}/cancel",
        json={"reason": "False alarm confirmed"},
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "CANCELLED"


def test_retry_action(test_client):
    """Confirms failed or cancelled actions can be retried."""
    client, tokens, _ = test_client

    payload = {
        "action_type": "ISOLATE_NETWORK",
        "target": "endpoint",
        "requires_approval": True,
    }

    create_resp = client.post(
        "/api/v1/response/actions",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    action_id = create_resp.json()["action_id"]

    # Cancel first
    client.post(
        f"/api/v1/response/actions/{action_id}/cancel",
        json={"reason": "Interrupted"},
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )

    # Retry
    retry_resp = client.post(
        f"/api/v1/response/actions/{action_id}/retry",
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    assert retry_resp.status_code == 200
    assert retry_resp.json()["status"] in ("SUCCESS", "APPROVED")


def test_action_and_global_audit_trail(test_client):
    """Confirms that all containment lifecycle events generate immutable audit entries."""
    client, tokens, _ = test_client

    payload = {
        "action_type": "TERMINATE_PROCESS",
        "target": "5555",
        "parameters": {"pid": 5555, "process_name": "crypto_lock.exe"},
        "risk_level": "CRITICAL",
        "dry_run": True,
        "requires_approval": False,
        "auto_execute": True,
    }

    create_resp = client.post(
        "/api/v1/response/actions",
        json=payload,
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    action_id = create_resp.json()["action_id"]

    # Check action-specific audit trail
    audit_resp = client.get(
        f"/api/v1/response/actions/{action_id}/audit",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) >= 2  # CREATED and EXECUTED
    events = [l["event"] for l in logs]
    assert "CREATED" in events
    assert "EXECUTED" in events

    # Check global audit trail
    global_audit = client.get(
        "/api/v1/response/audit",
        headers={"Authorization": f"Bearer {tokens['analyst']}"},
    )
    assert global_audit.status_code == 200
    assert len(global_audit.json()) >= 2
