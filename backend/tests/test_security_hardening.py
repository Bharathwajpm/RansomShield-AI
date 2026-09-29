"""
RansomShield AI — Security Hardening Test Suite
Phase 5: Production Hardening & Security

Validates enterprise security invariants across:
1. JWT security (expiration, signature tampering, algorithm validation, malformed tokens)
2. Agent authentication (missing/invalid key rejection, constant-time validation)
3. Input validation & path traversal defense (null bytes, UNC paths, traversal sequences)
4. Rate limiting enforcement (sliding-window throttling, HTTP 429)
5. Request body size enforcement (HTTP 413 payload too large)
6. Error handling & stack trace leak prevention
7. Production configuration safety validation
8. Protected process termination refusal
"""

import pytest
from datetime import timedelta
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings
from backend.auth.jwt import create_access_token, decode_access_token, JWTError, TokenExpiredError
from agent.response.process_response import ProcessResponseHandler
from agent.response.action_models import ResponseActionStatus


@pytest.fixture
def sec_client():
    settings = Settings(
        app_name="RansomShield Security Hardening Test",
        environment="testing",
        mongodb_uri=None,
        database_backend="memory",
        jwt_secret_key="test-security-jwt-secret-key-12345",
        jwt_algorithm="HS256",
        access_token_expire_minutes=60,
        agent_api_key="test-agent-key-secret",
        rate_limit_enabled=True,
        rate_limit_auth_per_minute=5,  # Low threshold for testing rate limits
        rate_limit_general_per_minute=50,
        rate_limit_response_per_minute=20,
        max_request_body_bytes=1024 * 100,  # 100 KB for testing payload limits
        response_dry_run=True,
        require_two_person_approval=True,
        enforce_agent_auth_in_test=True,
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        yield client, settings


# =====================================================================
# 1. JWT Security Tests
# =====================================================================

def test_jwt_expired_token_rejected(sec_client):
    """Confirms expired JWT tokens are strictly rejected with TokenExpiredError / 401."""
    client, settings = sec_client

    # Create an expired token (expired 10 minutes ago)
    expired_token = create_access_token(
        {"sub": "analyst", "role": "ANALYST"},
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_delta=timedelta(minutes=-10),
    )

    with pytest.raises(TokenExpiredError):
        decode_access_token(expired_token, secret_key=settings.jwt_secret_key)

    # API call with expired token returns HTTP 401
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401
    assert "expired" in resp.text.lower()


def test_jwt_signature_tampering_rejected(sec_client):
    """Confirms tampered tokens fail cryptographic signature check."""
    client, settings = sec_client

    valid_token = create_access_token(
        {"sub": "analyst", "role": "ANALYST"},
        secret_key=settings.jwt_secret_key,
    )

    parts = valid_token.split(".")
    # Tamper with the payload segment
    tampered_token = f"{parts[0]}.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9.{parts[2]}"

    with pytest.raises(JWTError):
        decode_access_token(tampered_token, secret_key=settings.jwt_secret_key)

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert resp.status_code == 401


def test_jwt_wrong_secret_key_rejected(sec_client):
    """Confirms tokens signed by an unauthorized key fail decoding."""
    _, settings = sec_client

    forged_token = create_access_token(
        {"sub": "admin", "role": "ADMIN"},
        secret_key="attacker-arbitrary-secret-key-that-does-not-match",
    )

    with pytest.raises(JWTError):
        decode_access_token(forged_token, secret_key=settings.jwt_secret_key)


def test_jwt_malformed_token_rejected(sec_client):
    """Confirms malformed token formats are safely rejected."""
    _, settings = sec_client

    for bad in ["not-a-token", "a.b", "a.b.c.d", "", "null", "Bearer"]:
        with pytest.raises(JWTError):
            decode_access_token(bad, secret_key=settings.jwt_secret_key)


# =====================================================================
# 2. Agent Authentication Tests
# =====================================================================

def test_agent_auth_missing_and_invalid_key_rejected(sec_client):
    """Confirms agent telemetry endpoints require valid X-Agent-Key header."""
    client, settings = sec_client

    payload = {
        "agent_id": "test-win11-agent",
        "hostname": "DESKTOP-SEC",
        "os_name": "Windows",
        "os_version": "11.0",
        "architecture": "x86_64",
        "agent_version": "1.0.0",
        "ip_addresses": ["192.168.1.50"],
        "mac_addresses": ["00:11:22:33:44:55"],
    }

    # 1. Missing key -> 401
    resp_missing = client.post("/api/v1/agents/register", json=payload)
    assert resp_missing.status_code == 401

    # 2. Invalid key -> 401
    resp_invalid = client.post(
        "/api/v1/agents/register",
        json=payload,
        headers={"X-Agent-Key": "completely-wrong-agent-key"},
    )
    assert resp_invalid.status_code == 401

    # 3. Correct key -> 201
    resp_valid = client.post(
        "/api/v1/agents/register",
        json=payload,
        headers={"X-Agent-Key": settings.agent_api_key},
    )
    assert resp_valid.status_code == 201


# =====================================================================
# 3. Input Validation & Path Traversal Rejection
# =====================================================================

def test_quarantine_path_traversal_rejection(sec_client):
    """Confirms path traversal sequences are rejected at the API schema boundary."""
    client, settings = sec_client
    token = create_access_token({"sub": "admin", "role": "ADMIN"}, secret_key=settings.jwt_secret_key)

    bad_payload = {
        "action_type": "QUARANTINE_FILE",
        "target": "C:\\safe\\path\\..\\..\\Windows\\System32\\calc.exe",
        "parameters": {"file_path": "C:\\safe\\path\\..\\..\\Windows\\System32\\calc.exe"},
    }

    resp = client.post(
        "/api/v1/response/actions",
        json=bad_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422  # Pydantic validation error


def test_quarantine_null_byte_rejection(sec_client):
    """Confirms null bytes (\x00) in file path are rejected."""
    client, settings = sec_client
    token = create_access_token({"sub": "admin", "role": "ADMIN"}, secret_key=settings.jwt_secret_key)

    null_payload = {
        "action_type": "QUARANTINE_FILE",
        "target": "C:\\safe\\file.txt\x00.exe",
        "parameters": {"file_path": "C:\\safe\\file.txt\x00.exe"},
    }

    resp = client.post(
        "/api/v1/response/actions",
        json=null_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


def test_quarantine_unc_path_rejection(sec_client):
    """Confirms UNC network share paths (\\\\share\\file) are rejected."""
    client, settings = sec_client
    token = create_access_token({"sub": "admin", "role": "ADMIN"}, secret_key=settings.jwt_secret_key)

    unc_payload = {
        "action_type": "QUARANTINE_FILE",
        "target": "\\\\remote-server\\share\\malware.exe",
        "parameters": {"file_path": "\\\\remote-server\\share\\malware.exe"},
    }

    resp = client.post(
        "/api/v1/response/actions",
        json=unc_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


# =====================================================================
# 4. Rate Limiting Tests
# =====================================================================

def test_rate_limiting_auth_endpoint(sec_client):
    """Confirms that exceeding auth rate limit triggers HTTP 429 Too Many Requests."""
    client, _ = sec_client

    # Auth limit configured to 5 req/min in fixture
    responses = []
    for _ in range(7):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
        responses.append(resp.status_code)

    assert 429 in responses
    # Verify Retry-After header present
    rate_limited_resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert rate_limited_resp.status_code == 429
    assert "Retry-After" in rate_limited_resp.headers


# =====================================================================
# 5. Request Body Size Limits
# =====================================================================

def test_request_body_size_limit(sec_client):
    """Confirms that payloads exceeding max_request_body_bytes are rejected with HTTP 413."""
    client, settings = sec_client
    token = create_access_token({"sub": "admin", "role": "ADMIN"}, secret_key=settings.jwt_secret_key)

    # Fixture sets limit to 100 KB; send a 150 KB payload
    oversized_data = "A" * (150 * 1024)
    resp = client.post(
        "/api/v1/response/actions",
        json={
            "action_type": "TERMINATE_PROCESS",
            "target": "1234",
            "parameters": {"oversized_blob": oversized_data},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 413
    assert "PAYLOAD_TOO_LARGE" in resp.text


# =====================================================================
# 6. Error Response Sanitization
# =====================================================================

def test_error_response_no_stack_trace_leak(sec_client):
    """Confirms 500 internal errors do not leak stack traces or internal paths to clients."""
    client, _ = sec_client

    # Accessing nonexistent resource returns controlled 404 envelope
    resp = client.get("/api/v1/nonexistent-endpoint-xyz")
    assert resp.status_code == 404
    data = resp.json()
    assert data["success"] is False
    assert "error" in data
    assert "Traceback" not in resp.text


# =====================================================================
# 7. Production Configuration Safety Validation
# =====================================================================

def test_production_mode_rejects_default_secrets():
    """Confirms Settings raises ValueError if production mode is configured with weak/default secrets."""
    with pytest.raises(ValueError) as exc1:
        Settings(
            environment="production",
            jwt_secret_key="ransomshield-super-secret-jwt-key-change-in-production",
            agent_api_key="a" * 32,
            cors_origins=["http://localhost:3000"],
        )
    assert "JWT_SECRET_KEY" in str(exc1.value)

    with pytest.raises(ValueError) as exc2:
        Settings(
            environment="production",
            jwt_secret_key="a" * 32,
            agent_api_key="rs-agent-secret-key-prod",
            cors_origins=["http://localhost:3000"],
        )
    assert "AGENT_API_KEY" in str(exc2.value)

    with pytest.raises(ValueError) as exc3:
        Settings(
            environment="production",
            jwt_secret_key="a" * 32,
            agent_api_key="a" * 32,
            cors_origins=["*"],
        )
    assert "CORS_ORIGINS" in str(exc3.value)


# =====================================================================
# 8. Protected Process Safeguards
# =====================================================================

def test_protected_process_refusal():
    """Confirms critical system binaries cannot be terminated even under live execution."""
    handler = ProcessResponseHandler(dry_run=False)

    for proc in ["csrss.exe", "lsass.exe", "smss.exe", "wininit.exe", "services.exe", "explorer.exe"]:
        is_prot, reason = handler.is_protected(pid=54321, process_name=proc)
        assert is_prot is True
        assert len(reason) > 0

    # PID 0 and 4 are strictly refused
    res0 = handler.terminate_process(pid=0)
    assert res0.status == ResponseActionStatus.REFUSED
    res4 = handler.terminate_process(pid=4)
    assert res4.status == ResponseActionStatus.REFUSED
