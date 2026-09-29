"""
RansomShield AI — Auth & RBAC Test Suite
Phase 3C: Full Backend Integration

Tests PBKDF2 password hashing, HMAC-SHA256 JWT tokens, login endpoint,
server-side RBAC enforcement (ADMIN vs ANALYST vs VIEWER), and agent key validation.
"""

import pytest
from datetime import timedelta
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings
from backend.auth.security import hash_password, verify_password
from backend.auth.jwt import create_access_token, decode_access_token, JWTError, TokenExpiredError
from backend.repositories.factory import get_user_repository
from backend.schemas.user import UserRole


@pytest.fixture
def auth_client():
    settings = Settings(
        app_name="RansomShield Auth Test Backend",
        environment="testing",
        mongodb_uri=None,
        jwt_secret_key="test-jwt-secret-key-for-testing",
        jwt_algorithm="HS256",
        access_token_expire_minutes=60,
        agent_api_key="test-agent-key-secret",
        enforce_agent_auth_in_test=True,
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        yield client, settings


# --- Cryptographic & JWT Unit Tests ---

def test_password_hashing_and_verification():
    raw_pass = "SuperSecurePassword123!"
    hashed = hash_password(raw_pass)
    assert hashed.startswith("pbkdf2_sha256$100000$")
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(raw_pass, "invalid$format") is False


def test_jwt_creation_and_decoding():
    secret = "my-secret-key-12345"
    payload = {"sub": "analyst", "role": "ANALYST"}
    token = create_access_token(payload, secret_key=secret, expires_delta=timedelta(minutes=15))
    assert isinstance(token, str)
    assert len(token.split(".")) == 3

    decoded = decode_access_token(token, secret_key=secret)
    assert decoded["sub"] == "analyst"
    assert decoded["role"] == "ANALYST"
    assert "exp" in decoded
    assert "iat" in decoded


def test_jwt_tampering_and_expiration():
    secret = "my-secret-key-12345"
    # Tampered signature
    token = create_access_token({"sub": "admin"}, secret_key=secret)
    tampered = token[:-4] + "ABCD"
    with pytest.raises(JWTError):
        decode_access_token(tampered, secret_key=secret)

    # Expired token
    expired_token = create_access_token({"sub": "admin"}, secret_key=secret, expires_delta=timedelta(seconds=-10))
    with pytest.raises(TokenExpiredError):
        decode_access_token(expired_token, secret_key=secret)


# --- Endpoint Authentication Tests ---

def test_login_successful_and_unsuccessful(auth_client):
    client, _ = auth_client

    # 1. Valid Admin Login
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "ADMIN"

    # 2. Invalid Password
    bad_resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert bad_resp.status_code == 401
    err_msg = bad_resp.json().get("detail") or bad_resp.json().get("error", {}).get("message", "")
    assert "Invalid username or password" in err_msg

    # 3. Nonexistent User
    missing_resp = client.post("/api/v1/auth/login", json={"username": "nonexistent_user", "password": "pwd"})
    assert missing_resp.status_code == 401


def test_get_me_protected_route(auth_client):
    client, _ = auth_client

    # Unauthenticated -> 401
    unauth = client.get("/api/v1/auth/me")
    assert unauth.status_code == 401

    # Authenticated as Analyst
    login_resp = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"})
    token = login_resp.json()["access_token"]

    auth_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert auth_me.status_code == 200
    assert auth_me.json()["username"] == "analyst"
    assert auth_me.json()["role"] == "ANALYST"


# --- RBAC Server-Side Enforcement Tests ---

def test_rbac_admin_vs_analyst_vs_viewer(auth_client):
    client, _ = auth_client

    # Login tokens for all 3 roles
    admin_tok = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"}).json()["access_token"]
    analyst_tok = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"}).json()["access_token"]
    viewer_tok = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer123"}).json()["access_token"]

    new_user_payload = {
        "username": "new_analyst",
        "password": "Password123!",
        "role": "ANALYST",
        "full_name": "New SOC Analyst",
    }

    # 1. Viewer trying to register a user -> 403 Forbidden
    resp_viewer = client.post("/api/v1/auth/register", json=new_user_payload, headers={"Authorization": f"Bearer {viewer_tok}"})
    assert resp_viewer.status_code == 403

    # 2. Analyst trying to register a user -> 403 Forbidden
    resp_analyst = client.post("/api/v1/auth/register", json=new_user_payload, headers={"Authorization": f"Bearer {analyst_tok}"})
    assert resp_analyst.status_code == 403

    # 3. Admin registering user -> 201 Created
    resp_admin = client.post("/api/v1/auth/register", json=new_user_payload, headers={"Authorization": f"Bearer {admin_tok}"})
    assert resp_admin.status_code == 201
    assert resp_admin.json()["username"] == "new_analyst"

    # 4. Listing users: Admin permitted (200), Viewer forbidden (403)
    assert client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {admin_tok}"}).status_code == 200
    assert client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {viewer_tok}"}).status_code == 403


# --- Agent Authentication Tests ---

def test_agent_api_key_authentication(auth_client):
    client, settings = auth_client

    payload = {
        "agent_id": "ep-agent-auth-01",
        "hostname": "ENDPOINT-TEST",
        "os_name": "Windows",
        "os_version": "11.0",
        "architecture": "x86_64",
        "agent_version": "2.0.0",
    }

    # 1. Missing Agent Key when enforced -> 401
    resp_no_key = client.post("/api/v1/agents/register", json=payload)
    assert resp_no_key.status_code == 401

    # 2. Invalid Agent Key -> 401
    resp_bad_key = client.post(
        "/api/v1/agents/register",
        json=payload,
        headers={"X-Agent-Key": "wrong-secret-key"},
    )
    assert resp_bad_key.status_code == 401

    # 3. Valid Agent Key -> 201
    resp_valid = client.post(
        "/api/v1/agents/register",
        json=payload,
        headers={"X-Agent-Key": settings.agent_api_key},
    )
    assert resp_valid.status_code == 201
    assert resp_valid.json()["success"] is True
