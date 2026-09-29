"""
RansomShield AI — JWT Creation & Verification
Phase 3C: Full Backend Integration

Provides standard HMAC-SHA256 (HS256) JSON Web Token creation, signature verification,
and claim extraction adhering strictly to RFC 7519.
Zero external dependency risk, using Python's standard hmac, hashlib, and base64 modules.
"""

import hmac
import hashlib
import base64
import json
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone


class JWTError(Exception):
    """Raised when token validation, parsing, or signature verification fails."""
    pass


class TokenExpiredError(JWTError):
    """Raised when a valid token has expired."""
    pass


def _base64url_encode(data: bytes) -> str:
    """Encodes bytes to base64url string without trailing '=' padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _base64url_decode(data_str: str) -> bytes:
    """Decodes a base64url string, adding required '=' padding."""
    rem = len(data_str) % 4
    if rem > 0:
        data_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data_str.encode("utf-8"))


def create_access_token(
    data: Dict[str, Any],
    secret_key: str,
    algorithm: str = "HS256",
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Creates an RFC 7519 compliant signed JWT token.
    """
    if algorithm != "HS256":
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Currently supported: 'HS256'")

    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=60)

    header = {"alg": "HS256", "typ": "JWT"}
    payload = data.copy()
    payload["iat"] = int(now.timestamp())
    payload["exp"] = int(expire.timestamp())

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    encoded_header = _base64url_encode(header_bytes)
    encoded_payload = _base64url_encode(payload_bytes)

    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    signature = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    encoded_signature = _base64url_encode(signature)

    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def decode_access_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256",
) -> Dict[str, Any]:
    """
    Decodes and verifies a JWT token. Checks cryptographic signature and expiration.
    Returns the decoded payload dict.
    """
    if not token or not isinstance(token, str):
        raise JWTError("Invalid token format")

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JWTError("Token must contain exactly 3 segments")

    encoded_header, encoded_payload, encoded_signature = parts

    try:
        header_bytes = _base64url_decode(encoded_header)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as e:
        raise JWTError(f"Malformed token header: {e}")

    if header.get("alg") != algorithm:
        raise JWTError(f"Algorithm mismatch: expected {algorithm}, got {header.get('alg')}")

    # Verify signature
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    expected_signature = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()

    try:
        actual_signature = _base64url_decode(encoded_signature)
    except Exception as e:
        raise JWTError(f"Malformed token signature: {e}")

    if not hmac.compare_digest(actual_signature, expected_signature):
        raise JWTError("Invalid token signature")

    # Decode payload
    try:
        payload_bytes = _base64url_decode(encoded_payload)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise JWTError(f"Malformed token payload: {e}")

    # Check expiration
    exp = payload.get("exp")
    if exp is not None:
        now_ts = int(time.time())
        if now_ts >= exp:
            raise TokenExpiredError("Token has expired")

    return payload
