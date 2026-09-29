"""
RansomShield AI — Password Hashing & Verification
Phase 3C: Full Backend Integration

Provides production-grade, constant-time password hashing and verification using
PBKDF2-HMAC-SHA256 (NIST SP 800-132 recommended, 100,000 iterations, 16-byte random salt).
Zero external C-library dependency, preventing Windows compilation issues.
"""

import hashlib
import secrets
from typing import Tuple

DEFAULT_ITERATIONS = 100_000
ALGORITHM_NAME = "pbkdf2_sha256"


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """
    Hashes a plaintext password using PBKDF2-HMAC-SHA256 with a secure random salt.
    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return f"{ALGORITHM_NAME}${iterations}${salt.hex()}${key.hex()}"


def verify_password(password: str, hashed_str: str) -> bool:
    """
    Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash using
    constant-time comparison to protect against timing attacks.
    """
    if not password or not hashed_str:
        return False

    parts = hashed_str.split("$")
    if len(parts) != 4:
        return False

    algo, iter_str, salt_hex, key_hex = parts
    if algo != ALGORITHM_NAME:
        return False

    try:
        iterations = int(iter_str)
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
    except (ValueError, TypeError):
        return False

    computed_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return secrets.compare_digest(computed_key, expected_key)
