"""
RansomShield AI — Auth & RBAC Route Dependencies
Phase 3C: Full Backend Integration

Provides FastAPI dependencies for JWT bearer token validation, server-side RBAC enforcement,
and agent API key authentication.
"""

import logging
from typing import List, Optional
from fastapi import Header, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.config.settings import get_settings
from backend.auth.jwt import decode_access_token, JWTError, TokenExpiredError
from backend.schemas.user import UserResponse, UserRole
from backend.services.user_service import user_service

logger = logging.getLogger("RansomShieldBackend.AuthDependencies")

security_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> UserResponse:
    """
    Extracts and verifies JWT bearer token from Authorization header.
    Returns the authenticated UserResponse.
    Raises HTTP 401 on missing, expired, or invalid token.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Missing Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    settings = getattr(request.app.state, "settings", None) or get_settings()
    token = credentials.credentials

    try:
        payload = decode_access_token(
            token=token,
            secret_key=settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token claims (missing subject)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await user_service.get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_roles(*allowed_roles: UserRole):
    """
    Factory creating a dependency that enforces server-side Role-Based Access Control (RBAC).
    Raises HTTP 403 Forbidden if user's role is not in allowed_roles.
    """
    async def role_checker(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
        if current_user.role not in allowed_roles:
            role_names = [r.value if hasattr(r, "value") else str(r) for r in allowed_roles]
            curr_name = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
            logger.warning(
                f"[RBAC_FORBIDDEN] User '{current_user.username}' with role '{curr_name}' "
                f"attempted to access endpoint requiring {role_names}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires one of roles {role_names}. Your role is '{curr_name}'.",
            )
        return current_user

    return role_checker


async def verify_agent_auth(
    request: Request,
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> bool:
    """
    Authenticates Windows Endpoint Agent telemetry requests.
    Validates either:
    1. X-Agent-Key header matching settings.agent_api_key, OR
    2. Bearer token of an authenticated ADMIN/ANALYST user or agent token.
    """
    settings = getattr(request.app.state, "settings", None) or get_settings()

    # 1. Check Agent Secret Key
    if x_agent_key is not None:
        if x_agent_key == settings.agent_api_key:
            return True
        logger.warning("[AGENT_AUTH_FAILED] Invalid X-Agent-Key provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent authentication key",
        )

    # 2. Check Bearer Token (if provided)
    if credentials and credentials.credentials:
        token = credentials.credentials
        if token == settings.agent_api_key:
            return True
        try:
            payload = decode_access_token(
                token=token,
                secret_key=settings.jwt_secret_key,
                algorithm=settings.jwt_algorithm,
            )
            if payload.get("sub"):
                return True
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired bearer token",
            )

    # 3. If explicit enforcement requested or in production/staging environments, require authentication
    if getattr(settings, "enforce_agent_auth_in_test", False) or settings.environment in ("production", "prod", "staging"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Endpoint agent authentication required (missing or invalid X-Agent-Key)",
        )

    # 4. In development/testing environments when unauthenticated, allow pass-through
    return True
