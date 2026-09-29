"""
RansomShield AI — Authentication & User Management Router
Phase 3C: Full Backend Integration

Endpoints:
- POST /api/v1/auth/login: Authenticate user, issue JWT access token
- GET  /api/v1/auth/me: Retrieve currently authenticated user profile
- POST /api/v1/auth/register: Create user (Admin only)
- GET  /api/v1/auth/users: List users (Admin only)
"""

from datetime import timedelta
from typing import List
from fastapi import APIRouter, HTTPException, status, Depends, Request

from backend.config.settings import get_settings
from backend.schemas.user import LoginRequest, TokenResponse, UserCreate, UserResponse, UserRole
from backend.auth.jwt import create_access_token
from backend.auth.dependencies import get_current_user, require_roles
from backend.services.user_service import user_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request):
    """
    Authenticates username and password against stored PBKDF2 hashes.
    Returns standard JWT access token and user role profile.
    """
    user = await user_service.authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    settings = getattr(request.app.state, "settings", None) or get_settings()
    expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    token_claims = {
        "sub": user.username,
        "user_id": user.user_id,
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
    }

    access_token = create_access_token(
        data=token_claims,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_delta=expires_delta,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=user,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: UserResponse = Depends(get_current_user)):
    """Returns the authenticated user's profile and RBAC role."""
    return current_user


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    req: UserCreate,
    current_user: UserResponse = Depends(require_roles(UserRole.ADMIN)),
):
    """Registers a new user account (Admin only)."""
    try:
        new_user = await user_service.create_user(req)
        return new_user
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 50,
    current_user: UserResponse = Depends(require_roles(UserRole.ADMIN)),
):
    """Lists registered users (Admin only)."""
    return await user_service.list_users(skip=skip, limit=limit)
