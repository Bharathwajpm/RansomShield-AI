"""
RansomShield AI — User & Authentication Schemas
Phase 3C: Full Backend Integration

Defines strongly typed schemas for User management, RBAC, and Authentication.
"""

from enum import Enum
from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: Optional[str] = Field(None, description="Optional email address")
    role: UserRole = Field(default=UserRole.ANALYST, description="RBAC Role")
    full_name: Optional[str] = Field(None, description="Display name")
    is_active: bool = Field(default=True, description="Account active status")


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, description="Plaintext password for registration")


class UserInDB(UserBase):
    user_id: str = Field(..., description="Unique User identifier")
    hashed_password: str = Field(..., description="PBKDF2-HMAC-SHA256 hashed password")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserResponse(UserBase):
    user_id: str
    created_at: datetime
    updated_at: datetime


class LoginRequest(BaseModel):
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Plaintext password")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
