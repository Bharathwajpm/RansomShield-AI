"""
RansomShield AI — User & Authentication Service Layer
Phase 3C: Full Backend Integration

Provides user authentication, password validation, user registration, and RBAC profile retrieval.
"""

import uuid
import logging
from typing import Optional, List
from datetime import datetime, timezone

from backend.schemas.user import UserCreate, UserResponse, UserInDB, UserRole
from backend.auth.security import hash_password, verify_password
from backend.repositories.factory import get_user_repository

logger = logging.getLogger("RansomShieldBackend.UserService")


class UserService:
    """Service layer for authentication and user management."""

    def __init__(self, user_repo=None):
        self._repo = user_repo

    @property
    def repo(self):
        return self._repo or get_user_repository()

    async def authenticate_user(self, username: str, password: str) -> Optional[UserResponse]:
        """Verifies username and password. Returns UserResponse if valid, None otherwise."""
        user_in_db = await self.repo.get_by_username(username)
        if not user_in_db:
            return None
        if not user_in_db.is_active:
            return None
        if not verify_password(password, user_in_db.hashed_password):
            return None
        return UserResponse(
            user_id=user_in_db.user_id,
            username=user_in_db.username,
            email=user_in_db.email,
            role=user_in_db.role,
            full_name=user_in_db.full_name,
            is_active=user_in_db.is_active,
            created_at=user_in_db.created_at,
            updated_at=user_in_db.updated_at,
        )

    async def get_user_by_username(self, username: str) -> Optional[UserResponse]:
        """Retrieves a user profile by username."""
        user_in_db = await self.repo.get_by_username(username)
        if not user_in_db:
            return None
        return UserResponse(
            user_id=user_in_db.user_id,
            username=user_in_db.username,
            email=user_in_db.email,
            role=user_in_db.role,
            full_name=user_in_db.full_name,
            is_active=user_in_db.is_active,
            created_at=user_in_db.created_at,
            updated_at=user_in_db.updated_at,
        )

    async def get_user_by_id(self, user_id: str) -> Optional[UserResponse]:
        """Retrieves a user profile by user_id."""
        user_in_db = await self.repo.get_by_id(user_id)
        if not user_in_db:
            return None
        return UserResponse(
            user_id=user_in_db.user_id,
            username=user_in_db.username,
            email=user_in_db.email,
            role=user_in_db.role,
            full_name=user_in_db.full_name,
            is_active=user_in_db.is_active,
            created_at=user_in_db.created_at,
            updated_at=user_in_db.updated_at,
        )

    async def create_user(self, user_in: UserCreate) -> UserResponse:
        """Registers a new user account."""
        existing = await self.repo.get_by_username(user_in.username)
        if existing:
            raise ValueError(f"Username '{user_in.username}' is already taken")

        now = datetime.now(timezone.utc)
        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        hashed = hash_password(user_in.password)

        new_user = UserInDB(
            user_id=user_id,
            username=user_in.username,
            email=user_in.email,
            role=user_in.role,
            full_name=user_in.full_name,
            is_active=user_in.is_active,
            hashed_password=hashed,
            created_at=now,
            updated_at=now,
        )
        created = await self.repo.create(new_user)
        return UserResponse(
            user_id=created.user_id,
            username=created.username,
            email=created.email,
            role=created.role,
            full_name=created.full_name,
            is_active=created.is_active,
            created_at=created.created_at,
            updated_at=created.updated_at,
        )

    async def list_users(self, skip: int = 0, limit: int = 50) -> List[UserResponse]:
        """Lists users with pagination."""
        users_in_db = await self.repo.get_all(skip=skip, limit=limit)
        return [
            UserResponse(
                user_id=u.user_id,
                username=u.username,
                email=u.email,
                role=u.role,
                full_name=u.full_name,
                is_active=u.is_active,
                created_at=u.created_at,
                updated_at=u.updated_at,
            )
            for u in users_in_db
        ]


user_service = UserService()
