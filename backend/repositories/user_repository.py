"""
RansomShield AI — In-Memory User Repository
Phase 3C: Full Backend Integration

Thread-safe in-memory user repository with default seed users (admin, analyst, viewer).
"""

import threading
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from backend.repositories.base import BaseRepository
from backend.schemas.user import UserInDB, UserRole
from backend.auth.security import hash_password


class UserRepository(BaseRepository[UserInDB]):
    """Thread-safe in-memory repository for user accounts with bootstrap seeds."""

    def __init__(self):
        self._lock = threading.Lock()
        self._users: Dict[str, UserInDB] = {}
        self._username_index: Dict[str, str] = {}  # username.lower() -> user_id
        self._seed_default_users()

    def _seed_default_users(self):
        """Initializes default admin, analyst, and viewer accounts."""
        defaults = [
            ("admin", "admin123", UserRole.ADMIN, "SOC Administrator", "admin@ransomshield.local"),
            ("analyst", "analyst123", UserRole.ANALYST, "SOC Analyst", "analyst@ransomshield.local"),
            ("viewer", "viewer123", UserRole.VIEWER, "SOC Read-Only Viewer", "viewer@ransomshield.local"),
        ]
        now = datetime.now(timezone.utc)
        for uname, pwd, role, fullname, email in defaults:
            uid = f"usr_{uname}"
            user = UserInDB(
                user_id=uid,
                username=uname,
                email=email,
                role=role,
                full_name=fullname,
                is_active=True,
                hashed_password=hash_password(pwd),
                created_at=now,
                updated_at=now,
            )
            self._users[uid] = user
            self._username_index[uname.lower()] = uid

    async def get_by_id(self, entity_id: str) -> Optional[UserInDB]:
        with self._lock:
            return self._users.get(entity_id)

    async def get_by_username(self, username: str) -> Optional[UserInDB]:
        with self._lock:
            uid = self._username_index.get(username.lower())
            if uid:
                return self._users.get(uid)
            return None

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[UserInDB]:
        with self._lock:
            items = list(self._users.values())
            if filters:
                for k, v in filters.items():
                    items = [u for u in items if getattr(u, k, None) == v]
            return items[offset : offset + limit]

    async def get_all(self, skip: int = 0, limit: int = 100, filters: Optional[Dict[str, Any]] = None) -> List[UserInDB]:
        return await self.list(limit=limit, offset=skip, **(filters or {}))

    async def create(self, entity: UserInDB) -> UserInDB:
        with self._lock:
            if entity.username.lower() in self._username_index:
                raise ValueError(f"Username '{entity.username}' already exists")
            self._users[entity.user_id] = entity
            self._username_index[entity.username.lower()] = entity.user_id
            return entity

    async def update(self, entity_id: str, updates: Dict[str, Any]) -> Optional[UserInDB]:
        with self._lock:
            existing = self._users.get(entity_id)
            if not existing:
                return None
            data = existing.model_dump()
            data.update(updates)
            data["updated_at"] = datetime.now(timezone.utc)
            updated_user = UserInDB(**data)
            self._users[entity_id] = updated_user
            return updated_user

    async def delete(self, entity_id: str) -> bool:
        with self._lock:
            user = self._users.pop(entity_id, None)
            if user:
                self._username_index.pop(user.username.lower(), None)
                return True
            return False

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        with self._lock:
            if not filters:
                return len(self._users)
            items = list(self._users.values())
            for k, v in filters.items():
                items = [u for u in items if getattr(u, k, None) == v]
            return len(items)


user_repository = UserRepository()
