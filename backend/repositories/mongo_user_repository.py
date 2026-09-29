"""
RansomShield AI — MongoDB User Repository
Phase 3C: Full Backend Integration

MongoDB repository for persistent user storage, authentication queries, and RBAC roles.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from backend.repositories.base import BaseRepository
from backend.schemas.user import UserInDB, UserRole
from backend.database.mongodb import get_db_manager
from backend.auth.security import hash_password

logger = logging.getLogger("RansomShieldBackend.MongoUserRepository")


class MongoUserRepository(BaseRepository[UserInDB]):
    """MongoDB implementation of the User repository."""

    def __init__(self):
        self._seeded = False

    @property
    def collection(self):
        return get_db_manager().users_collection

    async def _ensure_default_users(self):
        """Seeds default accounts into MongoDB if the collection is empty."""
        if self._seeded:
            return
        try:
            count = await self.collection.count_documents({})
            if count == 0:
                logger.info("[DB_SEED] Seeding default accounts into MongoDB users collection...")
                defaults = [
                    ("admin", "admin123", UserRole.ADMIN, "SOC Administrator", "admin@ransomshield.local"),
                    ("analyst", "analyst123", UserRole.ANALYST, "SOC Analyst", "analyst@ransomshield.local"),
                    ("viewer", "viewer123", UserRole.VIEWER, "SOC Read-Only Viewer", "viewer@ransomshield.local"),
                ]
                now = datetime.now(timezone.utc)
                docs = []
                for uname, pwd, role, fullname, email in defaults:
                    user = UserInDB(
                        user_id=f"usr_{uname}",
                        username=uname,
                        email=email,
                        role=role,
                        full_name=fullname,
                        is_active=True,
                        hashed_password=hash_password(pwd),
                        created_at=now,
                        updated_at=now,
                    )
                    doc = user.model_dump()
                    doc["created_at"] = doc["created_at"].isoformat()
                    doc["updated_at"] = doc["updated_at"].isoformat()
                    docs.append(doc)
                await self.collection.insert_many(docs)
                logger.info("[DB_SEED] Successfully seeded default accounts into MongoDB.")
            self._seeded = True
        except Exception as e:
            logger.warning(f"[DB_SEED] Note during user seed check: {e}")

    async def get_by_id(self, entity_id: str) -> Optional[UserInDB]:
        await self._ensure_default_users()
        doc = await self.collection.find_one({"user_id": entity_id}, {"_id": 0})
        if not doc:
            return None
        return UserInDB(**doc)

    async def get_by_username(self, username: str) -> Optional[UserInDB]:
        await self._ensure_default_users()
        doc = await self.collection.find_one({"username": username}, {"_id": 0})
        if not doc:
            return None
        return UserInDB(**doc)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[UserInDB]:
        await self._ensure_default_users()
        query = filters or {}
        cursor = self.collection.find(query, {"_id": 0}).skip(offset).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [UserInDB(**d) for d in docs]

    async def get_all(self, skip: int = 0, limit: int = 100, filters: Optional[Dict[str, Any]] = None) -> List[UserInDB]:
        return await self.list(limit=limit, offset=skip, **(filters or {}))

    async def create(self, entity: UserInDB) -> UserInDB:
        await self._ensure_default_users()
        doc = entity.model_dump()
        doc["created_at"] = doc["created_at"].isoformat()
        doc["updated_at"] = doc["updated_at"].isoformat()
        await self.collection.insert_one(doc)
        return entity

    async def update(self, entity_id: str, updates: Dict[str, Any]) -> Optional[UserInDB]:
        await self._ensure_default_users()
        now = datetime.now(timezone.utc).isoformat()
        updates["updated_at"] = now
        res = await self.collection.find_one_and_update(
            {"user_id": entity_id},
            {"$set": updates},
            projection={"_id": 0},
            return_document=True,
        )
        if not res:
            return None
        return UserInDB(**res)

    async def delete(self, entity_id: str) -> bool:
        await self._ensure_default_users()
        res = await self.collection.delete_one({"user_id": entity_id})
        return res.deleted_count > 0

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        await self._ensure_default_users()
        return await self.collection.count_documents(filters or {})
