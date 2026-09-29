"""
RansomShield AI — MongoDB Agent Repository
Phase 3B: MongoDB Persistence Layer

Provides persistent MongoDB storage for registered endpoint agents.
"""

import time
import re
from typing import Optional, List, Dict, Any
from pymongo import DESCENDING, ReturnDocument

from backend.repositories.base import BaseRepository
from backend.schemas.agent import AgentResponse
from backend.database.mongodb import MongoDBManager, get_db_manager


class MongoAgentRepository(BaseRepository[AgentResponse]):
    """
    MongoDB repository implementation for endpoint agents.
    """

    def __init__(self, db_manager: Optional[MongoDBManager] = None):
        self._db_mgr = db_manager

    @property
    def collection(self):
        return (self._db_mgr or get_db_manager()).agents_collection

    async def create(self, item: AgentResponse) -> AgentResponse:
        doc = item.model_dump()
        doc["_id"] = item.agent_id
        await self.collection.replace_one({"_id": item.agent_id}, doc, upsert=True)
        return item

    async def get_by_id(self, item_id: str) -> Optional[AgentResponse]:
        doc = await self.collection.find_one({"_id": item_id})
        if not doc:
            return None
        doc.pop("_id", None)
        return AgentResponse(**doc)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[AgentResponse]:
        query: Dict[str, Any] = {}
        status_filter = filters.get("status")
        if status_filter:
            # Case-insensitive safe regex
            escaped = re.escape(status_filter.strip())
            query["status"] = {"$regex": f"^{escaped}$", "$options": "i"}

        cursor = self.collection.find(query).sort("last_seen", DESCENDING).skip(offset).limit(limit)
        items: List[AgentResponse] = []
        async for doc in cursor:
            doc.pop("_id", None)
            items.append(AgentResponse(**doc))
        return items

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[AgentResponse]:
        doc = await self.collection.find_one_and_update(
            {"_id": item_id},
            {"$set": updates},
            return_document=ReturnDocument.AFTER,
        )
        if not doc:
            return None
        doc.pop("_id", None)
        return AgentResponse(**doc)

    async def delete(self, item_id: str) -> bool:
        result = await self.collection.delete_one({"_id": item_id})
        return result.deleted_count > 0

    async def update_heartbeat(self, agent_id: str, timestamp: Optional[float] = None) -> Optional[AgentResponse]:
        now = timestamp or time.time()
        return await self.update(agent_id, {"last_seen": now, "status": "online"})

    async def clear(self) -> None:
        """Removes all documents from the agents collection (primarily for tests)."""
        await self.collection.delete_many({})
