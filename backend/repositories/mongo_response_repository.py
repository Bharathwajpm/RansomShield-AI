"""
RansomShield AI — MongoDB Response & Audit Repositories
Phase 4: Defensive Response & Endpoint Containment

Provides persistent MongoDB storage for response containment actions and immutable audit logs.
"""

import re
from typing import Optional, List, Dict, Any
from pymongo import DESCENDING, ReturnDocument

from backend.repositories.base import BaseRepository
from backend.schemas.response import ResponseActionResponse, ResponseAuditLog
from backend.database.mongodb import MongoDBManager, get_db_manager


class MongoResponseRepository(BaseRepository[ResponseActionResponse]):
    """
    MongoDB repository implementation for defensive response actions.
    """

    def __init__(self, db_manager: Optional[MongoDBManager] = None):
        self._db_mgr = db_manager

    @property
    def collection(self):
        return (self._db_mgr or get_db_manager()).response_actions_collection

    async def create(self, item: ResponseActionResponse) -> ResponseActionResponse:
        doc = item.model_dump()
        doc["_id"] = item.action_id
        await self.collection.replace_one({"_id": item.action_id}, doc, upsert=True)
        return item

    async def get_by_id(self, item_id: str) -> Optional[ResponseActionResponse]:
        doc = await self.collection.find_one({"_id": item_id})
        if not doc:
            return None
        doc.pop("_id", None)
        return ResponseActionResponse(**doc)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[ResponseActionResponse]:
        query: Dict[str, Any] = {}

        status_filter = filters.get("status")
        if status_filter:
            escaped = re.escape(str(status_filter).strip())
            query["status"] = {"$regex": f"^{escaped}$", "$options": "i"}

        type_filter = filters.get("action_type")
        if type_filter:
            escaped = re.escape(str(type_filter).strip())
            query["action_type"] = {"$regex": f"^{escaped}$", "$options": "i"}

        agent_filter = filters.get("agent_id")
        if agent_filter:
            query["agent_id"] = str(agent_filter).strip()

        cursor = self.collection.find(query).sort("created_at", DESCENDING).skip(offset).limit(limit)
        items: List[ResponseActionResponse] = []
        async for doc in cursor:
            doc.pop("_id", None)
            items.append(ResponseActionResponse(**doc))
        return items

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[ResponseActionResponse]:
        updated_doc = await self.collection.find_one_and_update(
            {"_id": item_id},
            {"$set": updates},
            return_document=ReturnDocument.AFTER,
        )
        if not updated_doc:
            return None
        updated_doc.pop("_id", None)
        return ResponseActionResponse(**updated_doc)

    async def delete(self, item_id: str) -> bool:
        result = await self.collection.delete_one({"_id": item_id})
        return result.deleted_count > 0


class MongoResponseAuditRepository:
    """
    MongoDB append-only audit repository for immutable response logging.
    """

    def __init__(self, db_manager: Optional[MongoDBManager] = None):
        self._db_mgr = db_manager

    @property
    def collection(self):
        return (self._db_mgr or get_db_manager()).response_audit_collection

    async def create(self, log: ResponseAuditLog) -> ResponseAuditLog:
        doc = log.model_dump()
        doc["_id"] = log.log_id
        await self.collection.replace_one({"_id": log.log_id}, doc, upsert=True)
        return log

    async def list_by_action(self, action_id: str) -> List[ResponseAuditLog]:
        cursor = self.collection.find({"action_id": action_id}).sort("timestamp", DESCENDING)
        items: List[ResponseAuditLog] = []
        async for doc in cursor:
            doc.pop("_id", None)
            items.append(ResponseAuditLog(**doc))
        return items

    async def list_all(self, limit: int = 100, offset: int = 0, agent_id: Optional[str] = None) -> List[ResponseAuditLog]:
        query: Dict[str, Any] = {}
        if agent_id:
            query["agent_id"] = agent_id
        cursor = self.collection.find(query).sort("timestamp", DESCENDING).skip(offset).limit(limit)
        items: List[ResponseAuditLog] = []
        async for doc in cursor:
            doc.pop("_id", None)
            items.append(ResponseAuditLog(**doc))
        return items
