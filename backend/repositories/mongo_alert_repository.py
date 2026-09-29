"""
RansomShield AI — MongoDB Alert Repository
Phase 3B: MongoDB Persistence Layer

Provides persistent MongoDB storage for detection alerts.
"""

import re
from typing import Optional, List, Dict, Any
from pymongo import DESCENDING, ReturnDocument

from backend.repositories.base import BaseRepository
from backend.schemas.alert import AlertResponse
from backend.database.mongodb import MongoDBManager, get_db_manager


class MongoAlertRepository(BaseRepository[AlertResponse]):
    """
    MongoDB repository implementation for detection alerts.
    """

    def __init__(self, db_manager: Optional[MongoDBManager] = None):
        self._db_mgr = db_manager

    @property
    def collection(self):
        return (self._db_mgr or get_db_manager()).alerts_collection

    async def create(self, item: AlertResponse) -> AlertResponse:
        doc = item.model_dump()
        doc["_id"] = item.alert_id
        await self.collection.replace_one({"_id": item.alert_id}, doc, upsert=True)
        return item

    async def get_by_id(self, item_id: str) -> Optional[AlertResponse]:
        doc = await self.collection.find_one({"_id": item_id})
        if not doc:
            return None
        doc.pop("_id", None)
        return AlertResponse(**doc)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[AlertResponse]:
        query: Dict[str, Any] = {}
        
        status_filter = filters.get("status")
        if status_filter:
            escaped = re.escape(status_filter.strip())
            query["status"] = {"$regex": f"^{escaped}$", "$options": "i"}

        severity_filter = filters.get("severity")
        if severity_filter:
            escaped = re.escape(severity_filter.strip())
            query["severity"] = {"$regex": f"^{escaped}$", "$options": "i"}

        endpoint_filter = filters.get("endpoint_id")
        if endpoint_filter:
            query["endpoint_id"] = endpoint_filter.strip()

        cursor = self.collection.find(query).sort("created_at", DESCENDING).skip(offset).limit(limit)
        items: List[AlertResponse] = []
        async for doc in cursor:
            doc.pop("_id", None)
            items.append(AlertResponse(**doc))
        return items

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[AlertResponse]:
        doc = await self.collection.find_one_and_update(
            {"_id": item_id},
            {"$set": updates},
            return_document=ReturnDocument.AFTER,
        )
        if not doc:
            return None
        doc.pop("_id", None)
        return AlertResponse(**doc)

    async def delete(self, item_id: str) -> bool:
        result = await self.collection.delete_one({"_id": item_id})
        return result.deleted_count > 0

    async def clear(self) -> None:
        """Removes all documents from the alerts collection (primarily for tests)."""
        await self.collection.delete_many({})
