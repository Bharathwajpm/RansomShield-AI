"""
RansomShield AI — MongoDB Incident Repository
Phase 3B: MongoDB Persistence Layer

Provides persistent MongoDB storage for correlated security incidents.
"""

import re
from typing import Optional, List, Dict, Any
from pymongo import DESCENDING, ReturnDocument

from backend.repositories.base import BaseRepository
from backend.schemas.incident import IncidentResponse
from backend.database.mongodb import MongoDBManager, get_db_manager


class MongoIncidentRepository(BaseRepository[IncidentResponse]):
    """
    MongoDB repository implementation for security incidents.
    """

    def __init__(self, db_manager: Optional[MongoDBManager] = None):
        self._db_mgr = db_manager

    @property
    def collection(self):
        return (self._db_mgr or get_db_manager()).incidents_collection

    async def create(self, item: IncidentResponse) -> IncidentResponse:
        doc = item.model_dump()
        doc["_id"] = item.incident_id
        await self.collection.replace_one({"_id": item.incident_id}, doc, upsert=True)
        return item

    async def get_by_id(self, item_id: str) -> Optional[IncidentResponse]:
        doc = await self.collection.find_one({"_id": item_id})
        if not doc:
            return None
        doc.pop("_id", None)
        return IncidentResponse(**doc)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[IncidentResponse]:
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
        items: List[IncidentResponse] = []
        async for doc in cursor:
            doc.pop("_id", None)
            items.append(IncidentResponse(**doc))
        return items

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[IncidentResponse]:
        doc = await self.collection.find_one_and_update(
            {"_id": item_id},
            {"$set": updates},
            return_document=ReturnDocument.AFTER,
        )
        if not doc:
            return None
        doc.pop("_id", None)
        return IncidentResponse(**doc)

    async def delete(self, item_id: str) -> bool:
        result = await self.collection.delete_one({"_id": item_id})
        return result.deleted_count > 0

    async def clear(self) -> None:
        """Removes all documents from the incidents collection (primarily for tests)."""
        await self.collection.delete_many({})
