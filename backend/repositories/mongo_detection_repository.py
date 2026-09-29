"""
RansomShield AI — MongoDB Detection Repository
Phase 3B: MongoDB Persistence Layer

Provides persistent MongoDB storage for raw live DetectionResult records.
"""

import re
from typing import Optional, List, Dict, Any
from pymongo import DESCENDING, ReturnDocument

from backend.repositories.base import BaseRepository
from backend.schemas.detection import DetectionResponse
from backend.database.mongodb import MongoDBManager, get_db_manager


class MongoDetectionRepository(BaseRepository[DetectionResponse]):
    """
    MongoDB repository implementation for raw live inference detections.
    """

    def __init__(self, db_manager: Optional[MongoDBManager] = None):
        self._db_mgr = db_manager

    @property
    def collection(self):
        return (self._db_mgr or get_db_manager()).detections_collection

    async def create(self, item: DetectionResponse) -> DetectionResponse:
        doc = item.model_dump()
        doc["_id"] = item.detection_id
        await self.collection.replace_one({"_id": item.detection_id}, doc, upsert=True)
        return item

    async def get_by_id(self, item_id: str) -> Optional[DetectionResponse]:
        doc = await self.collection.find_one({"_id": item_id})
        if not doc:
            return None
        doc.pop("_id", None)
        return DetectionResponse(**doc)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[DetectionResponse]:
        query: Dict[str, Any] = {}

        endpoint_filter = filters.get("endpoint_id")
        if endpoint_filter:
            query["endpoint_id"] = endpoint_filter.strip()

        prediction_filter = filters.get("prediction")
        if prediction_filter:
            escaped = re.escape(prediction_filter.strip())
            query["prediction"] = {"$regex": f"^{escaped}$", "$options": "i"}

        cursor = self.collection.find(query).sort("timestamp", DESCENDING).skip(offset).limit(limit)
        items: List[DetectionResponse] = []
        async for doc in cursor:
            doc.pop("_id", None)
            items.append(DetectionResponse(**doc))
        return items

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[DetectionResponse]:
        doc = await self.collection.find_one_and_update(
            {"_id": item_id},
            {"$set": updates},
            return_document=ReturnDocument.AFTER,
        )
        if not doc:
            return None
        doc.pop("_id", None)
        return DetectionResponse(**doc)

    async def delete(self, item_id: str) -> bool:
        result = await self.collection.delete_one({"_id": item_id})
        return result.deleted_count > 0

    async def clear(self) -> None:
        """Removes all documents from the detections collection (primarily for tests)."""
        await self.collection.delete_many({})
