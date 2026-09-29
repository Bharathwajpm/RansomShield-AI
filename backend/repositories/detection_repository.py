"""
RansomShield AI — Detection Repository
Phase 3A: Backend Foundation

Provides thread-safe in-memory storage for raw live DetectionResult records.
"""

import threading
from typing import Optional, List, Dict, Any
from backend.repositories.base import BaseRepository
from backend.schemas.detection import DetectionResponse


class DetectionRepository(BaseRepository[DetectionResponse]):
    """
    In-memory repository for raw detection records.
    """

    def __init__(self, max_records: int = 1000):
        self._detections: Dict[str, DetectionResponse] = {}
        self._order: List[str] = []
        self._max_records = max_records
        self._lock = threading.RLock()

    async def create(self, item: DetectionResponse) -> DetectionResponse:
        with self._lock:
            if item.detection_id in self._detections:
                self._order.remove(item.detection_id)
            elif len(self._order) >= self._max_records:
                evicted_id = self._order.pop(0)
                if evicted_id in self._detections:
                    del self._detections[evicted_id]

            self._detections[item.detection_id] = item
            self._order.append(item.detection_id)
            return item

    async def get_by_id(self, item_id: str) -> Optional[DetectionResponse]:
        with self._lock:
            return self._detections.get(item_id)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[DetectionResponse]:
        endpoint_filter = filters.get("endpoint_id")
        prediction_filter = filters.get("prediction")

        with self._lock:
            items = [self._detections[did] for did in reversed(self._order) if did in self._detections]

            if endpoint_filter:
                items = [d for d in items if d.endpoint_id == endpoint_filter]
            if prediction_filter:
                items = [d for d in items if d.prediction.lower() == prediction_filter.lower()]

            return items[offset : offset + limit]

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[DetectionResponse]:
        with self._lock:
            det = self._detections.get(item_id)
            if not det:
                return None
            det_dict = det.model_dump()
            det_dict.update(updates)
            updated_det = DetectionResponse(**det_dict)
            self._detections[item_id] = updated_det
            return updated_det

    async def delete(self, item_id: str) -> bool:
        with self._lock:
            if item_id in self._detections:
                del self._detections[item_id]
                if item_id in self._order:
                    self._order.remove(item_id)
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._detections.clear()
            self._order.clear()


# Singleton repository instance
detection_repository = DetectionRepository()


def get_detection_repository() -> DetectionRepository:
    return detection_repository
