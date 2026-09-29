"""
RansomShield AI — Alert Repository
Phase 3A: Backend Foundation

Provides thread-safe in-memory storage for detection alerts.
"""

import threading
from typing import Optional, List, Dict, Any
from backend.repositories.base import BaseRepository
from backend.schemas.alert import AlertResponse


class AlertRepository(BaseRepository[AlertResponse]):
    """
    In-memory repository for detection alerts.
    """

    def __init__(self, max_records: int = 1000):
        self._alerts: Dict[str, AlertResponse] = {}
        self._order: List[str] = []
        self._max_records = max_records
        self._lock = threading.RLock()

    async def create(self, item: AlertResponse) -> AlertResponse:
        with self._lock:
            if item.alert_id in self._alerts:
                self._order.remove(item.alert_id)
            elif len(self._order) >= self._max_records:
                evicted_id = self._order.pop(0)
                if evicted_id in self._alerts:
                    del self._alerts[evicted_id]

            self._alerts[item.alert_id] = item
            self._order.append(item.alert_id)
            return item

    async def get_by_id(self, item_id: str) -> Optional[AlertResponse]:
        with self._lock:
            return self._alerts.get(item_id)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[AlertResponse]:
        status_filter = filters.get("status")
        severity_filter = filters.get("severity")
        endpoint_filter = filters.get("endpoint_id")

        with self._lock:
            # Newest alerts first
            items = [self._alerts[aid] for aid in reversed(self._order) if aid in self._alerts]

            if status_filter:
                items = [a for a in items if a.status.upper() == status_filter.upper()]
            if severity_filter:
                items = [a for a in items if a.severity.upper() == severity_filter.upper()]
            if endpoint_filter:
                items = [a for a in items if a.endpoint_id == endpoint_filter]

            return items[offset : offset + limit]

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[AlertResponse]:
        with self._lock:
            alert = self._alerts.get(item_id)
            if not alert:
                return None
            alert_dict = alert.model_dump()
            alert_dict.update(updates)
            updated_alert = AlertResponse(**alert_dict)
            self._alerts[item_id] = updated_alert
            return updated_alert

    async def delete(self, item_id: str) -> bool:
        with self._lock:
            if item_id in self._alerts:
                del self._alerts[item_id]
                if item_id in self._order:
                    self._order.remove(item_id)
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._alerts.clear()
            self._order.clear()


# Singleton repository instance
alert_repository = AlertRepository()


def get_alert_repository() -> AlertRepository:
    return alert_repository
