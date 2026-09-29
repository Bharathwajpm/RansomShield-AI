"""
RansomShield AI — Incident Repository
Phase 3A: Backend Foundation

Provides thread-safe in-memory storage for correlated security incidents.
"""

import threading
from typing import Optional, List, Dict, Any
from backend.repositories.base import BaseRepository
from backend.schemas.incident import IncidentResponse


class IncidentRepository(BaseRepository[IncidentResponse]):
    """
    In-memory repository for security incidents.
    """

    def __init__(self, max_records: int = 500):
        self._incidents: Dict[str, IncidentResponse] = {}
        self._order: List[str] = []
        self._max_records = max_records
        self._lock = threading.RLock()

    async def create(self, item: IncidentResponse) -> IncidentResponse:
        with self._lock:
            if item.incident_id in self._incidents:
                self._order.remove(item.incident_id)
            elif len(self._order) >= self._max_records:
                evicted_id = self._order.pop(0)
                if evicted_id in self._incidents:
                    del self._incidents[evicted_id]

            self._incidents[item.incident_id] = item
            self._order.append(item.incident_id)
            return item

    async def get_by_id(self, item_id: str) -> Optional[IncidentResponse]:
        with self._lock:
            return self._incidents.get(item_id)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[IncidentResponse]:
        status_filter = filters.get("status")
        severity_filter = filters.get("severity")
        endpoint_filter = filters.get("endpoint_id")

        with self._lock:
            # Newest incidents first
            items = [self._incidents[iid] for iid in reversed(self._order) if iid in self._incidents]

            if status_filter:
                items = [i for i in items if i.status.upper() == status_filter.upper()]
            if severity_filter:
                items = [i for i in items if i.severity.upper() == severity_filter.upper()]
            if endpoint_filter:
                items = [i for i in items if i.endpoint_id == endpoint_filter]

            return items[offset : offset + limit]

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[IncidentResponse]:
        with self._lock:
            inc = self._incidents.get(item_id)
            if not inc:
                return None
            inc_dict = inc.model_dump()
            inc_dict.update(updates)
            updated_inc = IncidentResponse(**inc_dict)
            self._incidents[item_id] = updated_inc
            return updated_inc

    async def delete(self, item_id: str) -> bool:
        with self._lock:
            if item_id in self._incidents:
                del self._incidents[item_id]
                if item_id in self._order:
                    self._order.remove(item_id)
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._incidents.clear()
            self._order.clear()


# Singleton repository instance
incident_repository = IncidentRepository()


def get_incident_repository() -> IncidentRepository:
    return incident_repository
