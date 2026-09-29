"""
RansomShield AI — Response Action & Audit In-Memory Repositories
Phase 4: Defensive Response & Endpoint Containment

Thread-safe in-memory storage for defensive response actions and immutable audit logs.
"""

import threading
from typing import Optional, List, Dict, Any

from backend.repositories.base import BaseRepository
from backend.schemas.response import ResponseActionResponse, ResponseAuditLog


class ResponseRepository(BaseRepository[ResponseActionResponse]):
    """
    In-memory repository for response and containment actions.
    """

    def __init__(self, max_records: int = 1000):
        self._actions: Dict[str, ResponseActionResponse] = {}
        self._order: List[str] = []
        self._max_records = max_records
        self._lock = threading.RLock()

    async def create(self, item: ResponseActionResponse) -> ResponseActionResponse:
        with self._lock:
            if item.action_id in self._actions:
                self._order.remove(item.action_id)
            elif len(self._order) >= self._max_records:
                evicted_id = self._order.pop(0)
                self._actions.pop(evicted_id, None)

            self._actions[item.action_id] = item
            self._order.append(item.action_id)
            return item

    async def get_by_id(self, item_id: str) -> Optional[ResponseActionResponse]:
        with self._lock:
            return self._actions.get(item_id)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[ResponseActionResponse]:
        status_filter = filters.get("status")
        type_filter = filters.get("action_type")
        agent_filter = filters.get("agent_id")

        with self._lock:
            items = [self._actions[aid] for aid in reversed(self._order) if aid in self._actions]

            if status_filter:
                items = [a for a in items if a.status.value.upper() == str(status_filter).upper()]
            if type_filter:
                items = [a for a in items if a.action_type.value.upper() == str(type_filter).upper()]
            if agent_filter:
                items = [a for a in items if a.agent_id == agent_filter]

            return items[offset : offset + limit]

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[ResponseActionResponse]:
        with self._lock:
            item = self._actions.get(item_id)
            if not item:
                return None

            data = item.model_dump()
            data.update(updates)
            updated_item = ResponseActionResponse(**data)
            self._actions[item_id] = updated_item
            return updated_item

    async def delete(self, item_id: str) -> bool:
        with self._lock:
            if item_id in self._actions:
                del self._actions[item_id]
                if item_id in self._order:
                    self._order.remove(item_id)
                return True
            return False


class ResponseAuditRepository:
    """
    Append-only thread-safe in-memory store for immutable response audit logs.
    """

    def __init__(self, max_records: int = 5000):
        self._logs: List[ResponseAuditLog] = []
        self._max_records = max_records
        self._lock = threading.RLock()

    async def create(self, log: ResponseAuditLog) -> ResponseAuditLog:
        with self._lock:
            if len(self._logs) >= self._max_records:
                self._logs.pop(0)
            self._logs.append(log)
            return log

    async def list_by_action(self, action_id: str) -> List[ResponseAuditLog]:
        with self._lock:
            return [l for l in reversed(self._logs) if l.action_id == action_id]

    async def list_all(self, limit: int = 100, offset: int = 0, agent_id: Optional[str] = None) -> List[ResponseAuditLog]:
        with self._lock:
            logs = list(reversed(self._logs))
            if agent_id:
                logs = [l for l in logs if l.agent_id == agent_id]
            return logs[offset : offset + limit]


# Singleton instances
response_repository = ResponseRepository()
response_audit_repository = ResponseAuditRepository()
