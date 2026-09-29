"""
RansomShield AI — Agent Repository
Phase 3A: Backend Foundation

Provides thread-safe in-memory storage for registered endpoint agents.
"""

import threading
import time
from typing import Optional, List, Dict, Any
from backend.repositories.base import BaseRepository
from backend.schemas.agent import AgentResponse


class AgentRepository(BaseRepository[AgentResponse]):
    """
    In-memory repository for endpoint agents.
    """

    def __init__(self):
        self._agents: Dict[str, AgentResponse] = {}
        self._lock = threading.RLock()

    async def create(self, item: AgentResponse) -> AgentResponse:
        with self._lock:
            self._agents[item.agent_id] = item
            return item

    async def get_by_id(self, item_id: str) -> Optional[AgentResponse]:
        with self._lock:
            return self._agents.get(item_id)

    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[AgentResponse]:
        status_filter = filters.get("status")
        with self._lock:
            items = list(self._agents.values())
            if status_filter:
                items = [a for a in items if a.status.lower() == status_filter.lower()]
            # Sort by last_seen descending
            items.sort(key=lambda a: a.last_seen, reverse=True)
            return items[offset : offset + limit]

    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[AgentResponse]:
        with self._lock:
            agent = self._agents.get(item_id)
            if not agent:
                return None
            agent_dict = agent.model_dump()
            agent_dict.update(updates)
            updated_agent = AgentResponse(**agent_dict)
            self._agents[item_id] = updated_agent
            return updated_agent

    async def delete(self, item_id: str) -> bool:
        with self._lock:
            if item_id in self._agents:
                del self._agents[item_id]
                return True
            return False

    async def update_heartbeat(self, agent_id: str, timestamp: Optional[float] = None) -> Optional[AgentResponse]:
        if timestamp is None:
            timestamp = time.time()
        return await self.update(agent_id, {"last_seen": timestamp, "status": "online"})

    def clear(self) -> None:
        with self._lock:
            self._agents.clear()


# Singleton repository instance
agent_repository = AgentRepository()


def get_agent_repository() -> AgentRepository:
    return agent_repository
