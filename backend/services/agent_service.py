"""
RansomShield AI — Agent Service
Phase 3A: Backend Foundation

Encapsulates business logic for agent registration, heartbeat monitoring,
and diagnostic health status.
"""

import time
from typing import List, Optional, Dict, Any

from backend.schemas.agent import AgentRegisterRequest, AgentResponse, AgentStatusResponse
from backend.repositories.base import BaseRepository
from backend.repositories import get_agent_repository
from backend.config.settings import Settings, get_settings


class AgentService:
    """
    Business service layer for endpoint agent management.
    """

    def __init__(
        self,
        repository: Optional[BaseRepository[AgentResponse]] = None,
        settings: Optional[Settings] = None,
    ):
        self._repository = repository
        self.settings = settings or get_settings()

    @property
    def repository(self) -> BaseRepository[AgentResponse]:
        if self._repository is not None:
            return self._repository
        return get_agent_repository()

    async def register_agent(self, req: AgentRegisterRequest) -> AgentResponse:
        """Registers or updates an endpoint agent."""
        now = time.time()
        existing = await self.repository.get_by_id(req.agent_id)

        registered_at = existing.registered_at if existing else now

        agent = AgentResponse(
            agent_id=req.agent_id,
            hostname=req.hostname,
            os_name=req.os_name,
            os_version=req.os_version,
            agent_version=req.agent_version,
            status="online",
            last_seen=now,
            ip_address=req.ip_address,
            monitored_directories=req.monitored_directories,
            registered_at=registered_at,
        )
        return await self.repository.create(agent)

    async def get_agent(self, agent_id: str) -> Optional[AgentResponse]:
        """Retrieves an agent by ID and checks online/offline timeout status."""
        agent = await self.repository.get_by_id(agent_id)
        if not agent:
            return None

        # Check heartbeat timeout
        timeout = self.settings.agent_heartbeat_timeout_seconds
        now = time.time()
        if (now - agent.last_seen) > timeout and agent.status == "online":
            agent = await self.repository.update(agent_id, {"status": "offline"})

        return agent

    async def list_agents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[AgentResponse]:
        """Lists registered agents with optional status filtering."""
        return await self.repository.list(limit=limit, offset=offset, status=status)

    async def get_agent_status(self, agent_id: str) -> Optional[AgentStatusResponse]:
        """Retrieves real-time status and health metrics for an agent."""
        agent = await self.get_agent(agent_id)
        if not agent:
            return None

        now = time.time()
        is_online = (now - agent.last_seen) <= self.settings.agent_heartbeat_timeout_seconds
        uptime = round(now - agent.registered_at, 2)

        return AgentStatusResponse(
            agent_id=agent.agent_id,
            status=agent.status,
            is_online=is_online,
            last_seen=agent.last_seen,
            uptime_seconds=uptime,
            metrics={"monitored_directories_count": len(agent.monitored_directories)},
        )

    async def update_heartbeat(self, agent_id: str) -> Optional[AgentResponse]:
        """Updates agent last_seen heartbeat timestamp."""
        return await self.repository.update_heartbeat(agent_id)


# Singleton service instance
agent_service = AgentService()


def get_agent_service() -> AgentService:
    return agent_service
