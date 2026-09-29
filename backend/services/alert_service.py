"""
RansomShield AI — Alert Service
Phase 3A: Backend Foundation

Encapsulates business logic for detection alert retrieval, acknowledgement, and resolution.
"""

import time
from typing import List, Optional, Dict, Any

from backend.schemas.alert import AlertResponse, AlertAcknowledgeRequest, AlertResolveRequest
from backend.repositories.base import BaseRepository
from backend.repositories import get_alert_repository


class AlertService:
    """
    Business service layer for detection alerts.
    """

    def __init__(self, repository: Optional[BaseRepository[AlertResponse]] = None):
        self._repository = repository

    @property
    def repository(self) -> BaseRepository[AlertResponse]:
        if self._repository is not None:
            return self._repository
        return get_alert_repository()

    async def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        endpoint_id: Optional[str] = None,
    ) -> List[AlertResponse]:
        """Lists alerts matching optional filters."""
        return await self.repository.list(
            limit=limit,
            offset=offset,
            status=status,
            severity=severity,
            endpoint_id=endpoint_id,
        )

    async def get_alert(self, alert_id: str) -> Optional[AlertResponse]:
        """Retrieves an alert by ID."""
        return await self.repository.get_by_id(alert_id)

    async def acknowledge_alert(
        self,
        alert_id: str,
        req: Optional[AlertAcknowledgeRequest] = None,
    ) -> Optional[AlertResponse]:
        """Acknowledges an active alert."""
        alert = await self.get_alert(alert_id)
        if not alert:
            return None

        now = time.time()
        updates = {
            "status": "ACKNOWLEDGED",
            "updated_at": now,
        }
        return await self.repository.update(alert_id, updates)

    async def resolve_alert(
        self,
        alert_id: str,
        req: Optional[AlertResolveRequest] = None,
    ) -> Optional[AlertResponse]:
        """Resolves an alert."""
        alert = await self.get_alert(alert_id)
        if not alert:
            return None

        now = time.time()
        updates = {
            "status": "RESOLVED",
            "updated_at": now,
        }
        return await self.repository.update(alert_id, updates)

    async def save_alert(self, alert: AlertResponse) -> AlertResponse:
        """Stores a new or updated alert."""
        return await self.repository.create(alert)


# Singleton service instance
alert_service = AlertService()


def get_alert_service() -> AlertService:
    return alert_service
