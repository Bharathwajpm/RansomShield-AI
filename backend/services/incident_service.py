"""
RansomShield AI — Incident Service
Phase 3A: Backend Foundation

Encapsulates business logic for security incidents, lifecycle state machine
transitions (OPEN -> ACKNOWLEDGED -> RESOLVED / FALSE_POSITIVE), and correlation.
"""

import time
from typing import List, Optional, Dict, Any

from backend.schemas.incident import (
    IncidentResponse,
    IncidentAcknowledgeRequest,
    IncidentResolveRequest,
    IncidentFalsePositiveRequest,
)
from backend.repositories.base import BaseRepository
from backend.repositories import get_incident_repository
from agent.detection.severity import IncidentStatus
from agent.detection.incident_manager import IncidentStateMachine, InvalidStateTransitionError


class IncidentService:
    """
    Business service layer for security incidents.
    """

    def __init__(self, repository: Optional[BaseRepository[IncidentResponse]] = None):
        self._repository = repository

    @property
    def repository(self) -> BaseRepository[IncidentResponse]:
        if self._repository is not None:
            return self._repository
        return get_incident_repository()

    async def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        endpoint_id: Optional[str] = None,
    ) -> List[IncidentResponse]:
        """Lists incidents matching optional filters."""
        return await self.repository.list(
            limit=limit,
            offset=offset,
            status=status,
            severity=severity,
            endpoint_id=endpoint_id,
        )

    async def get_incident(self, incident_id: str) -> Optional[IncidentResponse]:
        """Retrieves an incident by ID."""
        return await self.repository.get_by_id(incident_id)

    async def acknowledge_incident(
        self,
        incident_id: str,
        req: Optional[IncidentAcknowledgeRequest] = None,
    ) -> Optional[IncidentResponse]:
        """Acknowledges an open incident after validating state machine transition."""
        inc = await self.get_incident(incident_id)
        if not inc:
            return None

        current_status = IncidentStatus(inc.status)
        target_status = IncidentStatus.ACKNOWLEDGED
        IncidentStateMachine.validate_transition(current_status, target_status)

        now = time.time()
        updates = {
            "status": "ACKNOWLEDGED",
            "updated_at": now,
        }
        return await self.repository.update(incident_id, updates)

    async def resolve_incident(
        self,
        incident_id: str,
        req: Optional[IncidentResolveRequest] = None,
    ) -> Optional[IncidentResponse]:
        """Resolves an active incident after validating state machine transition."""
        inc = await self.get_incident(incident_id)
        if not inc:
            return None

        current_status = IncidentStatus(inc.status)
        target_status = IncidentStatus.RESOLVED
        IncidentStateMachine.validate_transition(current_status, target_status)

        now = time.time()
        resolution_note = req.resolution_note if (req and req.resolution_note) else "Resolved by analyst."
        updates = {
            "status": "RESOLVED",
            "resolution_note": resolution_note,
            "updated_at": now,
        }
        return await self.repository.update(incident_id, updates)

    async def mark_false_positive(
        self,
        incident_id: str,
        req: Optional[IncidentFalsePositiveRequest] = None,
    ) -> Optional[IncidentResponse]:
        """Marks an incident as false positive after validating state machine transition."""
        inc = await self.get_incident(incident_id)
        if not inc:
            return None

        current_status = IncidentStatus(inc.status)
        target_status = IncidentStatus.FALSE_POSITIVE
        IncidentStateMachine.validate_transition(current_status, target_status)

        now = time.time()
        reason = req.reason if (req and req.reason) else "Marked false positive."
        updates = {
            "status": "FALSE_POSITIVE",
            "resolution_note": f"False Positive: {reason}",
            "updated_at": now,
        }
        return await self.repository.update(incident_id, updates)

    async def save_incident(self, incident: IncidentResponse) -> IncidentResponse:
        """Stores a new or updated incident."""
        return await self.repository.create(incident)


# Singleton service instance
incident_service = IncidentService()


def get_incident_service() -> IncidentService:
    return incident_service
