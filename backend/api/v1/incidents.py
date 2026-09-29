"""
RansomShield AI — Incidents API Endpoints
Phase 3A: Backend Foundation

Handles querying correlated security incidents, analyst acknowledgements,
resolutions, and false positive categorizations.
"""

from typing import List, Optional
from fastapi import APIRouter, Request, HTTPException, Query, status, Depends

from backend.schemas.common import ResponseEnvelope
from backend.schemas.incident import (
    IncidentResponse,
    IncidentAcknowledgeRequest,
    IncidentResolveRequest,
    IncidentFalsePositiveRequest,
)
from backend.services.incident_service import IncidentService, get_incident_service
from backend.auth.dependencies import verify_agent_auth
from backend.ws.manager import ws_manager

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.post("", response_model=ResponseEnvelope[IncidentResponse], status_code=status.HTTP_201_CREATED)
async def ingest_incident(
    req: IncidentResponse,
    request: Request,
    _auth: bool = Depends(verify_agent_auth),
) -> ResponseEnvelope[IncidentResponse]:
    """Ingests or updates a correlated security incident from an endpoint agent."""
    service = get_incident_service()
    incident = await service.save_incident(req)

    try:
        await ws_manager.broadcast("incident.created", incident.model_dump(mode="json"))
    except Exception:
        pass

    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=incident, request_id=req_id)


@router.get("", response_model=ResponseEnvelope[List[IncidentResponse]])
async def list_incidents(
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max incidents to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    status: Optional[str] = Query(None, description="Filter by status (OPEN/ACKNOWLEDGED/RESOLVED/FALSE_POSITIVE)"),
    severity: Optional[str] = Query(None, description="Filter by severity (INFO/LOW/MEDIUM/HIGH/CRITICAL)"),
    endpoint_id: Optional[str] = Query(None, description="Filter by endpoint ID"),
) -> ResponseEnvelope[List[IncidentResponse]]:
    """Lists security incidents with optional filtering."""
    service = get_incident_service()
    incidents = await service.list_incidents(
        limit=limit,
        offset=offset,
        status=status,
        severity=severity,
        endpoint_id=endpoint_id,
    )
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(
        success=True,
        data=incidents,
        meta={"count": len(incidents), "limit": limit, "offset": offset},
        request_id=req_id,
    )


@router.get("/{incident_id}", response_model=ResponseEnvelope[IncidentResponse])
async def get_incident(incident_id: str, request: Request) -> ResponseEnvelope[IncidentResponse]:
    """Retrieves a single security incident by ID."""
    service = get_incident_service()
    inc = await service.get_incident(incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=inc, request_id=req_id)


@router.patch("/{incident_id}/acknowledge", response_model=ResponseEnvelope[IncidentResponse])
async def acknowledge_incident(
    incident_id: str,
    request: Request,
    req: Optional[IncidentAcknowledgeRequest] = None,
) -> ResponseEnvelope[IncidentResponse]:
    """Acknowledges an open security incident."""
    service = get_incident_service()
    inc = await service.acknowledge_incident(incident_id, req)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    try:
        await ws_manager.broadcast("incident.updated", inc.model_dump(mode="json"))
    except Exception:
        pass
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=inc, request_id=req_id)


@router.patch("/{incident_id}/resolve", response_model=ResponseEnvelope[IncidentResponse])
async def resolve_incident(
    incident_id: str,
    request: Request,
    req: Optional[IncidentResolveRequest] = None,
) -> ResponseEnvelope[IncidentResponse]:
    """Resolves an active security incident."""
    service = get_incident_service()
    inc = await service.resolve_incident(incident_id, req)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    try:
        await ws_manager.broadcast("incident.updated", inc.model_dump(mode="json"))
    except Exception:
        pass
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=inc, request_id=req_id)


@router.patch("/{incident_id}/false-positive", response_model=ResponseEnvelope[IncidentResponse])
async def mark_false_positive(
    incident_id: str,
    request: Request,
    req: Optional[IncidentFalsePositiveRequest] = None,
) -> ResponseEnvelope[IncidentResponse]:
    """Marks an incident as a false positive."""
    service = get_incident_service()
    inc = await service.mark_false_positive(incident_id, req)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    try:
        await ws_manager.broadcast("incident.updated", inc.model_dump(mode="json"))
    except Exception:
        pass
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=inc, request_id=req_id)
