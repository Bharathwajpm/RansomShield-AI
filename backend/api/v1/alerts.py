"""
RansomShield AI — Alerts API Endpoints
Phase 3A: Backend Foundation

Handles querying detection alerts, analyst acknowledgements, and alert resolution.
"""

from typing import List, Optional
from fastapi import APIRouter, Request, HTTPException, Query, status, Depends

from backend.schemas.common import ResponseEnvelope
from backend.schemas.alert import AlertResponse, AlertAcknowledgeRequest, AlertResolveRequest
from backend.services.alert_service import AlertService, get_alert_service
from backend.auth.dependencies import verify_agent_auth
from backend.ws.manager import ws_manager

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.post("", response_model=ResponseEnvelope[AlertResponse], status_code=status.HTTP_201_CREATED)
async def ingest_alert(
    req: AlertResponse,
    request: Request,
    _auth: bool = Depends(verify_agent_auth),
) -> ResponseEnvelope[AlertResponse]:
    """Ingests or updates a detection alert from an endpoint agent."""
    service = get_alert_service()
    alert = await service.save_alert(req)

    try:
        await ws_manager.broadcast("alert.created", alert.model_dump(mode="json"))
    except Exception:
        pass

    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=alert, request_id=req_id)


@router.get("", response_model=ResponseEnvelope[List[AlertResponse]])
async def list_alerts(
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max alerts to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    status: Optional[str] = Query(None, description="Filter by status (ACTIVE/ACKNOWLEDGED/RESOLVED/SUPPRESSED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (INFO/LOW/MEDIUM/HIGH/CRITICAL)"),
    endpoint_id: Optional[str] = Query(None, description="Filter by endpoint ID"),
) -> ResponseEnvelope[List[AlertResponse]]:
    """Lists detection alerts with optional filtering."""
    service = get_alert_service()
    alerts = await service.list_alerts(
        limit=limit,
        offset=offset,
        status=status,
        severity=severity,
        endpoint_id=endpoint_id,
    )
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(
        success=True,
        data=alerts,
        meta={"count": len(alerts), "limit": limit, "offset": offset},
        request_id=req_id,
    )


@router.get("/{alert_id}", response_model=ResponseEnvelope[AlertResponse])
async def get_alert(alert_id: str, request: Request) -> ResponseEnvelope[AlertResponse]:
    """Retrieves a single alert by ID."""
    service = get_alert_service()
    alert = await service.get_alert(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=alert, request_id=req_id)


@router.patch("/{alert_id}/acknowledge", response_model=ResponseEnvelope[AlertResponse])
async def acknowledge_alert(
    alert_id: str,
    request: Request,
    req: Optional[AlertAcknowledgeRequest] = None,
) -> ResponseEnvelope[AlertResponse]:
    """Acknowledges an active alert."""
    service = get_alert_service()
    alert = await service.acknowledge_alert(alert_id, req)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    try:
        await ws_manager.broadcast("alert.updated", alert.model_dump(mode="json"))
    except Exception:
        pass
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=alert, request_id=req_id)


@router.patch("/{alert_id}/resolve", response_model=ResponseEnvelope[AlertResponse])
async def resolve_alert(
    alert_id: str,
    request: Request,
    req: Optional[AlertResolveRequest] = None,
) -> ResponseEnvelope[AlertResponse]:
    """Resolves an alert."""
    service = get_alert_service()
    alert = await service.resolve_alert(alert_id, req)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    try:
        await ws_manager.broadcast("alert.updated", alert.model_dump(mode="json"))
    except Exception:
        pass
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=alert, request_id=req_id)
