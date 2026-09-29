"""
RansomShield AI — Detections API Endpoints
Phase 3A: Backend Foundation

Handles ingestion of live Model V2 DetectionResult streams from endpoint agents
and provides query capabilities for historical detection telemetry.
"""

from typing import List, Optional
from fastapi import APIRouter, Request, HTTPException, Query, status, Depends

from backend.schemas.common import ResponseEnvelope
from backend.schemas.detection import DetectionIngestRequest, DetectionResponse
from backend.services.detection_service import DetectionService, get_detection_service
from backend.auth.dependencies import verify_agent_auth
from backend.ws.manager import ws_manager

router = APIRouter(prefix="/detections", tags=["Detections"])


@router.post("", response_model=ResponseEnvelope[DetectionResponse], status_code=status.HTTP_201_CREATED)
async def ingest_detection(
    req: DetectionIngestRequest,
    request: Request,
    _auth: bool = Depends(verify_agent_auth),
) -> ResponseEnvelope[DetectionResponse]:
    """Ingests a live Model V2 DetectionResult from an endpoint agent."""
    service = get_detection_service()
    detection = await service.ingest_detection(req)

    # Safe real-time WebSocket broadcast after successful validation & persistence
    try:
        await ws_manager.broadcast("detection.created", detection.model_dump(mode="json"))
    except Exception:
        pass

    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=detection, request_id=req_id)


@router.get("", response_model=ResponseEnvelope[List[DetectionResponse]])
async def list_detections(
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max detections to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    endpoint_id: Optional[str] = Query(None, description="Filter by endpoint ID"),
    prediction: Optional[str] = Query(None, description="Filter by prediction (Goodware/Ransomware)"),
) -> ResponseEnvelope[List[DetectionResponse]]:
    """Lists ingested live detections."""
    service = get_detection_service()
    detections = await service.list_detections(
        limit=limit,
        offset=offset,
        endpoint_id=endpoint_id,
        prediction=prediction,
    )
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(
        success=True,
        data=detections,
        meta={"count": len(detections), "limit": limit, "offset": offset},
        request_id=req_id,
    )


@router.get("/{detection_id}", response_model=ResponseEnvelope[DetectionResponse])
async def get_detection(detection_id: str, request: Request) -> ResponseEnvelope[DetectionResponse]:
    """Retrieves a single detection by ID."""
    service = get_detection_service()
    detection = await service.get_detection(detection_id)
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection '{detection_id}' not found.",
        )
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=detection, request_id=req_id)
