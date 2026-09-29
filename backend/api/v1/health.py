"""
RansomShield AI — Health & Readiness API Endpoints
Phase 3A: Backend Foundation

Provides liveness and readiness diagnostic probes for container orchestration
and uptime monitoring.
"""

from fastapi import APIRouter, Request
from backend.schemas.common import ResponseEnvelope, HealthResponse, ReadinessResponse
from backend.config.settings import get_settings
from backend.database.mongodb import get_db_manager

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=ResponseEnvelope[HealthResponse])
async def get_health(request: Request) -> ResponseEnvelope[HealthResponse]:
    """Basic service health probe."""
    settings = getattr(request.app.state, "settings", None) or get_settings()
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(
        success=True,
        data=HealthResponse(
            status="ok",
            service="ransomshield-backend",
            version=settings.app_version,
            environment=settings.environment,
        ),
        request_id=req_id,
    )


@router.get("/live", response_model=ResponseEnvelope[dict])
async def get_liveness(request: Request) -> ResponseEnvelope[dict]:
    """Liveness probe verifying that the application is running and responding."""
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(
        success=True,
        data={"status": "alive"},
        request_id=req_id,
    )


@router.get("/ready", response_model=ResponseEnvelope[ReadinessResponse])
async def get_readiness(request: Request) -> ResponseEnvelope[ReadinessResponse]:
    """Readiness probe evaluating operational dependencies."""
    app_settings = getattr(request.app.state, "settings", None)
    db_mgr = get_db_manager(app_settings)
    db_status = await db_mgr.check_connection()
    req_id = getattr(request.state, "request_id", None)

    return ResponseEnvelope(
        success=True,
        data=ReadinessResponse(
            status="ready",
            dependencies={
                "database": db_status,
                "in_memory_store": {"status": "healthy"},
            },
        ),
        request_id=req_id,
    )
