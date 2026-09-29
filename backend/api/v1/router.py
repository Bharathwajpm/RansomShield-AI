"""
RansomShield AI — API v1 Master Router
Phase 3A: Backend Foundation

Aggregates all API v1 domain subrouters.
"""

from fastapi import APIRouter

from backend.api.v1.health import router as health_router
from backend.api.v1.auth import router as auth_router
from backend.api.v1.ws import router as ws_router
from backend.api.v1.agents import router as agents_router
from backend.api.v1.alerts import router as alerts_router
from backend.api.v1.incidents import router as incidents_router
from backend.api.v1.detections import router as detections_router
from backend.api.v1.response import router as response_router

api_v1_router = APIRouter()

api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(ws_router)
api_v1_router.include_router(agents_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(detections_router)
api_v1_router.include_router(response_router)
