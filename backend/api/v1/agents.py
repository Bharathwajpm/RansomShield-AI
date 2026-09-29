"""
RansomShield AI — Agents API Endpoints
Phase 3A: Backend Foundation

Handles endpoint agent registration, discovery, and diagnostic status querying.
"""

from typing import List, Optional
from fastapi import APIRouter, Request, HTTPException, Query, status, Depends

from backend.schemas.common import ResponseEnvelope
from backend.schemas.agent import AgentRegisterRequest, AgentResponse, AgentStatusResponse
from backend.services.agent_service import AgentService, get_agent_service
from backend.auth.dependencies import verify_agent_auth
from backend.ws.manager import ws_manager

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.post("/register", response_model=ResponseEnvelope[AgentResponse], status_code=status.HTTP_201_CREATED)
async def register_agent(
    req: AgentRegisterRequest,
    request: Request,
    _auth: bool = Depends(verify_agent_auth),
) -> ResponseEnvelope[AgentResponse]:
    """Registers an endpoint agent or refreshes existing agent registration."""
    service = get_agent_service()
    agent = await service.register_agent(req)

    try:
        await ws_manager.broadcast("agent.status_changed", agent.model_dump(mode="json"))
    except Exception:
        pass

    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=agent, request_id=req_id)


@router.get("", response_model=ResponseEnvelope[List[AgentResponse]])
async def list_agents(
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max agents to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    status: Optional[str] = Query(None, description="Filter by status (online/offline)"),
) -> ResponseEnvelope[List[AgentResponse]]:
    """Lists registered endpoint agents."""
    service = get_agent_service()
    agents = await service.list_agents(limit=limit, offset=offset, status=status)
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(
        success=True,
        data=agents,
        meta={"count": len(agents), "limit": limit, "offset": offset},
        request_id=req_id,
    )


@router.get("/{agent_id}", response_model=ResponseEnvelope[AgentResponse])
async def get_agent(agent_id: str, request: Request) -> ResponseEnvelope[AgentResponse]:
    """Retrieves an agent by ID."""
    service = get_agent_service()
    agent = await service.get_agent(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found.",
        )
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=agent, request_id=req_id)


@router.get("/{agent_id}/status", response_model=ResponseEnvelope[AgentStatusResponse])
async def get_agent_status(agent_id: str, request: Request) -> ResponseEnvelope[AgentStatusResponse]:
    """Retrieves real-time diagnostic status for an agent."""
    service = get_agent_service()
    agent_stat = await service.get_agent_status(agent_id)
    if not agent_stat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found.",
        )
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=agent_stat, request_id=req_id)


@router.post("/{agent_id}/heartbeat", response_model=ResponseEnvelope[AgentResponse])
async def update_agent_heartbeat(
    agent_id: str,
    request: Request,
    _auth: bool = Depends(verify_agent_auth),
) -> ResponseEnvelope[AgentResponse]:
    """Updates last_seen heartbeat timestamp for an agent."""
    service = get_agent_service()
    agent = await service.update_heartbeat(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found.",
        )
    try:
        await ws_manager.broadcast("agent.status_changed", agent.model_dump(mode="json"))
    except Exception:
        pass
    req_id = getattr(request.state, "request_id", None)
    return ResponseEnvelope(success=True, data=agent, request_id=req_id)

