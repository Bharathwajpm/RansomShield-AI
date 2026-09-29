"""
RansomShield AI — Response & Containment Endpoints
Phase 4: Defensive Response & Endpoint Containment

REST APIs for triggering, approving, querying, and auditing defensive response actions.
Enforces strict server-side RBAC (ADMIN and ANALYST allowed; VIEWER 403 Forbidden).
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Path, status

from backend.schemas.response import (
    ResponseActionCreate,
    ResponseActionResponse,
    ResponseActionApproval,
    ResponseActionCancel,
    ResponseAuditLog,
    ResponseActionStatus,
    ResponseActionType,
)
from backend.schemas.user import UserResponse, UserRole
from backend.auth.dependencies import get_current_user, require_roles
from backend.services.response_service import response_service

router = APIRouter(prefix="/response", tags=["Response & Containment"])


@router.post(
    "/actions",
    response_model=ResponseActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create defensive containment action",
)
async def create_response_action(
    payload: ResponseActionCreate,
    current_user: UserResponse = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Creates and initiates a defensive containment action.
    Requires ADMIN or ANALYST role. Rejects VIEWER with HTTP 403.
    """
    return await response_service.create_action(payload=payload, current_user=current_user)


@router.get(
    "/actions",
    response_model=List[ResponseActionResponse],
    summary="List defensive containment actions",
)
async def list_response_actions(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None),
    action_type: Optional[str] = Query(default=None),
    agent_id: Optional[str] = Query(default=None),
    current_user: UserResponse = Depends(get_current_user),
):
    """
    Lists recorded containment actions with optional filtering.
    Accessible to all authenticated users (ADMIN, ANALYST, VIEWER).
    """
    return await response_service.list_actions(
        limit=limit,
        offset=offset,
        status_filter=status,
        type_filter=action_type,
        agent_id=agent_id,
    )


@router.get(
    "/actions/{action_id}",
    response_model=ResponseActionResponse,
    summary="Get containment action details",
)
async def get_response_action(
    action_id: str = Path(..., description="Action ID"),
    current_user: UserResponse = Depends(get_current_user),
):
    """
    Retrieves full details of a containment action.
    """
    return await response_service.get_action(action_id=action_id)


@router.post(
    "/actions/{action_id}/approve",
    response_model=ResponseActionResponse,
    summary="Approve pending containment action",
)
async def approve_response_action(
    action_id: str = Path(...),
    body: Optional[ResponseActionApproval] = None,
    current_user: UserResponse = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Approves a pending containment action and triggers execution.
    Enforces the two-person approval rule: creator cannot approve their own action.
    """
    notes = body.notes if body else None
    return await response_service.approve_action(action_id=action_id, approver=current_user, notes=notes)


@router.post(
    "/actions/{action_id}/cancel",
    response_model=ResponseActionResponse,
    summary="Cancel pending containment action",
)
async def cancel_response_action(
    action_id: str = Path(...),
    body: Optional[ResponseActionCancel] = None,
    current_user: UserResponse = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Cancels a pending containment action.
    """
    reason = body.reason if body else None
    return await response_service.cancel_action(action_id=action_id, actor=current_user, reason=reason)


@router.post(
    "/actions/{action_id}/retry",
    response_model=ResponseActionResponse,
    summary="Retry failed containment action",
)
async def retry_response_action(
    action_id: str = Path(...),
    current_user: UserResponse = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Retries execution of a failed, refused, or cancelled containment action.
    """
    return await response_service.retry_action(action_id=action_id, actor=current_user)


@router.get(
    "/actions/{action_id}/audit",
    response_model=List[ResponseAuditLog],
    summary="Get action audit log trail",
)
async def get_action_audit_trail(
    action_id: str = Path(...),
    current_user: UserResponse = Depends(get_current_user),
):
    """
    Returns the immutable audit log entries associated with a specific action.
    """
    return await response_service.get_audit_logs(action_id=action_id)


@router.get(
    "/audit",
    response_model=List[ResponseAuditLog],
    summary="Get global response audit log",
)
async def get_global_response_audit(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    agent_id: Optional[str] = Query(default=None),
    current_user: UserResponse = Depends(get_current_user),
):
    """
    Queries the global immutable audit log of all response actions.
    """
    return await response_service.get_audit_logs(agent_id=agent_id, limit=limit, offset=offset)
