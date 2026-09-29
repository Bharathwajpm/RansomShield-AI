"""
RansomShield AI — Defensive Response Service
Phase 4: Defensive Response & Endpoint Containment

Coordinates defensive containment orchestration, server-side RBAC validation,
two-person approval enforcement, dry-run safety execution, post-action verification,
immutable audit logging, and WebSocket broadcasting.
"""

import time
import uuid
import logging
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status

from backend.schemas.response import (
    ResponseActionCreate,
    ResponseActionResponse,
    ActionResultSchema,
    ResponseAuditLog,
    ResponseActionStatus,
    ResponseActionType,
    RiskLevel,
    VerificationStatus,
)
from backend.schemas.user import UserResponse, UserRole
from backend.repositories.base import BaseRepository
from backend.repositories.factory import (
    get_response_repository,
    get_response_audit_repository,
)
from backend.config.settings import get_settings, Settings
from backend.ws.manager import ws_manager

from agent.response.action_models import (
    ResponseAction as AgentResponseAction,
    ResponseActionType as AgentActionType,
    ResponseActionStatus as AgentActionStatus,
    RiskLevel as AgentRiskLevel,
    VerificationStatus as AgentVerificationStatus,
)
from agent.response.response_engine import ResponseEngine

logger = logging.getLogger("RansomShield.ResponseService")


class ResponseService:
    """
    Orchestration service for endpoint containment actions and SOC governance.
    """

    def __init__(
        self,
        repository: Optional[BaseRepository[ResponseActionResponse]] = None,
        audit_repository: Optional[Any] = None,
        settings: Optional[Settings] = None,
    ):
        self._repo = repository
        self._audit_repo = audit_repository
        self._settings = settings

    @property
    def repo(self) -> BaseRepository[ResponseActionResponse]:
        return self._repo or get_response_repository()

    @property
    def audit_repo(self) -> Any:
        return self._audit_repo or get_response_audit_repository()

    @property
    def settings(self) -> Settings:
        return self._settings or get_settings()

    async def create_action(
        self,
        payload: ResponseActionCreate,
        current_user: UserResponse,
    ) -> ResponseActionResponse:
        """
        Validates, persists, and conditionally dispatches a containment action.
        """
        # RBAC Check: Only ADMIN and ANALYST can initiate response actions
        if current_user.role == UserRole.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Viewers cannot create or execute response actions.",
            )

        # Determine whether approval is required by policy
        requires_approval = payload.requires_approval
        if self.settings.require_two_person_approval:
            if payload.action_type == ResponseActionType.ISOLATE_NETWORK:
                requires_approval = True
            elif payload.risk_level == RiskLevel.CRITICAL and current_user.role != UserRole.ADMIN:
                requires_approval = True

        action_id = str(uuid.uuid4())
        initial_status = ResponseActionStatus.PENDING if requires_approval else ResponseActionStatus.APPROVED

        effective_dry_run = payload.dry_run
        if self.settings.response_dry_run:
            effective_dry_run = True

        action = ResponseActionResponse(
            action_id=action_id,
            agent_id=payload.agent_id,
            action_type=payload.action_type,
            target=payload.target,
            parameters=payload.parameters,
            risk_level=payload.risk_level,
            dry_run=effective_dry_run,
            requires_approval=requires_approval,
            created_by=current_user.username,
            status=initial_status,
            verification_status=VerificationStatus.UNVERIFIED,
            created_at=time.time(),
        )

        # Persist action
        saved_action = await self.repo.create(action)

        # Audit Log
        audit_entry = ResponseAuditLog(
            action_id=action.action_id,
            agent_id=action.agent_id,
            action_type=action.action_type.value,
            actor=current_user.username,
            event="CREATED",
            details={
                "target": action.target,
                "risk_level": action.risk_level.value,
                "requires_approval": requires_approval,
                "dry_run": action.dry_run,
            },
            timestamp=time.time(),
        )
        await self.audit_repo.create(audit_entry)

        # Real-time WebSocket broadcast
        try:
            await ws_manager.broadcast("response.created", saved_action.model_dump())
        except Exception as e:
            logger.warning(f"Error broadcasting response.created: {e}")

        # If no approval needed and auto_execute requested, execute immediately
        if not requires_approval and payload.auto_execute:
            return await self._execute_action(saved_action, actor=current_user.username)

        return saved_action

    async def get_action(self, action_id: str) -> ResponseActionResponse:
        """Retrieves a response action by ID or raises 404."""
        action = await self.repo.get_by_id(action_id)
        if not action:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Response action '{action_id}' not found.",
            )
        return action

    async def list_actions(
        self,
        limit: int = 50,
        offset: int = 0,
        status_filter: Optional[str] = None,
        type_filter: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> List[ResponseActionResponse]:
        """Lists response actions with filtering."""
        return await self.repo.list(
            limit=limit,
            offset=offset,
            status=status_filter,
            action_type=type_filter,
            agent_id=agent_id,
        )

    async def approve_action(
        self,
        action_id: str,
        approver: UserResponse,
        notes: Optional[str] = None,
    ) -> ResponseActionResponse:
        """
        Approves a pending response action, enforcing the two-person rule.
        """
        if approver.role == UserRole.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Viewers cannot approve containment actions.",
            )

        action = await self.get_action(action_id)
        if action.status != ResponseActionStatus.PENDING:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Action '{action_id}' is not pending approval (current status: {action.status.value}).",
            )

        # Two-person approval check: Creator cannot approve their own high-risk action
        if self.settings.require_two_person_approval and action.requires_approval:
            if approver.username == action.created_by:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Two-person rule violation: You cannot approve an action that you created.",
                )

        # Update action to APPROVED
        action.status = ResponseActionStatus.APPROVED
        action.approved_by = approver.username
        await self.repo.update(action_id, {
            "status": ResponseActionStatus.APPROVED.value,
            "approved_by": approver.username,
        })

        # Record audit log
        audit_entry = ResponseAuditLog(
            action_id=action.action_id,
            agent_id=action.agent_id,
            action_type=action.action_type.value,
            actor=approver.username,
            event="APPROVED",
            details={"notes": notes},
            timestamp=time.time(),
        )
        await self.audit_repo.create(audit_entry)

        # Execute approved action
        return await self._execute_action(action, actor=approver.username)

    async def cancel_action(
        self,
        action_id: str,
        actor: UserResponse,
        reason: Optional[str] = None,
    ) -> ResponseActionResponse:
        """Cancels a pending response action."""
        if actor.role == UserRole.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Viewers cannot cancel containment actions.",
            )

        action = await self.get_action(action_id)
        if action.status in (ResponseActionStatus.SUCCESS, ResponseActionStatus.IN_PROGRESS):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel action '{action_id}' in state {action.status.value}.",
            )

        action.status = ResponseActionStatus.CANCELLED
        await self.repo.update(action_id, {"status": ResponseActionStatus.CANCELLED.value})

        # Record audit log
        audit_entry = ResponseAuditLog(
            action_id=action.action_id,
            agent_id=action.agent_id,
            action_type=action.action_type.value,
            actor=actor.username,
            event="CANCELLED",
            details={"reason": reason},
            timestamp=time.time(),
        )
        await self.audit_repo.create(audit_entry)

        try:
            await ws_manager.broadcast("response.updated", action.model_dump())
        except Exception as e:
            logger.warning(f"Error broadcasting response.updated: {e}")

        return action

    async def retry_action(
        self,
        action_id: str,
        actor: UserResponse,
    ) -> ResponseActionResponse:
        """Retries a failed or refused response action."""
        if actor.role == UserRole.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Viewers cannot retry containment actions.",
            )

        action = await self.get_action(action_id)
        if action.status not in (ResponseActionStatus.FAILED, ResponseActionStatus.REFUSED, ResponseActionStatus.CANCELLED):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Action '{action_id}' in state {action.status.value} is not eligible for retry.",
            )

        # Reset status and re-execute
        action.status = ResponseActionStatus.APPROVED
        await self.repo.update(action_id, {
            "status": ResponseActionStatus.APPROVED.value,
            "error_message": None,
        })

        audit_entry = ResponseAuditLog(
            action_id=action.action_id,
            agent_id=action.agent_id,
            action_type=action.action_type.value,
            actor=actor.username,
            event="RETRIED",
            details={},
            timestamp=time.time(),
        )
        await self.audit_repo.create(audit_entry)

        return await self._execute_action(action, actor=actor.username)

    async def _execute_action(
        self,
        action: ResponseActionResponse,
        actor: str,
    ) -> ResponseActionResponse:
        """
        Executes action via endpoint response engine, captures verification,
        and logs audit trail.
        """
        action.status = ResponseActionStatus.IN_PROGRESS
        action.executed_at = time.time()
        await self.repo.update(action.action_id, {
            "status": ResponseActionStatus.IN_PROGRESS.value,
            "executed_at": action.executed_at,
        })

        # Instantiate endpoint response engine
        engine = ResponseEngine(
            dry_run=action.dry_run,
            quarantine_dir=self.settings.quarantine_directory,
            require_approval_for_isolation=self.settings.require_two_person_approval,
        )

        agent_action = AgentResponseAction(
            action_id=action.action_id,
            action_type=AgentActionType(action.action_type.value),
            target=action.target,
            parameters=action.parameters,
            risk_level=AgentRiskLevel(action.risk_level.value),
            dry_run=action.dry_run,
            requires_approval=False,  # Already approved by service
            status=AgentActionStatus.APPROVED,
            created_by=action.created_by,
            approved_by=action.approved_by or actor,
        )

        exec_result = engine.execute_action(agent_action)

        # Convert back to schema result
        result_schema = ActionResultSchema(
            status=ResponseActionStatus(exec_result.status.value),
            verification_status=VerificationStatus(exec_result.verification_status.value),
            execution_time_ms=exec_result.execution_time_ms,
            message=exec_result.message,
            details=exec_result.details,
        )

        action.status = result_schema.status
        action.verification_status = result_schema.verification_status
        action.result = result_schema
        if result_schema.status in (ResponseActionStatus.FAILED, ResponseActionStatus.REFUSED):
            action.error_message = result_schema.message

        # Persist final state
        await self.repo.update(action.action_id, {
            "status": action.status.value,
            "verification_status": action.verification_status.value,
            "result": result_schema.model_dump(),
            "error_message": action.error_message,
        })

        # Append to audit trail
        audit_entry = ResponseAuditLog(
            action_id=action.action_id,
            agent_id=action.agent_id,
            action_type=action.action_type.value,
            actor=actor,
            event="EXECUTED",
            details=result_schema.model_dump(),
            timestamp=time.time(),
        )
        await self.audit_repo.create(audit_entry)

        # Broadcast update to SOC dashboard
        try:
            await ws_manager.broadcast("response.updated", action.model_dump())
        except Exception as e:
            logger.warning(f"Error broadcasting response.updated: {e}")

        return action

    async def get_audit_logs(
        self,
        action_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ResponseAuditLog]:
        """Fetches audit logs for a specific action or globally."""
        if action_id:
            return await self.audit_repo.list_by_action(action_id)
        return await self.audit_repo.list_all(limit=limit, offset=offset, agent_id=agent_id)


# Singleton instance
response_service = ResponseService()
