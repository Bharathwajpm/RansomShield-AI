"""
RansomShield AI — Defensive Response Engine
Phase 4: Defensive Response & Endpoint Containment

Coordinates defensive containment execution across process termination,
cryptographic file quarantine, and reversible network isolation.
"""

import time
import logging
from typing import Dict, Any, List, Optional

from agent.response.action_models import (
    ResponseAction,
    ActionResult,
    ResponseActionType,
    ResponseActionStatus,
    VerificationStatus,
)
from agent.response.process_response import ProcessResponseHandler
from agent.response.file_quarantine import FileQuarantineHandler
from agent.response.network_isolation import NetworkIsolationHandler
from agent.response.action_policy import ResponsePolicyEngine

logger = logging.getLogger("RansomShield.ResponseEngine")


class ResponseEngine:
    """
    Central orchestrator for defensive containment actions on the endpoint.
    """

    def __init__(
        self,
        dry_run: bool = True,
        quarantine_dir: str = "data/quarantine",
        backend_host: str = "127.0.0.1",
        backend_port: int = 8000,
        require_approval_for_isolation: bool = True,
    ):
        self.dry_run = dry_run
        self.quarantine_dir = quarantine_dir
        self.backend_host = backend_host
        self.backend_port = backend_port

        self.process_handler = ProcessResponseHandler(dry_run=dry_run)
        self.quarantine_handler = FileQuarantineHandler(quarantine_dir=quarantine_dir, dry_run=dry_run)
        self.network_handler = NetworkIsolationHandler(dry_run=dry_run)
        self.policy_engine = ResponsePolicyEngine(
            require_approval_for_isolation=require_approval_for_isolation,
            dry_run_default=dry_run,
        )

        self._action_history: Dict[str, ResponseAction] = {}

    def get_action(self, action_id: str) -> Optional[ResponseAction]:
        """Retrieves an action by ID from local history."""
        return self._action_history.get(action_id)

    def list_actions(self) -> List[ResponseAction]:
        """Returns all executed or recorded actions sorted by creation time descending."""
        return sorted(self._action_history.values(), key=lambda a: a.created_at, reverse=True)

    def execute_action(self, action: ResponseAction) -> ActionResult:
        """
        Executes a containment action with full safety verification and audit tracking.
        """
        # Step 1: Check approval constraint
        if action.requires_approval and action.status != ResponseActionStatus.APPROVED:
            action.status = ResponseActionStatus.PENDING
            result = ActionResult(
                status=ResponseActionStatus.PENDING,
                verification_status=VerificationStatus.UNVERIFIED,
                message=f"Action '{action.action_type.value}' requires prior approval before execution.",
            )
            action.result = result
            self._action_history[action.action_id] = action
            logger.info(f"[RESPONSE_PENDING] Action {action.action_id} awaiting approval.")
            return result

        action.status = ResponseActionStatus.IN_PROGRESS
        action.executed_at = time.time()
        effective_dry_run = action.dry_run if action.dry_run is not None else self.dry_run

        logger.info(
            f"[RESPONSE_EXECUTION_START] Executing {action.action_type.value} on '{action.target}' (dry_run={effective_dry_run})"
        )

        try:
            if action.action_type == ResponseActionType.TERMINATE_PROCESS:
                pid = int(action.parameters.get("pid") or action.target)
                expected_proc = action.parameters.get("process_name")
                expected_hash = action.parameters.get("sha256")
                result = self.process_handler.terminate_process(
                    pid=pid,
                    expected_process_name=expected_proc,
                    expected_sha256=expected_hash,
                    dry_run=effective_dry_run,
                )

            elif action.action_type == ResponseActionType.QUARANTINE_FILE:
                file_path = action.parameters.get("file_path") or action.target
                expected_hash = action.parameters.get("expected_sha256") or action.parameters.get("sha256")
                result = self.quarantine_handler.quarantine_file(
                    file_path=file_path,
                    action_id=action.action_id,
                    expected_sha256=expected_hash,
                    dry_run=effective_dry_run,
                )

            elif action.action_type == ResponseActionType.ISOLATE_NETWORK:
                b_host = action.parameters.get("backend_host", self.backend_host)
                b_port = int(action.parameters.get("backend_port", self.backend_port))
                result = self.network_handler.isolate_network(
                    backend_host=b_host,
                    backend_port=b_port,
                    dry_run=effective_dry_run,
                )

            elif action.action_type == ResponseActionType.RELEASE_NETWORK_ISOLATION:
                result = self.network_handler.release_isolation(
                    dry_run=effective_dry_run,
                )

            else:
                result = ActionResult(
                    status=ResponseActionStatus.FAILED,
                    verification_status=VerificationStatus.VERIFIED_FAILURE,
                    message=f"Unknown response action type: {action.action_type}",
                )

        except Exception as e:
            logger.exception(f"Unexpected error executing {action.action_type}: {e}")
            result = ActionResult(
                status=ResponseActionStatus.FAILED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                message=f"Execution error: {e}",
                details={"error": str(e)},
            )

        # Update action state
        action.status = result.status
        action.verification_status = result.verification_status
        action.result = result
        if result.status == ResponseActionStatus.FAILED:
            action.error_message = result.message

        self._action_history[action.action_id] = action

        logger.info(
            f"[RESPONSE_EXECUTION_END] Action {action.action_id} completed with status {result.status.value} "
            f"(verification: {result.verification_status.value}, duration: {result.execution_time_ms:.2f}ms)"
        )
        return result
