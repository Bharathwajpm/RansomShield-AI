"""
RansomShield AI — Response Policy Engine
Phase 4: Defensive Response & Endpoint Containment

Evaluates alerts, incidents, and threat severity to produce recommended
defensive containment actions according to SOC policy rules.
"""

from typing import List, Dict, Any, Optional

from agent.detection.severity import AlertSeverity, IncidentSeverity
from agent.response.action_models import (
    ResponseAction,
    ResponseActionType,
    RiskLevel,
    ResponseActionStatus,
)


class ResponsePolicyEngine:
    """
    Translates threat detections into standardized, policy-compliant containment actions.
    """

    def __init__(
        self,
        require_approval_for_isolation: bool = True,
        require_approval_for_termination: bool = False,
        dry_run_default: bool = True,
    ):
        self.require_approval_for_isolation = require_approval_for_isolation
        self.require_approval_for_termination = require_approval_for_termination
        self.dry_run_default = dry_run_default

    def evaluate_alert(
        self,
        severity: AlertSeverity,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        file_path: Optional[str] = None,
        sha256: Optional[str] = None,
    ) -> List[ResponseAction]:
        """
        Recommends response actions based on an alert's severity and context.
        """
        actions: List[ResponseAction] = []

        if severity == AlertSeverity.CRITICAL:
            # 1. Terminate offending process immediately
            if pid is not None:
                actions.append(
                    ResponseAction(
                        action_type=ResponseActionType.TERMINATE_PROCESS,
                        target=str(pid),
                        parameters={"pid": pid, "process_name": process_name, "sha256": sha256},
                        risk_level=RiskLevel.CRITICAL,
                        dry_run=self.dry_run_default,
                        requires_approval=self.require_approval_for_termination,
                    )
                )

            # 2. Quarantine ransomware binary / payload
            if file_path:
                actions.append(
                    ResponseAction(
                        action_type=ResponseActionType.QUARANTINE_FILE,
                        target=file_path,
                        parameters={"file_path": file_path, "expected_sha256": sha256},
                        risk_level=RiskLevel.HIGH,
                        dry_run=self.dry_run_default,
                        requires_approval=False,  # Quarantine is non-destructive
                    )
                )

            # 3. Network Isolation recommended for critical incidents
            actions.append(
                ResponseAction(
                    action_type=ResponseActionType.ISOLATE_NETWORK,
                    target="endpoint",
                    parameters={"reason": "Critical ransomware infection detected."},
                    risk_level=RiskLevel.CRITICAL,
                    dry_run=self.dry_run_default,
                    requires_approval=self.require_approval_for_isolation,
                )
            )

        elif severity == AlertSeverity.HIGH:
            if file_path:
                actions.append(
                    ResponseAction(
                        action_type=ResponseActionType.QUARANTINE_FILE,
                        target=file_path,
                        parameters={"file_path": file_path, "expected_sha256": sha256},
                        risk_level=RiskLevel.HIGH,
                        dry_run=self.dry_run_default,
                        requires_approval=False,
                    )
                )
            if pid is not None:
                actions.append(
                    ResponseAction(
                        action_type=ResponseActionType.TERMINATE_PROCESS,
                        target=str(pid),
                        parameters={"pid": pid, "process_name": process_name, "sha256": sha256},
                        risk_level=RiskLevel.HIGH,
                        dry_run=self.dry_run_default,
                        requires_approval=True,
                    )
                )

        elif severity == AlertSeverity.MEDIUM:
            if file_path:
                actions.append(
                    ResponseAction(
                        action_type=ResponseActionType.QUARANTINE_FILE,
                        target=file_path,
                        parameters={"file_path": file_path, "expected_sha256": sha256},
                        risk_level=RiskLevel.MEDIUM,
                        dry_run=self.dry_run_default,
                        requires_approval=True,
                    )
                )

        return actions
