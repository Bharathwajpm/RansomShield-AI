"""
RansomShield AI — Response & Containment Action Models
Phase 4: Defensive Response & Endpoint Containment

Defines strongly-typed schemas and status lifecycle for defensive containment
actions including process termination, safe file quarantine, and reversible
network isolation.
"""

import time
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


class ResponseActionType(str, Enum):
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    ISOLATE_NETWORK = "ISOLATE_NETWORK"
    RELEASE_NETWORK_ISOLATION = "RELEASE_NETWORK_ISOLATION"


class ResponseActionStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REFUSED = "REFUSED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"
    VERIFIED_FAILURE = "VERIFIED_FAILURE"


@dataclass
class ActionResult:
    status: ResponseActionStatus
    verification_status: VerificationStatus
    execution_time_ms: float = 0.0
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "verification_status": self.verification_status.value,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ResponseAction:
    action_type: ResponseActionType
    target: str
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parameters: Dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    dry_run: bool = True
    requires_approval: bool = False
    created_by: str = "system"
    approved_by: Optional[str] = None
    status: ResponseActionStatus = ResponseActionStatus.PENDING
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    created_at: float = field(default_factory=time.time)
    executed_at: Optional[float] = None
    result: Optional[ActionResult] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "target": self.target,
            "parameters": self.parameters,
            "risk_level": self.risk_level.value,
            "dry_run": self.dry_run,
            "requires_approval": self.requires_approval,
            "created_by": self.created_by,
            "approved_by": self.approved_by,
            "status": self.status.value,
            "verification_status": self.verification_status.value,
            "created_at": self.created_at,
            "executed_at": self.executed_at,
            "error_message": self.error_message,
        }
        if self.result:
            data["result"] = self.result.to_dict()
        else:
            data["result"] = None
        return data
