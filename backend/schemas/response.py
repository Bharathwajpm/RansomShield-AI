"""
RansomShield AI — Response Action & Audit Schemas
Phase 4: Defensive Response & Endpoint Containment

Pydantic schemas for API request validation, response serialization,
approval workflows, and immutable audit logs.
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator


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


class ActionResultSchema(BaseModel):
    status: ResponseActionStatus
    verification_status: VerificationStatus
    execution_time_ms: float = 0.0
    message: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


class ResponseActionCreate(BaseModel):
    action_type: ResponseActionType
    target: str = Field(..., description="Target process PID, file path, or 'endpoint'")
    agent_id: str = Field(default="local-agent", description="Target agent ID")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action parameters (e.g. process_name, sha256)")
    risk_level: RiskLevel = Field(default=RiskLevel.MEDIUM, description="Risk severity of action")
    dry_run: bool = Field(default=True, description="Whether to simulate action safely")
    requires_approval: bool = Field(default=False, description="Whether two-person or supervisor approval is required")
    auto_execute: bool = Field(default=True, description="Execute immediately if approval is not required")

    @field_validator("target")
    @classmethod
    def validate_target_safety(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Target must not be empty.")
        raw = v.strip()
        if "\x00" in raw or "\0" in raw:
            raise ValueError("Null bytes are forbidden in target identifier.")
        if raw.startswith(("\\\\", "//")):
            raise ValueError("UNC network share paths are forbidden.")
        if ".." in raw.replace("/", "\\").split("\\"):
            raise ValueError("Directory traversal sequence '..' is forbidden in target.")
        return raw

    @model_validator(mode="after")
    def validate_action_parameters(self) -> "ResponseActionCreate":
        # Additional deep validation for file quarantine parameters
        if self.action_type == ResponseActionType.QUARANTINE_FILE:
            file_path = self.parameters.get("file_path") or self.target
            if file_path:
                raw_path = str(file_path).strip()
                if "\x00" in raw_path or "\0" in raw_path:
                    raise ValueError("Null bytes are forbidden in file_path parameter.")
                if raw_path.startswith(("\\\\", "//")):
                    raise ValueError("UNC network share paths are forbidden in file_path.")
                if ".." in raw_path.replace("/", "\\").split("\\"):
                    raise ValueError("Directory traversal '..' detected in file_path parameter.")

        # Additional validation for process termination
        elif self.action_type == ResponseActionType.TERMINATE_PROCESS:
            pid_val = self.parameters.get("pid") or self.target
            try:
                pid_int = int(pid_val)
                if pid_int < 0:
                    raise ValueError("Process PID cannot be negative.")
            except (ValueError, TypeError):
                pass

        return self


class ResponseActionResponse(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = "local-agent"
    action_type: ResponseActionType
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    dry_run: bool = True
    requires_approval: bool = False
    created_by: str = "system"
    approved_by: Optional[str] = None
    status: ResponseActionStatus = ResponseActionStatus.PENDING
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    created_at: float = Field(default_factory=time.time)
    executed_at: Optional[float] = None
    result: Optional[ActionResultSchema] = None
    error_message: Optional[str] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action_id": "act-12345",
                "agent_id": "win-agent-01",
                "action_type": "TERMINATE_PROCESS",
                "target": "4820",
                "parameters": {"process_name": "wannacry.exe"},
                "risk_level": "CRITICAL",
                "dry_run": True,
                "requires_approval": False,
                "created_by": "admin",
                "status": "SUCCESS",
                "verification_status": "VERIFIED_SUCCESS",
            }
        }
    )


class ResponseActionApproval(BaseModel):
    notes: Optional[str] = Field(default=None, description="Operational justification or approval notes")


class ResponseActionCancel(BaseModel):
    reason: Optional[str] = Field(default=None, description="Reason for cancellation")


class ResponseAuditLog(BaseModel):
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str
    agent_id: str
    action_type: str
    actor: str
    event: str  # CREATED, APPROVED, EXECUTED, CANCELLED, RETRIED
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class ResponseActionFilter(BaseModel):
    agent_id: Optional[str] = None
    status: Optional[ResponseActionStatus] = None
    action_type: Optional[ResponseActionType] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
