"""
RansomShield AI — Common API Schemas
Phase 3A: Backend Foundation

Defines standardized API response envelopes, error structures, health responses,
and pagination parameters.
"""

from typing import Generic, TypeVar, Optional, Any, Dict
from pydantic import BaseModel, Field
import time


T = TypeVar("T")


class ErrorDetail(BaseModel):
    """Detailed error object contained in API error responses."""
    code: str = Field(..., description="Standardized error code string (e.g. ALERT_NOT_FOUND)")
    message: str = Field(..., description="Human-readable explanation of the error")
    request_id: Optional[str] = Field(None, description="Unique correlation ID for tracing the request")
    details: Optional[Any] = Field(None, description="Additional context or validation error details")


class ResponseEnvelope(BaseModel, Generic[T]):
    """Standardized API response envelope wrapping all v1 endpoints."""
    success: bool = Field(True, description="Indicates whether the request completed successfully")
    data: Optional[T] = Field(None, description="Response payload payload if successful")
    error: Optional[ErrorDetail] = Field(None, description="Error detail if request failed")
    meta: Optional[Dict[str, Any]] = Field(None, description="Metadata such as pagination or counts")
    request_id: Optional[str] = Field(None, description="Request tracking ID")


class HealthResponse(BaseModel):
    """API health status response."""
    status: str = Field("ok", description="Overall service status")
    service: str = Field("ransomshield-backend", description="Service identifier")
    version: str = Field("0.1.0", description="Service version")
    timestamp: float = Field(default_factory=time.time, description="Current server UNIX timestamp")
    environment: str = Field("development", description="Deployment environment")


class ReadinessResponse(BaseModel):
    """API readiness status response detailing dependency states."""
    status: str = Field("ready", description="Overall readiness status")
    dependencies: Dict[str, Any] = Field(..., description="Detailed dependency status breakdown")
    timestamp: float = Field(default_factory=time.time, description="Current server UNIX timestamp")
