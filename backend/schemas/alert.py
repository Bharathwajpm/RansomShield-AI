"""
RansomShield AI — Alert API Schemas
Phase 3A: Backend Foundation

Defines Pydantic schemas for detection alerts and lifecycle transitions.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import time


class AlertResponse(BaseModel):
    """Schema representing a detection alert."""
    alert_id: str
    endpoint_id: str
    prediction: str
    confidence: float
    risk_score: int
    severity: str
    status: str
    stage: int = 1
    model_version: str = "xgb_ransomware_v2"
    window_seconds: int = 10
    reason: str = ""
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    suppression_count: int = 0
    incident_id: Optional[str] = None
    created_at: float
    updated_at: float


class AlertAcknowledgeRequest(BaseModel):
    """Payload to acknowledge an alert."""
    note: Optional[str] = Field(None, description="Optional analyst notes")


class AlertResolveRequest(BaseModel):
    """Payload to resolve an alert."""
    resolution_note: Optional[str] = Field(None, description="Resolution rationale or actions taken")
