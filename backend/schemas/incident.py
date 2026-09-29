"""
RansomShield AI — Incident API Schemas
Phase 3A: Backend Foundation

Defines Pydantic schemas for correlated security incidents and state transitions.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import time


class IncidentResponse(BaseModel):
    """Schema representing a correlated security incident."""
    incident_id: str
    endpoint_id: str
    severity: str
    status: str
    alert_ids: List[str] = Field(default_factory=list)
    detection_count: int = 1
    first_detection: float
    last_detection: float
    primary_prediction: str = "Ransomware"
    highest_risk_score: int = 0
    top_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    model_version: str = "xgb_ransomware_v2"
    summary: str = ""
    resolution_note: Optional[str] = None
    created_at: float
    updated_at: float


class IncidentAcknowledgeRequest(BaseModel):
    """Payload to acknowledge an active incident."""
    note: Optional[str] = Field(None, description="SOC analyst acknowledgement note")


class IncidentResolveRequest(BaseModel):
    """Payload to resolve an active incident."""
    resolution_note: Optional[str] = Field(None, description="Resolution report or justification")


class IncidentFalsePositiveRequest(BaseModel):
    """Payload to mark an incident as a false positive."""
    reason: Optional[str] = Field(None, description="False positive justification or whitelist rationale")
