"""
RansomShield AI — Detection API Schemas
Phase 3A: Backend Foundation

Defines Pydantic schemas for ingesting and querying raw live ML DetectionResult records.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import time


class DetectionIngestRequest(BaseModel):
    """Payload sent by an endpoint agent to stream a live Model V2 DetectionResult."""
    detection_id: Optional[str] = Field(None, description="Unique detection identifier for idempotency")
    endpoint_id: str = Field("endpoint-agent-01", description="Endpoint identifier")
    timestamp: float = Field(default_factory=time.time, description="Detection evaluation timestamp")
    window_seconds: int = Field(10, description="Sliding window duration evaluated (5, 10, 30)")
    prediction: str = Field("Goodware", description="Class prediction: Goodware or Ransomware")
    confidence: float = Field(0.0, description="Model confidence percentage (0-100)")
    risk_score: int = Field(0, description="Calibrated risk score (0-100)")
    probabilities: Dict[str, float] = Field(default_factory=dict, description="Class probabilities")
    model_version: str = Field("xgb_ransomware_v2", description="Model version used for inference")
    stage: int = Field(1, description="Detection stage index")
    features: Dict[str, float] = Field(default_factory=dict, description="19 extracted Model V2 features")
    indicators: List[Dict[str, Any]] = Field(default_factory=list, description="TreeSHAP feature attributions")
    explanation: str = Field("", description="Model explanation summary")
    event_count: int = Field(0, description="Number of telemetry events evaluated in window")
    duration_ms: float = Field(0.0, description="Inference latency in milliseconds")


class DetectionResponse(BaseModel):
    """Stored detection record."""
    detection_id: str
    endpoint_id: str
    timestamp: float
    window_seconds: int = 10
    prediction: str = "Goodware"
    confidence: float = 0.0
    risk_score: int = 0
    probabilities: Dict[str, float] = Field(default_factory=dict)
    model_version: str = "xgb_ransomware_v2"
    stage: int = 1
    features: Dict[str, float] = Field(default_factory=dict)
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: str = ""
    event_count: int = 0
    duration_ms: float = 0.0
    created_at: float = Field(default_factory=time.time)
