"""
RansomShield AI — Detection Result Data Model
Phase 2C: Sliding Window Feature Extractor & Live ML Inference

Defines the strongly typed output schema for real-time model predictions,
calibrated risk scores, and TreeSHAP feature attributions.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import time


@dataclass
class DetectionResult:
    """
    Strongly typed inference detection result produced by LiveInferenceEngine.
    """
    timestamp: float
    window_seconds: int
    prediction: str
    confidence: float
    risk_score: int
    probabilities: Dict[str, float]
    model_version: str = "xgb_ransomware_v2"
    stage: int = 1
    features: Dict[str, float] = field(default_factory=dict)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    explanation: str = ""
    event_count: int = 0
    duration_ms: float = 0.0
    detection_id: Optional[str] = None

    def __post_init__(self):
        if not self.detection_id:
            import hashlib
            key = f"{self.timestamp}:{self.window_seconds}:{self.prediction}:{self.risk_score}"
            self.detection_id = f"det-{hashlib.sha256(key.encode()).hexdigest()[:12]}"

    def to_dict(self) -> Dict[str, Any]:
        """Converts DetectionResult into a JSON-serializable dictionary."""
        return asdict(self)

    @property
    def is_ransomware(self) -> bool:
        """Returns True if the sample was classified as ransomware."""
        return self.prediction in ("Ransomware", "RANSOMWARE")
