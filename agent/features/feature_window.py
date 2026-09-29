"""
RansomShield AI — Feature Window Data Model
Phase 2C: Sliding Window Feature Extractor & Live ML Inference

Encapsulates feature extraction metadata and vector representations for a given sliding window.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List
import numpy as np


@dataclass
class FeatureWindow:
    """
    Represents an aggregated telemetry feature extraction window (e.g. 5s, 10s, 30s).
    """
    window_seconds: int
    start_time: float
    end_time: float
    event_count: int
    features: Dict[str, float] = field(default_factory=dict)
    
    @property
    def feature_vector(self) -> np.ndarray:
        """Returns the extracted 19-element feature vector as a numpy array."""
        from ml.features.feature_contract import V2_FEATURE_NAMES
        return np.array([self.features.get(name, 0.0) for name in V2_FEATURE_NAMES], dtype=np.float64)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes feature window representation into a dictionary."""
        return {
            "window_seconds": self.window_seconds,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "event_count": self.event_count,
            "features": self.features,
        }
