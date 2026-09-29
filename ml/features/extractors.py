"""
RansomShield AI — Feature Extractors & Sliding Window Aggregator
Phase 1: Machine Learning & Feature Pipeline

Provides reusable feature engineering logic that aggregates raw timestamped
Windows telemetry events over sliding windows (5s, 10s, 30s) into model-ready
feature vectors strictly matching the feature contract.
"""

from typing import List, Dict, Any, Optional
import time
import numpy as np
import pandas as pd

from ml.features.feature_contract import FEATURE_NAMES, FEATURE_DEFINITIONS
from ml.features.entropy import calculate_shannon_entropy


class TelemetryEvent:
    """Represents a single raw telemetry event collected from an endpoint."""
    
    def __init__(
        self,
        timestamp: float,
        source: str,  # 'watchdog', 'psutil', 'Sysmon', 'Windows Event Log'
        event_type: str,  # 'FileModified', 'FileMoved', 'FileDeleted', 'ProcessCreate', etc.
        data: Optional[Dict[str, Any]] = None,
    ):
        self.timestamp = timestamp
        self.source = source
        self.event_type = event_type
        self.data = data or {}


class SlidingWindowAggregator:
    """
    Maintains time-indexed queues of raw telemetry events and computes
    rolling window features matching the ML feature contract.
    """
    
    def __init__(self, max_window_seconds: int = 30):
        self.max_window_seconds = max_window_seconds
        self.events: List[TelemetryEvent] = []
        self.latest_psutil_metrics: Dict[str, Any] = {
            "cpu_usage_pct": 0.0,
            "memory_usage_pct": 0.0,
            "unsigned_proc_ratio": 0.0,
        }
        
    def add_event(self, event: TelemetryEvent) -> None:
        """Adds a raw telemetry event and purges events outside the max window."""
        self.events.append(event)
        self.purge_expired(event.timestamp)
        
    def update_psutil_snapshot(
        self,
        cpu_usage_pct: float,
        memory_usage_pct: float,
        unsigned_proc_ratio: float = 0.0,
    ) -> None:
        """Updates the most recent psutil process metrics."""
        self.latest_psutil_metrics = {
            "cpu_usage_pct": float(cpu_usage_pct),
            "memory_usage_pct": float(memory_usage_pct),
            "unsigned_proc_ratio": float(unsigned_proc_ratio),
        }

    def purge_expired(self, current_time: float) -> None:
        """Removes events older than max_window_seconds from the buffer."""
        cutoff = current_time - self.max_window_seconds
        self.events = [e for e in self.events if e.timestamp >= cutoff]

    def get_events_in_window(self, current_time: float, window_seconds: int) -> List[TelemetryEvent]:
        """Returns events occurring within the last window_seconds."""
        cutoff = current_time - window_seconds
        return [e for e in self.events if e.timestamp >= cutoff]

    def extract_features(self, current_time: Optional[float] = None) -> Dict[str, float]:
        """
        Calculates all features from the feature contract over the current sliding windows.
        
        Returns:
            Dict mapping feature name to calculated float value.
        """
        if current_time is None:
            current_time = time.time()
            
        self.purge_expired(current_time)
        
        # Windows
        events_10s = self.get_events_in_window(current_time, 10)
        events_30s = self.get_events_in_window(current_time, 30)
        
        # 1. File Activity (10s window, scaled to rate per minute)
        file_mods = [e for e in events_10s if e.event_type in ("FileModified", "FileCreated")]
        file_renames = [e for e in events_10s if e.event_type in ("FileMoved", "FileRenamed")]
        file_deletes = [e for e in events_10s if e.event_type == "FileDeleted"]
        
        scale_10s = 60.0 / 10.0  # Multiplier to get per-minute rate
        file_mod_rate = len(file_mods) * scale_10s
        file_rename_rate = len(file_renames) * scale_10s
        file_delete_rate = len(file_deletes) * scale_10s
        
        # Entropy features from modified files
        entropies = []
        for e in file_mods + file_renames:
            if "entropy" in e.data:
                entropies.append(float(e.data["entropy"]))
            elif "raw_bytes" in e.data:
                entropies.append(calculate_shannon_entropy(e.data["raw_bytes"]))
                
        if entropies:
            write_entropy_avg = float(np.mean(entropies))
            high_entropy_ratio = float(np.mean([1.0 if ent > 7.2 else 0.0 for ent in entropies]))
        else:
            write_entropy_avg = 4.2  # Normal baseline
            high_entropy_ratio = 0.0
            
        # 2. Process Behavior
        scale_30s = 60.0 / 30.0
        proc_creates = [e for e in events_30s if e.event_type in ("ProcessCreate", "ProcessSpawn")]
        process_creation_rate = len(proc_creates) * scale_30s
        
        cpu_usage_pct = self.latest_psutil_metrics.get("cpu_usage_pct", 0.0)
        memory_usage_pct = self.latest_psutil_metrics.get("memory_usage_pct", 0.0)
        unsigned_proc_ratio = self.latest_psutil_metrics.get("unsigned_proc_ratio", 0.0)
        
        # 3. System & Network Behavior
        reg_writes = [e for e in events_10s if e.event_type in ("RegistryValueSet", "RegistryWrite")]
        registry_write_rate = len(reg_writes) * scale_10s
        
        net_conns = [e for e in events_10s if e.event_type in ("NetworkConnection", "SocketConnect")]
        network_connection_count = len(net_conns) * scale_10s
        
        shadow_tamper_events = [
            e for e in events_30s 
            if e.event_type == "ShadowCopyTamper" or e.data.get("shadow_copy_tamper")
        ]
        shadow_copy_tamper = 1.0 if len(shadow_tamper_events) > 0 else 0.0
        
        feature_dict = {
            "file_modification_rate": round(float(file_mod_rate), 2),
            "file_rename_rate": round(float(file_rename_rate), 2),
            "file_deletion_rate": round(float(file_delete_rate), 2),
            "write_entropy_avg": round(float(write_entropy_avg), 4),
            "high_entropy_ratio": round(float(high_entropy_ratio), 4),
            "cpu_usage_pct": round(float(cpu_usage_pct), 2),
            "memory_usage_pct": round(float(memory_usage_pct), 2),
            "process_creation_rate": round(float(process_creation_rate), 2),
            "unsigned_proc_ratio": round(float(unsigned_proc_ratio), 4),
            "registry_write_rate": round(float(registry_write_rate), 2),
            "network_connection_count": round(float(network_connection_count), 2),
            "shadow_copy_tamper": round(float(shadow_copy_tamper), 1),
        }
        
        return feature_dict

    def extract_feature_vector(self, current_time: Optional[float] = None) -> np.ndarray:
        """
        Extracts features in exact deterministic order defined by FEATURE_NAMES.
        
        Returns:
            1D numpy array of length 12
        """
        f_dict = self.extract_features(current_time)
        return np.array([f_dict[name] for name in FEATURE_NAMES], dtype=np.float64)


if __name__ == "__main__":
    agg = SlidingWindowAggregator()
    now = time.time()
    
    # Simulate normal activity
    agg.update_psutil_snapshot(cpu_usage_pct=24.5, memory_usage_pct=12.1, unsigned_proc_ratio=0.0)
    agg.add_event(TelemetryEvent(now - 8, "watchdog", "FileModified", {"entropy": 4.1}))
    agg.add_event(TelemetryEvent(now - 5, "watchdog", "FileModified", {"entropy": 4.3}))
    agg.add_event(TelemetryEvent(now - 2, "Sysmon", "RegistryValueSet"))
    
    feats = agg.extract_features(now)
    vec = agg.extract_feature_vector(now)
    print("Normal extracted features:", feats)
    print("Feature vector shape:", vec.shape)
