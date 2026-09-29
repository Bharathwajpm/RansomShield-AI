"""
RansomShield AI — Alert Deduplication Subsystem
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Suppresses duplicate alerts caused by multi-window overlapping evaluations (5s/10s/30s)
and high-frequency inference cycles using deterministic fingerprinting.
"""

import time
import threading
from typing import Dict, Any, Tuple, Optional
from agent.detection.severity import AlertSeverity


class AlertDeduplicator:
    """
    Thread-safe alert deduplicator tracking recent alert fingerprints within a sliding time window.
    """

    def __init__(self, deduplication_window_seconds: float = 15.0):
        self.deduplication_window_seconds = deduplication_window_seconds
        self._seen: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def generate_fingerprint(
        self,
        endpoint_id: str,
        prediction: str,
        severity: AlertSeverity,
        primary_indicator: str = "general",
        process_key: str = "default",
    ) -> str:
        """Generates a deterministic fingerprint string for deduplication comparison."""
        sev_str = severity.value if hasattr(severity, "value") else str(severity)
        return f"{endpoint_id}::{prediction}::{sev_str}::{primary_indicator}::{process_key}"

    def check_duplicate(
        self,
        fingerprint: str,
        alert_id: str,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, Optional[str], int]:
        """
        Checks if the given fingerprint is a duplicate within the deduplication window.
        
        Returns:
            Tuple of (is_duplicate, original_alert_id, suppression_count)
        """
        if current_time is None:
            current_time = time.time()

        with self._lock:
            # Check if fingerprint is in memory
            if fingerprint in self._seen:
                entry = self._seen[fingerprint]
                time_diff = current_time - entry["last_seen"]

                if time_diff < self.deduplication_window_seconds:
                    # Within deduplication window: Suppress duplicate
                    entry["count"] += 1
                    entry["last_seen"] = current_time
                    return True, entry["alert_id"], entry["count"]

            # Not duplicate or window expired: Record new alert entry
            self._seen[fingerprint] = {
                "alert_id": alert_id,
                "first_seen": current_time,
                "last_seen": current_time,
                "count": 0,
            }
            return False, None, 0

    def cleanup(self, max_age_seconds: Optional[float] = None, current_time: Optional[float] = None) -> int:
        """Prunes expired fingerprint records to bound memory usage."""
        if current_time is None:
            current_time = time.time()
        if max_age_seconds is None:
            max_age_seconds = self.deduplication_window_seconds * 2.0

        with self._lock:
            cutoff = current_time - max_age_seconds
            expired_keys = [k for k, v in self._seen.items() if v["last_seen"] < cutoff]
            for k in expired_keys:
                del self._seen[k]
            return len(expired_keys)

    def reset(self) -> None:
        """Clears all deduplication state."""
        with self._lock:
            self._seen.clear()
