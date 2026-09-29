"""
RansomShield AI — Alert Manager & DetectionAlert Model
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Defines the strongly typed DetectionAlert data contract and AlertManager service
for lifecycle tracking, deduplication, acknowledgement, and resolution.
"""

import time
import uuid
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple

from agent.detection.severity import AlertSeverity, AlertStatus
from agent.detection.deduplication import AlertDeduplicator
from agent.detection.incident_store import LocalIncidentStore


@dataclass
class DetectionAlert:
    """
    Strongly typed detection alert emitted when telemetry observations exceed risk thresholds.
    """
    alert_id: str = field(default_factory=lambda: f"alt-{uuid.uuid4().hex[:12]}")
    timestamp: float = field(default_factory=time.time)
    endpoint_id: str = "endpoint-agent-01"
    prediction: str = "Goodware"
    confidence: float = 0.0
    risk_score: int = 0
    severity: AlertSeverity = AlertSeverity.INFO
    status: AlertStatus = AlertStatus.ACTIVE
    stage: int = 1
    model_version: str = "xgb_ransomware_v2"
    window_seconds: int = 10
    reason: str = ""
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    features: Dict[str, float] = field(default_factory=dict)
    suppression_count: int = 0
    incident_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts DetectionAlert into a JSON-serializable dictionary."""
        d = asdict(self)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        d["status"] = self.status.value if hasattr(self.status, "value") else str(self.status)
        return d

    @property
    def is_active(self) -> bool:
        return self.status == AlertStatus.ACTIVE


class AlertManager:
    """
    Manages detection alerts lifecycle, deduplication, and persistence in the LocalIncidentStore.
    """

    def __init__(
        self,
        store: Optional[LocalIncidentStore] = None,
        deduplicator: Optional[AlertDeduplicator] = None,
        deduplication_seconds: float = 15.0,
    ):
        self.store = store or LocalIncidentStore()
        self.deduplicator = deduplicator or AlertDeduplicator(deduplication_window_seconds=deduplication_seconds)
        self._lock = threading.RLock()

    def create_alert(
        self,
        endpoint_id: str,
        prediction: str,
        confidence: float,
        risk_score: int,
        severity: AlertSeverity,
        window_seconds: int = 10,
        stage: int = 1,
        model_version: str = "xgb_ransomware_v2",
        reason: str = "",
        indicators: Optional[List[Dict[str, Any]]] = None,
        features: Optional[Dict[str, float]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        current_time: Optional[float] = None,
    ) -> Tuple[DetectionAlert, bool]:
        """
        Creates, deduplicates, and stores a new DetectionAlert.
        
        Returns:
            Tuple of (DetectionAlert, is_duplicate)
        """
        if current_time is None:
            current_time = time.time()

        indicators_list = indicators or []
        primary_indicator = indicators_list[0]["feature_name"] if indicators_list else "general"
        process_key = str(metadata.get("process_name", "system")) if metadata else "system"

        alert = DetectionAlert(
            timestamp=current_time,
            endpoint_id=endpoint_id,
            prediction=prediction,
            confidence=confidence,
            risk_score=risk_score,
            severity=severity,
            status=AlertStatus.ACTIVE,
            stage=stage,
            model_version=model_version,
            window_seconds=window_seconds,
            reason=reason,
            indicators=indicators_list,
            features=features or {},
            metadata=metadata or {},
        )

        with self._lock:
            fingerprint = self.deduplicator.generate_fingerprint(
                endpoint_id=endpoint_id,
                prediction=prediction,
                severity=severity,
                primary_indicator=primary_indicator,
                process_key=process_key,
            )

            is_dup, orig_alert_id, count = self.deduplicator.check_duplicate(
                fingerprint=fingerprint,
                alert_id=alert.alert_id,
                current_time=current_time,
            )

            if is_dup and orig_alert_id:
                # Update suppression count on existing original alert
                orig_alert = self.store.get_alert(orig_alert_id)
                if orig_alert:
                    orig_alert.suppression_count = count
                    orig_alert.timestamp = current_time
                    self.store.update_alert(orig_alert)

                alert.status = AlertStatus.SUPPRESSED
                alert.suppression_count = count
                return alert, True

            # Fresh, non-duplicate alert
            self.store.save_alert(alert)
            return alert, False

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Transitions alert status to ACKNOWLEDGED."""
        with self._lock:
            alert = self.store.get_alert(alert_id)
            if alert:
                alert.status = AlertStatus.ACKNOWLEDGED
                self.store.update_alert(alert)
                return True
            return False

    def resolve_alert(self, alert_id: str) -> bool:
        """Transitions alert status to RESOLVED."""
        with self._lock:
            alert = self.store.get_alert(alert_id)
            if alert:
                alert.status = AlertStatus.RESOLVED
                self.store.update_alert(alert)
                return True
            return False

    def suppress_alert(self, alert_id: str) -> bool:
        """Explicitly suppresses an alert."""
        with self._lock:
            alert = self.store.get_alert(alert_id)
            if alert:
                alert.status = AlertStatus.SUPPRESSED
                self.store.update_alert(alert)
                return True
            return False

    def get_alert(self, alert_id: str) -> Optional[DetectionAlert]:
        """Retrieves an alert by ID."""
        return self.store.get_alert(alert_id)

    def get_active_alerts(self, limit: int = 50) -> List[DetectionAlert]:
        """Returns all currently ACTIVE alerts."""
        return self.store.list_alerts(limit=limit, status=AlertStatus.ACTIVE)

    def list_alerts(
        self,
        limit: int = 100,
        severity: Optional[AlertSeverity] = None,
        status: Optional[AlertStatus] = None,
        endpoint_id: Optional[str] = None,
    ) -> List[DetectionAlert]:
        """Lists alerts matching optional filter criteria."""
        return self.store.list_alerts(limit=limit, severity=severity, status=status, endpoint_id=endpoint_id)
