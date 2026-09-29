"""
RansomShield AI — Incident Manager & Correlation Subsystem
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Correlates incoming alerts into cohesive security incidents, tracks incident lifecycle
state machine transitions, and manages incident escalation.
"""

import time
import uuid
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional

from agent.detection.severity import IncidentSeverity, IncidentStatus, AlertSeverity
from agent.detection.alert_manager import DetectionAlert
from agent.detection.incident_store import LocalIncidentStore


class InvalidStateTransitionError(Exception):
    """Raised when an illegal incident state machine transition is attempted."""
    pass


@dataclass
class Incident:
    """
    Correlated security incident aggregating multiple temporal and multi-window detection alerts.
    """
    incident_id: str = field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:12]}")
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    endpoint_id: str = "endpoint-agent-01"
    severity: IncidentSeverity = IncidentSeverity.LOW
    status: IncidentStatus = IncidentStatus.OPEN
    alert_ids: List[str] = field(default_factory=list)
    detection_count: int = 1
    first_detection: float = field(default_factory=time.time)
    last_detection: float = field(default_factory=time.time)
    primary_prediction: str = "Ransomware"
    highest_risk_score: int = 0
    top_indicators: List[Dict[str, Any]] = field(default_factory=list)
    model_version: str = "xgb_ransomware_v2"
    summary: str = ""
    resolution_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converts Incident into a JSON-serializable dictionary."""
        d = asdict(self)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        d["status"] = self.status.value if hasattr(self.status, "value") else str(self.status)
        return d


class IncidentStateMachine:
    """
    Validates and controls state machine transitions for Security Incidents.
    """

    VALID_TRANSITIONS = {
        IncidentStatus.OPEN: {
            IncidentStatus.ACKNOWLEDGED,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        },
        IncidentStatus.ACKNOWLEDGED: {
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        },
        IncidentStatus.RESOLVED: set(),  # Terminal state (reopen via explicit flag)
        IncidentStatus.FALSE_POSITIVE: set(),  # Terminal state
    }

    @classmethod
    def validate_transition(
        cls,
        current_status: IncidentStatus,
        target_status: IncidentStatus,
        allow_reopen: bool = False,
    ) -> None:
        """
        Validates whether current_status -> target_status is permitted.
        Raises InvalidStateTransitionError if illegal.
        """
        if current_status == target_status:
            return

        if allow_reopen and current_status in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE) and target_status == IncidentStatus.OPEN:
            return

        allowed = cls.VALID_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            raise InvalidStateTransitionError(
                f"Illegal state transition from '{current_status.value}' to '{target_status.value}'. "
                f"Allowed target states: {[s.value for s in allowed]}"
            )


class IncidentManager:
    """
    Correlates individual DetectionAlert records into unified Incidents and manages their lifecycle.
    """

    def __init__(
        self,
        store: Optional[LocalIncidentStore] = None,
        correlation_window_seconds: float = 60.0,
    ):
        self.store = store or LocalIncidentStore()
        self.correlation_window_seconds = correlation_window_seconds
        self._lock = threading.RLock()

    def correlate_alert(self, alert: DetectionAlert, current_time: Optional[float] = None) -> Incident:
        """
        Correlates an incoming alert with an existing active incident or creates a new incident.
        """
        if current_time is None:
            current_time = time.time()

        # Map AlertSeverity to IncidentSeverity
        sev_map = {
            AlertSeverity.INFO: IncidentSeverity.INFO,
            AlertSeverity.LOW: IncidentSeverity.LOW,
            AlertSeverity.MEDIUM: IncidentSeverity.MEDIUM,
            AlertSeverity.HIGH: IncidentSeverity.HIGH,
            AlertSeverity.CRITICAL: IncidentSeverity.CRITICAL,
        }
        alert_incident_sev = sev_map.get(alert.severity, IncidentSeverity.LOW)

        with self._lock:
            active_incident: Optional[Incident] = self.store.get_active_incident_for_endpoint(
                endpoint_id=alert.endpoint_id,
                max_age_seconds=self.correlation_window_seconds,
                current_time=current_time,
            )

            if active_incident:
                # Correlate with existing incident
                if alert.alert_id not in active_incident.alert_ids:
                    active_incident.alert_ids.append(alert.alert_id)
                active_incident.detection_count += 1
                active_incident.updated_at = current_time
                active_incident.last_detection = current_time
                
                # Update highest risk score
                active_incident.highest_risk_score = max(
                    active_incident.highest_risk_score,
                    alert.risk_score,
                )

                # Escalate severity if alert severity is higher
                if alert_incident_sev > active_incident.severity:
                    active_incident.severity = alert_incident_sev

                # Merge top SHAP indicators
                if alert.indicators:
                    existing_fnames = {ind["feature_name"] for ind in active_incident.top_indicators}
                    for ind in alert.indicators:
                        if ind["feature_name"] not in existing_fnames and len(active_incident.top_indicators) < 5:
                            active_incident.top_indicators.append(ind)

                # Link alert to incident
                alert.incident_id = active_incident.incident_id
                self.store.update_incident(active_incident)
                return active_incident

            # Create new incident
            summary = (
                f"Incident on {alert.endpoint_id}: {alert.prediction} detected "
                f"(Risk: {alert.risk_score}/100, Severity: {alert_incident_sev.value}). {alert.reason}"
            )

            new_incident = Incident(
                created_at=current_time,
                updated_at=current_time,
                endpoint_id=alert.endpoint_id,
                severity=alert_incident_sev,
                status=IncidentStatus.OPEN,
                alert_ids=[alert.alert_id],
                detection_count=1,
                first_detection=current_time,
                last_detection=current_time,
                primary_prediction=alert.prediction,
                highest_risk_score=alert.risk_score,
                top_indicators=list(alert.indicators[:5]),
                model_version=alert.model_version,
                summary=summary,
            )

            alert.incident_id = new_incident.incident_id
            self.store.save_incident(new_incident)
            return new_incident

    def acknowledge_incident(self, incident_id: str) -> bool:
        """Transitions incident status to ACKNOWLEDGED."""
        with self._lock:
            inc = self.store.get_incident(incident_id)
            if not inc:
                return False

            IncidentStateMachine.validate_transition(inc.status, IncidentStatus.ACKNOWLEDGED)
            inc.status = IncidentStatus.ACKNOWLEDGED
            inc.updated_at = time.time()
            self.store.update_incident(inc)
            return True

    def resolve_incident(self, incident_id: str, resolution_note: Optional[str] = None) -> bool:
        """Transitions incident status to RESOLVED."""
        with self._lock:
            inc = self.store.get_incident(incident_id)
            if not inc:
                return False

            IncidentStateMachine.validate_transition(inc.status, IncidentStatus.RESOLVED)
            inc.status = IncidentStatus.RESOLVED
            inc.resolution_note = resolution_note or "Resolved by analyst."
            inc.updated_at = time.time()
            self.store.update_incident(inc)
            return True

    def mark_false_positive(self, incident_id: str, reason: Optional[str] = None) -> bool:
        """Transitions incident status to FALSE_POSITIVE."""
        with self._lock:
            inc = self.store.get_incident(incident_id)
            if not inc:
                return False

            IncidentStateMachine.validate_transition(inc.status, IncidentStatus.FALSE_POSITIVE)
            inc.status = IncidentStatus.FALSE_POSITIVE
            inc.resolution_note = f"Marked False Positive: {reason or 'Benign activity verified.'}"
            inc.updated_at = time.time()
            self.store.update_incident(inc)
            return True

    def reopen_incident(self, incident_id: str, reason: Optional[str] = None) -> bool:
        """Reopens a resolved or false positive incident."""
        with self._lock:
            inc = self.store.get_incident(incident_id)
            if not inc:
                return False

            IncidentStateMachine.validate_transition(inc.status, IncidentStatus.OPEN, allow_reopen=True)
            inc.status = IncidentStatus.OPEN
            inc.summary += f" [Reopened: {reason or 'New activity detected'}]"
            inc.updated_at = time.time()
            self.store.update_incident(inc)
            return True

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieves an incident by ID."""
        return self.store.get_incident(incident_id)

    def list_incidents(
        self,
        limit: int = 50,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        endpoint_id: Optional[str] = None,
    ) -> List[Incident]:
        """Lists incidents matching optional filter criteria."""
        return self.store.list_incidents(limit=limit, status=status, severity=severity, endpoint_id=endpoint_id)
