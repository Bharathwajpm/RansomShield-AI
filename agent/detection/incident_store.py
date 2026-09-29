"""
RansomShield AI — Local In-Memory Incident & Alert Store
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Provides a thread-safe, bounded in-memory storage abstraction for alerts and incidents.
This layer abstracts local storage so Phase 3 can replace/extend it with MongoDB persistence.
"""

import time
import threading
from typing import Dict, Any, List, Optional
from collections import OrderedDict

from agent.detection.severity import AlertSeverity, AlertStatus, IncidentSeverity, IncidentStatus


class LocalIncidentStore:
    """
    Thread-safe, bounded in-memory store for detection alerts and correlated incidents.
    """

    def __init__(self, max_alerts: int = 1000, max_incidents: int = 500):
        self.max_alerts = max_alerts
        self.max_incidents = max_incidents
        
        self._alerts: OrderedDict[str, Any] = OrderedDict()
        self._incidents: OrderedDict[str, Any] = OrderedDict()
        self._lock = threading.RLock()

    # --- ALERT OPERATIONS ---

    def save_alert(self, alert: Any) -> None:
        """Stores a new DetectionAlert record with bounded FIFO eviction."""
        with self._lock:
            alert_id = getattr(alert, "alert_id", str(alert))
            if alert_id in self._alerts:
                del self._alerts[alert_id]
            elif len(self._alerts) >= self.max_alerts:
                self._alerts.popitem(last=False)  # Evict oldest alert

            self._alerts[alert_id] = alert

    def get_alert(self, alert_id: str) -> Optional[Any]:
        """Retrieves an alert by ID."""
        with self._lock:
            return self._alerts.get(alert_id)

    def list_alerts(
        self,
        limit: int = 100,
        severity: Optional[AlertSeverity] = None,
        status: Optional[AlertStatus] = None,
        endpoint_id: Optional[str] = None,
    ) -> List[Any]:
        """Lists alerts matching optional filter criteria, sorted by recency."""
        with self._lock:
            results = []
            for alert in reversed(self._alerts.values()):
                if severity and getattr(alert, "severity", None) != severity:
                    continue
                if status and getattr(alert, "status", None) != status:
                    continue
                if endpoint_id and getattr(alert, "endpoint_id", None) != endpoint_id:
                    continue
                results.append(alert)
                if len(results) >= limit:
                    break
            return results

    def update_alert(self, alert: Any) -> None:
        """Updates an existing alert record."""
        with self._lock:
            alert_id = getattr(alert, "alert_id", None)
            if alert_id and alert_id in self._alerts:
                self._alerts[alert_id] = alert

    # --- INCIDENT OPERATIONS ---

    def save_incident(self, incident: Any) -> None:
        """Stores a new Incident record with bounded FIFO eviction."""
        with self._lock:
            incident_id = getattr(incident, "incident_id", str(incident))
            if incident_id in self._incidents:
                del self._incidents[incident_id]
            elif len(self._incidents) >= self.max_incidents:
                self._incidents.popitem(last=False)  # Evict oldest incident

            self._incidents[incident_id] = incident

    def get_incident(self, incident_id: str) -> Optional[Any]:
        """Retrieves an incident by ID."""
        with self._lock:
            return self._incidents.get(incident_id)

    def list_incidents(
        self,
        limit: int = 50,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        endpoint_id: Optional[str] = None,
    ) -> List[Any]:
        """Lists incidents matching optional filter criteria, sorted by recency."""
        with self._lock:
            results = []
            for inc in reversed(self._incidents.values()):
                if status and getattr(inc, "status", None) != status:
                    continue
                if severity and getattr(inc, "severity", None) != severity:
                    continue
                if endpoint_id and getattr(inc, "endpoint_id", None) != endpoint_id:
                    continue
                results.append(inc)
                if len(results) >= limit:
                    break
            return results

    def update_incident(self, incident: Any) -> None:
        """Updates an existing incident record."""
        with self._lock:
            incident_id = getattr(incident, "incident_id", None)
            if incident_id and incident_id in self._incidents:
                self._incidents[incident_id] = incident

    def get_active_incident_for_endpoint(
        self,
        endpoint_id: str,
        max_age_seconds: float = 60.0,
        current_time: Optional[float] = None,
    ) -> Optional[Any]:
        """
        Retrieves the most recent active (OPEN or ACKNOWLEDGED) incident for an endpoint
        within the correlation window.
        """
        if current_time is None:
            current_time = time.time()

        with self._lock:
            for inc in reversed(self._incidents.values()):
                if getattr(inc, "endpoint_id", None) == endpoint_id:
                    inc_status = getattr(inc, "status", None)
                    if inc_status in (IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED):
                        last_det = getattr(inc, "last_detection", getattr(inc, "updated_at", 0.0))
                        if (current_time - last_det) <= max_age_seconds:
                            return inc
            return None

    def clear(self) -> None:
        """Clears all stored alerts and incidents."""
        with self._lock:
            self._alerts.clear()
            self._incidents.clear()
