"""
RansomShield AI — Agent Detection Package
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Exports severity models, alert models, incident models, deduplication, and decision engine.
"""

from agent.detection.severity import (
    AlertSeverity,
    IncidentSeverity,
    AlertStatus,
    IncidentStatus,
)
from agent.detection.deduplication import AlertDeduplicator
from agent.detection.incident_store import LocalIncidentStore
from agent.detection.alert_manager import DetectionAlert, AlertManager
from agent.detection.incident_manager import (
    Incident,
    IncidentStateMachine,
    InvalidStateTransitionError,
    IncidentManager,
)
from agent.detection.decision_engine import DetectionDecisionEngine

__all__ = [
    "AlertSeverity",
    "IncidentSeverity",
    "AlertStatus",
    "IncidentStatus",
    "AlertDeduplicator",
    "LocalIncidentStore",
    "DetectionAlert",
    "AlertManager",
    "Incident",
    "IncidentStateMachine",
    "InvalidStateTransitionError",
    "IncidentManager",
    "DetectionDecisionEngine",
]
