"""
RansomShield AI — Alert & Incident Severity Data Models
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Defines strongly typed enums and classifications for alerts, incidents,
and lifecycle states.
"""

from enum import Enum


class AlertSeverity(str, Enum):
    """Severity classification for individual detection alerts."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric rank for severity comparison and escalation."""
        ranks = {
            "INFO": 1,
            "LOW": 2,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5,
        }
        return ranks.get(self.value, 1)

    def __ge__(self, other: "AlertSeverity") -> bool:
        if not isinstance(other, AlertSeverity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: "AlertSeverity") -> bool:
        if not isinstance(other, AlertSeverity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: "AlertSeverity") -> bool:
        if not isinstance(other, AlertSeverity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: "AlertSeverity") -> bool:
        if not isinstance(other, AlertSeverity):
            return NotImplemented
        return self.rank < other.rank


class IncidentSeverity(str, Enum):
    """Aggregate severity classification for correlated incidents."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        ranks = {
            "INFO": 1,
            "LOW": 2,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5,
        }
        return ranks.get(self.value, 1)

    def __ge__(self, other: "IncidentSeverity") -> bool:
        if not isinstance(other, IncidentSeverity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: "IncidentSeverity") -> bool:
        if not isinstance(other, IncidentSeverity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: "IncidentSeverity") -> bool:
        if not isinstance(other, IncidentSeverity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: "IncidentSeverity") -> bool:
        if not isinstance(other, IncidentSeverity):
            return NotImplemented
        return self.rank < other.rank


class AlertStatus(str, Enum):
    """Operational status of a detection alert."""
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class IncidentStatus(str, Enum):
    """Operational state of a correlated security incident."""
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
