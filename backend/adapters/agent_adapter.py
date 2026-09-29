"""
RansomShield AI — Agent to Backend Model Adapter
Phase 3A: Backend Foundation

Provides bidirectional data mapping between Phase 2 Agent domain objects
(DetectionResult, DetectionAlert, Incident) and Phase 3 Backend Pydantic schemas.
"""

from typing import Dict, Any, Optional

from agent.inference.detection_result import DetectionResult
from agent.detection.alert_manager import DetectionAlert
from agent.detection.incident_manager import Incident
from backend.schemas.detection import DetectionIngestRequest, DetectionResponse
from backend.schemas.alert import AlertResponse
from backend.schemas.incident import IncidentResponse
from backend.schemas.agent import AgentStatusResponse


class AgentModelAdapter:
    """
    Translates agent telemetry and detection models to backend API schemas.
    """

    @classmethod
    def detection_result_to_ingest_request(
        cls,
        result: DetectionResult,
        endpoint_id: str = "endpoint-agent-01",
    ) -> DetectionIngestRequest:
        det_id = getattr(result, "detection_id", None)
        return DetectionIngestRequest(
            detection_id=det_id,
            endpoint_id=endpoint_id,
            timestamp=result.timestamp,
            window_seconds=result.window_seconds,
            prediction=result.prediction,
            confidence=result.confidence,
            risk_score=result.risk_score,
            probabilities=result.probabilities,
            model_version=result.model_version,
            stage=result.stage,
            features=result.features,
            indicators=result.indicators,
            explanation=result.explanation,
            event_count=result.event_count,
            duration_ms=result.duration_ms,
        )

    @classmethod
    def alert_to_response(cls, alert: DetectionAlert) -> AlertResponse:
        """Converts an agent DetectionAlert into a backend AlertResponse."""
        sev_str = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        stat_str = alert.status.value if hasattr(alert.status, "value") else str(alert.status)

        return AlertResponse(
            alert_id=alert.alert_id,
            endpoint_id=alert.endpoint_id,
            prediction=alert.prediction,
            confidence=alert.confidence,
            risk_score=alert.risk_score,
            severity=sev_str,
            status=stat_str,
            stage=alert.stage,
            model_version=alert.model_version,
            window_seconds=alert.window_seconds,
            reason=alert.reason,
            indicators=alert.indicators,
            suppression_count=alert.suppression_count,
            incident_id=alert.incident_id,
            created_at=alert.timestamp,
            updated_at=alert.timestamp,
        )

    @classmethod
    def incident_to_response(cls, incident: Incident) -> IncidentResponse:
        """Converts an agent Incident into a backend IncidentResponse."""
        sev_str = incident.severity.value if hasattr(incident.severity, "value") else str(incident.severity)
        stat_str = incident.status.value if hasattr(incident.status, "value") else str(incident.status)

        return IncidentResponse(
            incident_id=incident.incident_id,
            endpoint_id=incident.endpoint_id,
            severity=sev_str,
            status=stat_str,
            alert_ids=list(incident.alert_ids),
            detection_count=incident.detection_count,
            first_detection=incident.first_detection,
            last_detection=incident.last_detection,
            primary_prediction=incident.primary_prediction,
            highest_risk_score=incident.highest_risk_score,
            top_indicators=list(incident.top_indicators),
            model_version=incident.model_version,
            summary=incident.summary,
            resolution_note=incident.resolution_note,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
        )

    @classmethod
    def agent_status_to_response(cls, status_dict: Dict[str, Any]) -> AgentStatusResponse:
        """Converts RansomShieldAgent.status() output into an AgentStatusResponse."""
        return AgentStatusResponse(
            agent_id=status_dict.get("agent_id", "endpoint-agent-01"),
            status="online" if status_dict.get("running", False) else "offline",
            is_online=status_dict.get("running", False),
            last_seen=status_dict.get("uptime_seconds", 0.0),
            uptime_seconds=status_dict.get("uptime_seconds", 0.0),
            metrics={
                "sliding_windows": status_dict.get("sliding_windows", []),
                "monitored_directories": status_dict.get("monitored_directories", []),
            },
            buffer_stats=status_dict.get("buffer_stats"),
            alerts=status_dict.get("alerts", {}),
            incidents=status_dict.get("incidents", {}),
        )
