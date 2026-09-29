"""
RansomShield AI — Detection Decision Engine
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Consumes live DetectionResult records from Phase 2C, classifies observation severity
against configurable risk thresholds, synthesizes human-readable SHAP-based detection
explanations, creates alerts, and coordinates incident correlation.
"""

import time
import logging
from typing import Dict, Any, List, Optional, Tuple

from agent.inference.detection_result import DetectionResult
from agent.detection.severity import AlertSeverity, IncidentSeverity
from agent.detection.alert_manager import AlertManager, DetectionAlert
from agent.detection.incident_manager import IncidentManager, Incident


logger = logging.getLogger("RansomShieldDecisionEngine")


class DetectionDecisionEngine:
    """
    Evaluates live ML detection results, determines alert severity,
    and orchestrates alerting and incident correlation pipelines.
    """

    def __init__(
        self,
        alert_manager: Optional[AlertManager] = None,
        incident_manager: Optional[IncidentManager] = None,
        endpoint_id: str = "endpoint-agent-01",
        low_risk_threshold: int = 30,
        medium_risk_threshold: int = 50,
        high_risk_threshold: int = 70,
        critical_risk_threshold: int = 85,
        min_alert_risk_score: int = 40,
        enable_alerting: bool = True,
        enable_incident_management: bool = True,
    ):
        self.alert_manager = alert_manager or AlertManager()
        self.incident_manager = incident_manager or IncidentManager(store=self.alert_manager.store)
        self.endpoint_id = endpoint_id
        
        self.low_risk_threshold = low_risk_threshold
        self.medium_risk_threshold = medium_risk_threshold
        self.high_risk_threshold = high_risk_threshold
        self.critical_risk_threshold = critical_risk_threshold
        self.min_alert_risk_score = min_alert_risk_score
        
        self.enable_alerting = enable_alerting
        self.enable_incident_management = enable_incident_management

    def classify_severity(self, risk_score: int, is_ransomware: bool) -> AlertSeverity:
        """
        Classifies detection severity based on risk score and model classification.
        """
        if risk_score >= self.critical_risk_threshold or (is_ransomware and risk_score >= 80):
            return AlertSeverity.CRITICAL
        elif risk_score >= self.high_risk_threshold or is_ransomware:
            return AlertSeverity.HIGH
        elif risk_score >= self.medium_risk_threshold:
            return AlertSeverity.MEDIUM
        elif risk_score >= self.low_risk_threshold:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO

    def generate_detection_reason(self, detection: DetectionResult, severity: AlertSeverity) -> str:
        """
        Synthesizes a concise, human-readable detection reason from actual TreeSHAP indicators.
        """
        risk_str = f"Risk: {detection.risk_score}/100, Confidence: {detection.confidence}%"
        
        # Collect contributing risk-increasing indicators
        risk_indicators = [
            ind["label"] for ind in detection.indicators
            if ind.get("direction") == "increases risk" or ind.get("weight", 0) >= 40
        ]

        if not risk_indicators and detection.indicators:
            risk_indicators = [ind["label"] for ind in detection.indicators[:3]]

        indicator_summary = ", ".join(risk_indicators[:3]) if risk_indicators else "Anomaly deviation"

        if severity == AlertSeverity.CRITICAL:
            return f"CRITICAL: High-confidence ransomware behavior detected ({risk_str}): {indicator_summary}."
        elif severity == AlertSeverity.HIGH:
            return f"HIGH: Ransomware-like behavioral pattern detected ({risk_str}): {indicator_summary}."
        elif severity == AlertSeverity.MEDIUM:
            return f"MEDIUM: Suspicious activity observed ({risk_str}): {indicator_summary}."
        elif severity == AlertSeverity.LOW:
            return f"LOW: Minor behavioral deviation ({risk_str}): {indicator_summary}."
        else:
            return f"INFO: Normal baseline activity ({risk_str})."

    def process_detection(
        self,
        detection: DetectionResult,
        current_time: Optional[float] = None,
    ) -> Optional[Tuple[DetectionAlert, Optional[Incident]]]:
        """
        Processes a live DetectionResult through severity classification, alerting,
        and incident correlation.
        
        Returns:
            Tuple of (DetectionAlert, Optional[Incident]) or None if ignored as benign info.
        """
        if current_time is None:
            current_time = detection.timestamp or time.time()

        try:
            severity = self.classify_severity(
                risk_score=detection.risk_score,
                is_ransomware=detection.is_ransomware,
            )

            # Determine whether observation warrants alert generation
            warrants_alert = (
                severity >= AlertSeverity.LOW
                or detection.is_ransomware
                or detection.risk_score >= self.min_alert_risk_score
            )

            if not warrants_alert or not self.enable_alerting:
                return None

            reason = self.generate_detection_reason(detection, severity)

            # Create / deduplicate alert
            alert, is_duplicate = self.alert_manager.create_alert(
                endpoint_id=self.endpoint_id,
                prediction=detection.prediction,
                confidence=detection.confidence,
                risk_score=detection.risk_score,
                severity=severity,
                window_seconds=detection.window_seconds,
                stage=detection.stage,
                model_version=detection.model_version,
                reason=reason,
                indicators=detection.indicators,
                features=detection.features,
                metadata={"event_count": detection.event_count, "duration_ms": detection.duration_ms},
                current_time=current_time,
            )

            # Correlate into incident if not suppressed and incident management is enabled
            incident = None
            if not is_duplicate and self.enable_incident_management:
                incident = self.incident_manager.correlate_alert(alert, current_time=current_time)

            return alert, incident

        except Exception as e:
            logger.error(f"[DETECTION_PROCESSING_ERROR] Error in detection decision engine: {e}", exc_info=False)
            return None
