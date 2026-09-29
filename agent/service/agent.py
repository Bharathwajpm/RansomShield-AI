"""
RansomShield AI — Windows Endpoint Monitoring Agent Core Service
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Manages agent lifecycle, initialization, thread-safe in-memory buffer,
live collector processes, sliding window feature extraction, real-time
Model V2 XGBoost inference, TreeSHAP attribution, detection decision logic,
alert management, and incident correlation.
"""

import time
import logging
import signal
import threading
from typing import Dict, Any, Optional, List, Tuple

from agent.config import AgentConfig
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer
from agent.models.telemetry import BaseTelemetryEvent
from agent.collectors.base import BaseCollector
from agent.collectors.process_collector import ProcessCollector
from agent.collectors.file_collector import FileCollector
from agent.collectors.network_collector import NetworkCollector
from agent.collectors.sysmon_collector import SysmonCollector
from agent.collectors.event_log_collector import WindowsEventLogCollector
from agent.features.feature_extractor import LiveFeatureExtractor
from agent.inference.live_inference import LiveInferenceEngine
from agent.inference.detection_result import DetectionResult
from agent.detection.severity import AlertSeverity, AlertStatus, IncidentSeverity, IncidentStatus
from agent.detection.deduplication import AlertDeduplicator
from agent.detection.incident_store import LocalIncidentStore
from agent.detection.alert_manager import DetectionAlert, AlertManager
from agent.detection.incident_manager import Incident, IncidentManager
from agent.detection.decision_engine import DetectionDecisionEngine
from agent.transport.manager import AgentTransportManager
from agent.response import ResponseEngine, ResponseAction, ActionResult, ResponseActionType


class StructuredAgentLogger:
    """
    Structured logger ensuring standardized event tags across the agent lifecycle.
    """

    def __init__(self, name: str = "RansomShieldAgent", level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def agent_start(self, agent_id: str, version: str) -> None:
        self.logger.info(f"[AGENT_START] Initializing RansomShield Endpoint Agent '{agent_id}' (v{version})")

    def agent_stop(self, agent_id: str, reason: str = "Clean shutdown") -> None:
        self.logger.info(f"[AGENT_STOP] Stopping Agent '{agent_id}' — Reason: {reason}")

    def collector_available(self, name: str) -> None:
        self.logger.info(f"[COLLECTOR_AVAILABLE] Collector '{name}' is available and active.")

    def collector_unavailable(self, name: str, reason: str = "Required dependency/privilege missing") -> None:
        self.logger.warning(f"[COLLECTOR_UNAVAILABLE] Collector '{name}' is unavailable: {reason}")

    def buffer_event_added(self, event_type: str, count: int = 1) -> None:
        self.logger.debug(f"[BUFFER_EVENT_ADDED] Added {count} event(s) of type '{event_type}' to in-memory buffer.")

    def buffer_cleanup(self, purged_count: int, remaining_count: int) -> None:
        self.logger.debug(f"[BUFFER_CLEANUP] Purged {purged_count} expired event(s). Remaining: {remaining_count}")

    def feature_extraction_started(self, window_seconds: int) -> None:
        self.logger.debug(f"[FEATURE_EXTRACTION_STARTED] Extracting Model V2 features for {window_seconds}s window.")

    def feature_extraction_completed(self, window_seconds: int, event_count: int) -> None:
        self.logger.debug(f"[FEATURE_EXTRACTION_COMPLETED] Window: {window_seconds}s | Events: {event_count}")

    def inference_started(self, model_version: str) -> None:
        self.logger.debug(f"[INFERENCE_STARTED] Running inference using model '{model_version}'.")

    def inference_completed(self, prediction: str, risk_score: int, duration_ms: float) -> None:
        self.logger.info(f"[INFERENCE_COMPLETED] Prediction: {prediction} | Risk Score: {risk_score}/100 | Duration: {duration_ms}ms")

    def detection_result_created(self, prediction: str, confidence: float, risk_score: int) -> None:
        self.logger.info(f"[DETECTION_RESULT_CREATED] Result: {prediction} ({confidence}%) | Risk: {risk_score}")

    def shap_explanation_completed(self, indicator_count: int) -> None:
        self.logger.debug(f"[SHAP_EXPLANATION_COMPLETED] Generated {indicator_count} TreeSHAP feature attributions.")

    def alert_created(self, alert_id: str, severity: str, reason: str) -> None:
        self.logger.warning(f"[ALERT_CREATED] Alert '{alert_id}' ({severity}) — {reason}")

    def alert_deduplicated(self, alert_id: str, suppression_count: int) -> None:
        self.logger.debug(f"[ALERT_DEDUPLICATED] Alert '{alert_id}' suppressed (Count: {suppression_count}).")

    def alert_acknowledged(self, alert_id: str) -> None:
        self.logger.info(f"[ALERT_ACKNOWLEDGED] Alert '{alert_id}' acknowledged.")

    def alert_resolved(self, alert_id: str) -> None:
        self.logger.info(f"[ALERT_RESOLVED] Alert '{alert_id}' resolved.")

    def incident_created(self, incident_id: str, severity: str, alert_count: int) -> None:
        self.logger.error(f"[INCIDENT_CREATED] Security Incident '{incident_id}' ({severity}) created with {alert_count} alert(s).")

    def incident_updated(self, incident_id: str, new_alert_id: str, severity: str) -> None:
        self.logger.warning(f"[INCIDENT_UPDATED] Incident '{incident_id}' correlated with alert '{new_alert_id}' (Severity: {severity}).")

    def incident_resolved(self, incident_id: str) -> None:
        self.logger.info(f"[INCIDENT_RESOLVED] Incident '{incident_id}' marked RESOLVED.")

    def incident_false_positive(self, incident_id: str, reason: str) -> None:
        self.logger.info(f"[INCIDENT_FALSE_POSITIVE] Incident '{incident_id}' marked FALSE POSITIVE — {reason}")

    def detection_processing_error(self, message: str) -> None:
        self.logger.error(f"[DETECTION_PROCESSING_ERROR] {message}")

    def empty_telemetry_window(self, window_seconds: int) -> None:
        self.logger.debug(f"[EMPTY_TELEMETRY_WINDOW] Window {window_seconds}s has no events. Baseline applied.")

    def config_error(self, message: str) -> None:
        self.logger.error(f"[CONFIGURATION_ERROR] {message}")


class RansomShieldAgent:
    """
    Core Windows Endpoint Monitoring Agent managing live telemetry collectors,
    memory buffer, live Model V2 inference, and detection/alert/incident lifecycle.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.config.validate()

        self.logger = StructuredAgentLogger(level=self.config.log_level)
        self.buffer = InMemoryTelemetryBuffer[BaseTelemetryEvent](max_capacity=100_000)
        
        self._is_running: bool = False
        self._start_time: Optional[float] = None
        self._collectors: Dict[str, BaseCollector] = {}
        
        # Subsystem engines
        self.feature_extractor = LiveFeatureExtractor(buffer=self.buffer)
        self.inference_engine: Optional[LiveInferenceEngine] = None
        
        # Phase 2D Detection, Alerting & Incident Subsystems
        self.incident_store = LocalIncidentStore(
            max_alerts=self.config.max_active_alerts,
            max_incidents=self.config.max_active_incidents,
        )
        self.deduplicator = AlertDeduplicator(
            deduplication_window_seconds=self.config.alert_deduplication_seconds,
        )
        self.alert_manager = AlertManager(
            store=self.incident_store,
            deduplicator=self.deduplicator,
            deduplication_seconds=self.config.alert_deduplication_seconds,
        )
        self.incident_manager = IncidentManager(
            store=self.incident_store,
            correlation_window_seconds=self.config.incident_correlation_seconds,
        )
        self.decision_engine = DetectionDecisionEngine(
            alert_manager=self.alert_manager,
            incident_manager=self.incident_manager,
            endpoint_id=self.config.agent_id,
            low_risk_threshold=self.config.low_risk_threshold,
            medium_risk_threshold=self.config.medium_risk_threshold,
            high_risk_threshold=self.config.high_risk_threshold,
            critical_risk_threshold=self.config.critical_risk_threshold,
            min_alert_risk_score=self.config.min_alert_risk_score,
            enable_alerting=self.config.enable_alerting,
            enable_incident_management=self.config.enable_incident_management,
        )
        
        # Phase 3C Transport Subsystem
        self.transport: Optional[AgentTransportManager] = None
        if self.config.enable_backend_transport:
            self.transport = AgentTransportManager(config=self.config)

        # Phase 4 Defensive Response & Containment Engine
        self.response_engine = ResponseEngine(
            dry_run=self.config.response_dry_run,
            quarantine_dir=self.config.quarantine_directory,
            require_approval_for_isolation=self.config.require_approval_for_isolation,
        )

        self._init_collectors()
        self._init_inference_engine()

    def _init_collectors(self) -> None:
        """Instantiates live collector classes attached to the memory buffer."""
        if self.config.psutil_enabled:
            self._collectors["process"] = ProcessCollector(
                buffer=self.buffer,
                poll_interval=self.config.collection_interval_seconds,
            )
            self._collectors["network"] = NetworkCollector(
                buffer=self.buffer,
                poll_interval=max(1.0, self.config.collection_interval_seconds * 2.0),
            )
            
        if self.config.watchdog_enabled:
            self._collectors["file"] = FileCollector(
                monitored_paths=self.config.monitored_directories,
                buffer=self.buffer,
            )
            
        if self.config.sysmon_enabled:
            self._collectors["sysmon"] = SysmonCollector(
                buffer=self.buffer,
                poll_interval=self.config.collection_interval_seconds * 2.0,
            )
            
        if self.config.windows_event_log_enabled:
            self._collectors["event_log"] = WindowsEventLogCollector(
                buffer=self.buffer,
                channel="Application",
                poll_interval=self.config.collection_interval_seconds * 3.0,
            )

    def _init_inference_engine(self) -> None:
        """Instantiates the real-time live ML inference engine and binds decision engine callback."""
        if self.config.inference_enabled:
            self.inference_engine = LiveInferenceEngine(
                buffer=self.buffer,
                sliding_windows=self.config.sliding_window_durations,
                inference_interval_seconds=self.config.inference_interval_seconds,
                model_version=self.config.model_version,
            )
            
            # Register Phase 2D decision callback
            if self.config.enable_detection_decisions:
                self.inference_engine.register_callback(self._on_detection_result)

    def _on_detection_result(self, detection: DetectionResult) -> None:
        """Callback invoked whenever the live inference engine produces a new DetectionResult."""
        # Phase 3C: Enqueue DetectionResult to backend transport
        if self.transport:
            try:
                self.transport.enqueue_detection(detection)
            except Exception as e:
                self.logger.detection_processing_error(f"Error enqueuing detection to transport: {e}")

        try:
            res = self.decision_engine.process_detection(detection)
            if res:
                alert, incident = res
                if alert.status == AlertStatus.SUPPRESSED:
                    self.logger.alert_deduplicated(alert.alert_id, alert.suppression_count)
                else:
                    self.logger.alert_created(alert.alert_id, alert.severity.value, alert.reason)
                    # Phase 3C: Enqueue active alert to transport
                    if self.transport:
                        self.transport.enqueue_alert(alert)
                    
                if incident:
                    if incident.detection_count == 1:
                        self.logger.incident_created(incident.incident_id, incident.severity.value, 1)
                    else:
                        self.logger.incident_updated(incident.incident_id, alert.alert_id, incident.severity.value)
                    # Phase 3C: Enqueue correlated incident to transport
                    if self.transport:
                        self.transport.enqueue_incident(incident)
        except Exception as e:
            self.logger.detection_processing_error(f"Error handling live detection result: {e}")

    def start(self) -> None:
        """
        Starts the agent service, live telemetry collectors, ML inference engine, and transport.
        """
        if self._is_running:
            return

        self.logger.agent_start(self.config.agent_id, self.config.version)
        self._is_running = True
        self._start_time = time.time()

        # Start Phase 3C Transport Subsystem
        if self.transport:
            self.transport.start()

        # Check and start live collectors
        for name, collector in self._collectors.items():
            if collector.is_available():
                self.logger.collector_available(collector.name)
                collector.start()
            else:
                self.logger.collector_unavailable(
                    collector.name,
                    "Platform or module requirement not met (graceful degradation)"
                )

        # Start live inference engine
        if self.inference_engine and self.config.inference_enabled:
            self.inference_engine.start()

    def stop(self, reason: str = "Clean shutdown") -> None:
        """
        Gracefully stops the agent service, collectors, live inference engine, and transport.
        """
        if not self._is_running:
            return

        self.logger.agent_stop(self.config.agent_id, reason=reason)
        
        # Stop Phase 3C Transport Subsystem
        if self.transport:
            try:
                self.transport.stop()
            except Exception:
                pass

        # Stop live inference engine
        if self.inference_engine:
            try:
                self.inference_engine.stop()
            except Exception:
                pass

        # Stop collectors
        for collector in self._collectors.values():
            try:
                collector.stop()
            except Exception:
                pass

        self._is_running = False

    def evaluate_now(self, window_seconds: int = 10) -> Optional[DetectionResult]:
        """Manually triggers an immediate feature extraction & inference evaluation for a window."""
        if self.inference_engine:
            result = self.inference_engine.evaluate_window(window_seconds=window_seconds)
            if self.config.enable_detection_decisions:
                self._on_detection_result(result)
            return result
        return None

    def get_latest_detections(self) -> Dict[int, DetectionResult]:
        """Returns the latest detection results across all windows."""
        if self.inference_engine:
            return self.inference_engine.get_all_latest_results()
        return {}

    # --- ALERT & INCIDENT ACCESSORS ---

    def get_alerts(
        self,
        limit: int = 100,
        severity: Optional[AlertSeverity] = None,
        status: Optional[AlertStatus] = None,
    ) -> List[DetectionAlert]:
        """Lists alerts from local storage."""
        return self.alert_manager.list_alerts(limit=limit, severity=severity, status=status)

    def get_active_alerts(self, limit: int = 50) -> List[DetectionAlert]:
        """Lists active alerts."""
        return self.alert_manager.get_active_alerts(limit=limit)

    def get_incidents(
        self,
        limit: int = 50,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
    ) -> List[Incident]:
        """Lists incidents from local storage."""
        return self.incident_manager.list_incidents(limit=limit, status=status, severity=severity)

    def get_active_incidents(self, limit: int = 20) -> List[Incident]:
        """Lists active (OPEN or ACKNOWLEDGED) incidents."""
        open_incs = self.incident_manager.list_incidents(limit=limit, status=IncidentStatus.OPEN)
        ack_incs = self.incident_manager.list_incidents(limit=limit, status=IncidentStatus.ACKNOWLEDGED)
        return open_incs + ack_incs

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledges an alert."""
        success = self.alert_manager.acknowledge_alert(alert_id)
        if success:
            self.logger.alert_acknowledged(alert_id)
        return success

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolves an alert."""
        success = self.alert_manager.resolve_alert(alert_id)
        if success:
            self.logger.alert_resolved(alert_id)
        return success

    def acknowledge_incident(self, incident_id: str) -> bool:
        """Acknowledges an incident."""
        return self.incident_manager.acknowledge_incident(incident_id)

    def resolve_incident(self, incident_id: str, resolution_note: Optional[str] = None) -> bool:
        """Resolves an incident."""
        success = self.incident_manager.resolve_incident(incident_id, resolution_note)
        if success:
            self.logger.incident_resolved(incident_id)
        return success

    def mark_incident_false_positive(self, incident_id: str, reason: Optional[str] = None) -> bool:
        """Marks an incident as false positive."""
        success = self.incident_manager.mark_false_positive(incident_id, reason)
        if success:
            self.logger.incident_false_positive(incident_id, reason or "Marked by operator.")
        return success

    # --- PHASE 4 RESPONSE & CONTAINMENT ACCESSORS ---

    def execute_response_action(self, action: ResponseAction) -> ActionResult:
        """Executes a defensive response action on the endpoint."""
        return self.response_engine.execute_action(action)

    def get_response_actions(self) -> List[ResponseAction]:
        """Returns list of all response actions on this agent."""
        return self.response_engine.list_actions()

    def get_response_action(self, action_id: str) -> Optional[ResponseAction]:
        """Retrieves a response action by ID."""
        return self.response_engine.get_action(action_id)

    def status(self) -> Dict[str, Any]:
        """
        Returns a diagnostic status report of the agent, buffer, collectors, ML inference, and alerts/incidents.
        """
        uptime = time.time() - self._start_time if (self._is_running and self._start_time) else 0.0
        
        stat = {
            "agent_id": self.config.agent_id,
            "agent_name": self.config.agent_name,
            "version": self.config.version,
            "running": self._is_running,
            "uptime_seconds": round(uptime, 2),
            "buffer_stats": self.buffer.get_stats(),
            "sliding_windows": self.config.sliding_window_durations,
            "collectors": {name: coll.status() for name, coll in self._collectors.items()},
            "monitored_directories": self.config.monitored_directories,
            "phase": "Phase 2D / Phase 3C (Agent ↔ Backend Real-Time Communication)",
            "alerts": {
                "active_count": len(self.get_active_alerts()),
                "total_stored": len(self.get_alerts()),
            },
            "incidents": {
                "active_count": len(self.get_active_incidents()),
                "total_stored": len(self.get_incidents()),
            },
        }

        if self.inference_engine:
            stat["inference"] = self.inference_engine.status()

        if self.transport:
            stat["transport"] = self.transport.status()

        return stat

    def record_event(self, event: BaseTelemetryEvent) -> None:
        """
        Directly records a telemetry event into the in-memory buffer.
        """
        self.buffer.append(event)
        self.logger.buffer_event_added(event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type))

    def purge_expired_events(self) -> int:
        """
        Cleans up events exceeding the buffer retention period.
        """
        purged = self.buffer.cleanup_expired(retention_seconds=self.config.buffer_retention_seconds)
        self.logger.buffer_cleanup(purged, self.buffer.size())
        return purged
