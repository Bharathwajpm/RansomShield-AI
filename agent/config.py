"""
RansomShield AI — Windows Monitoring Agent Configuration
Phase 2A–2D: Endpoint Foundation, Telemetry, Live Inference & Incident Pipeline

Defines configurable settings for directory monitoring, collector toggles,
sampling frequencies, telemetry sliding window durations (5s, 10s, 30s),
live ML inference scheduling, and alerting/incident correlation thresholds.
"""

import os
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any


def get_default_monitored_directories() -> List[str]:
    """Generates cross-platform, Windows-safe default directory paths for monitoring."""
    user_home = Path.home()
    dirs = []
    
    # Standard user folders targeted by ransomware
    for folder in ["Documents", "Desktop", "Downloads", "Pictures"]:
        target = user_home / folder
        if target.exists():
            dirs.append(str(target))
            
    # System temp directory
    temp_dir = os.environ.get("TEMP", os.environ.get("TMP", str(user_home / "AppData" / "Local" / "Temp")))
    if temp_dir and os.path.exists(temp_dir):
        dirs.append(str(temp_dir))
        
    # If no directories exist (e.g. non-standard sandbox), fall back to current directory
    if not dirs:
        dirs.append(str(Path.cwd()))
        
    return dirs


@dataclass
class AgentConfig:
    """
    Configuration parameters for the Windows Endpoint Monitoring Agent.
    """
    # Agent Identity
    agent_id: str = "endpoint-agent-01"
    agent_name: str = "RansomShield-Endpoint-Agent"
    version: str = "0.1.0"
    
    # Monitored Target Directories
    monitored_directories: List[str] = field(default_factory=get_default_monitored_directories)
    
    # Telemetry Sampling & Sliding Window Durations (Seconds)
    collection_interval_seconds: float = 1.0
    sliding_window_durations: List[int] = field(default_factory=lambda: [5, 10, 30])
    buffer_retention_seconds: float = 120.0
    
    # Collector Toggles
    psutil_enabled: bool = True
    watchdog_enabled: bool = True
    sysmon_enabled: bool = True
    windows_event_log_enabled: bool = True
    
    # Live ML Inference Engine Toggles (Phase 2C)
    inference_enabled: bool = True
    inference_interval_seconds: float = 2.0
    model_version: str = "xgb_ransomware_v2"
    
    # Detection Decision, Alerting & Incident Settings (Phase 2D)
    enable_detection_decisions: bool = True
    enable_alerting: bool = True
    enable_incident_management: bool = True
    low_risk_threshold: int = 30
    medium_risk_threshold: int = 50
    high_risk_threshold: int = 70
    critical_risk_threshold: int = 85
    min_alert_risk_score: int = 40
    alert_deduplication_seconds: float = 15.0
    incident_correlation_seconds: float = 60.0
    max_active_alerts: int = 1000
    max_active_incidents: int = 500
    
    # Storage & Persistence
    sqlite_db_path: Optional[str] = "agent_telemetry.db"
    
    # Phase 3C: Agent ↔ Backend Real-Time Communication
    backend_url: str = "http://localhost:8000"
    enable_backend_transport: bool = False
    heartbeat_interval_seconds: float = 15.0
    backend_request_timeout: float = 5.0
    backend_max_retries: int = 3
    backend_retry_base_delay: float = 1.0
    backend_retry_max_delay: float = 30.0
    transport_queue_size: int = 500
    enable_local_spool: bool = True
    spool_db_path: Optional[str] = "agent_transport_spool.db"
    max_spool_records: int = 2000
    agent_api_key: Optional[str] = "rs-agent-secret-key-prod"

    # Phase 4: Defensive Response & Containment
    response_dry_run: bool = True
    quarantine_directory: str = "data/quarantine"
    enable_auto_containment: bool = False
    require_approval_for_isolation: bool = True
    require_approval_for_termination: bool = False

    # Logging Configuration
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    def validate(self) -> None:
        """Validates configuration parameters."""
        if self.collection_interval_seconds <= 0:
            raise ValueError("collection_interval_seconds must be positive.")
        if self.inference_interval_seconds <= 0:
            raise ValueError("inference_interval_seconds must be positive.")
        if not self.sliding_window_durations:
            raise ValueError("sliding_window_durations cannot be empty.")
        if any(w <= 0 for w in self.sliding_window_durations):
            raise ValueError("All sliding window durations must be positive integers.")
        if self.buffer_retention_seconds < max(self.sliding_window_durations):
            raise ValueError("buffer_retention_seconds must be greater than maximum sliding window duration.")
        if self.alert_deduplication_seconds < 0:
            raise ValueError("alert_deduplication_seconds cannot be negative.")
        if self.incident_correlation_seconds < 0:
            raise ValueError("incident_correlation_seconds cannot be negative.")
        if self.backend_request_timeout <= 0:
            raise ValueError("backend_request_timeout must be positive.")
        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive.")
        if self.transport_queue_size <= 0:
            raise ValueError("transport_queue_size must be positive.")
        if self.max_spool_records <= 0:
            raise ValueError("max_spool_records must be positive.")

    def to_dict(self) -> Dict[str, Any]:
        """Converts configuration into a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentConfig":
        """Instantiates AgentConfig from a dictionary."""
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        cfg = cls(**filtered)
        cfg.validate()
        return cfg

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Loads configuration from environment variables with fallback defaults."""
        data: Dict[str, Any] = {}
        
        if "RANSOMSHIELD_AGENT_ID" in os.environ:
            data["agent_id"] = os.environ["RANSOMSHIELD_AGENT_ID"]
        if "RANSOMSHIELD_COLLECTION_INTERVAL" in os.environ:
            data["collection_interval_seconds"] = float(os.environ["RANSOMSHIELD_COLLECTION_INTERVAL"])
        if "RANSOMSHIELD_INFERENCE_INTERVAL" in os.environ:
            data["inference_interval_seconds"] = float(os.environ["RANSOMSHIELD_INFERENCE_INTERVAL"])
        if "RANSOMSHIELD_LOG_LEVEL" in os.environ:
            data["log_level"] = os.environ["RANSOMSHIELD_LOG_LEVEL"]
        if "RANSOMSHIELD_SYSMON_ENABLED" in os.environ:
            data["sysmon_enabled"] = os.environ["RANSOMSHIELD_SYSMON_ENABLED"].lower() in ("true", "1", "yes")
        if "RANSOMSHIELD_WATCHDOG_ENABLED" in os.environ:
            data["watchdog_enabled"] = os.environ["RANSOMSHIELD_WATCHDOG_ENABLED"].lower() in ("true", "1", "yes")
        if "RANSOMSHIELD_PSUTIL_ENABLED" in os.environ:
            data["psutil_enabled"] = os.environ["RANSOMSHIELD_PSUTIL_ENABLED"].lower() in ("true", "1", "yes")
        if "RANSOMSHIELD_INFERENCE_ENABLED" in os.environ:
            data["inference_enabled"] = os.environ["RANSOMSHIELD_INFERENCE_ENABLED"].lower() in ("true", "1", "yes")
        if "RANSOMSHIELD_ALERTING_ENABLED" in os.environ:
            data["enable_alerting"] = os.environ["RANSOMSHIELD_ALERTING_ENABLED"].lower() in ("true", "1", "yes")
        if "RANSOMSHIELD_RESPONSE_DRY_RUN" in os.environ:
            data["response_dry_run"] = os.environ["RANSOMSHIELD_RESPONSE_DRY_RUN"].lower() in ("true", "1", "yes")
        if "RANSOMSHIELD_QUARANTINE_DIR" in os.environ:
            data["quarantine_directory"] = os.environ["RANSOMSHIELD_QUARANTINE_DIR"]
        if "RANSOMSHIELD_ENABLE_AUTO_CONTAINMENT" in os.environ:
            data["enable_auto_containment"] = os.environ["RANSOMSHIELD_ENABLE_AUTO_CONTAINMENT"].lower() in ("true", "1", "yes")
            
        return cls.from_dict(data)

    @classmethod
    def from_json_file(cls, file_path: str) -> "AgentConfig":
        """Loads configuration from a JSON file."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
