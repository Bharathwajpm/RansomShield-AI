"""
RansomShield AI — Strongly Typed Telemetry Data Contract
Phase 2A: Windows Agent Foundation

Defines the core telemetry event models representing endpoint behavior
across Process, File, Registry, Network, Named Pipe, and System/Sysmon event domains.
All structures strictly support the telemetry required by Model V2.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Union
import enum
import time
import uuid


class TelemetryEventType(str, enum.Enum):
    """
    Standardized event types representing Windows endpoint operations.
    Aligned with Windows Sysmon event IDs and OS notification events.
    """
    # Process Lifecycle (Sysmon Event ID 1 / psutil)
    ProcessCreate = "ProcessCreate"
    ProcessTerminate = "ProcessTerminate"

    # File System Activity (Sysmon Event IDs 2, 11, 23, 26 / watchdog)
    FileCreate = "FileCreate"
    FileDelete = "FileDelete"
    FileModify = "FileModify"
    FileRename = "FileRename"
    FileTimeChanged = "FileTimeChanged"
    FileDeleteArchived = "FileDeleteArchived"

    # Registry Activity (Sysmon Event IDs 12, 13, 14)
    RegistryValueSet = "RegistryValueSet"
    RegistryKeyCreate = "RegistryKeyCreate"
    RegistryKeyDelete = "RegistryKeyDelete"

    # Network Activity (Sysmon Event ID 3 / psutil)
    NetworkConnection = "NetworkConnection"

    # Named Pipes (Sysmon Event IDs 17, 18)
    PipeCreated = "PipeCreated"
    PipeConnected = "PipeConnected"

    # System & Windows Event Logs (Event ID 4688, etc.)
    SystemEvent = "SystemEvent"


@dataclass
class BaseTelemetryEvent:
    """Base structure for all timestamped telemetry events."""
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: TelemetryEventType = TelemetryEventType.SystemEvent
    source: str = "agent"
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the event into a dictionary."""
        d = asdict(self)
        d["event_type"] = self.event_type.value if isinstance(self.event_type, enum.Enum) else str(self.event_type)
        return d


@dataclass
class ProcessEvent(BaseTelemetryEvent):
    """
    Telemetry event capturing process execution and tree hierarchy.
    Maps to Model V2 features: Process_Create, process-related, suspicious_path,
    system_executable, path_length, directory_depth, process_name_length,
    process_vs_parent_freq_ratio, executable_depth_diff, parent_is_system_executable.
    """
    event_type: TelemetryEventType = TelemetryEventType.ProcessCreate
    source: str = "psutil"
    pid: int = 0
    parent_pid: Optional[int] = None
    process_name: str = ""
    executable_path: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    is_signed: Optional[bool] = None
    is_system_executable: Optional[bool] = None
    is_suspicious_path: Optional[bool] = None
    path_length: Optional[int] = None
    directory_depth: Optional[int] = None
    process_name_length: Optional[int] = None
    parent_name: Optional[str] = None
    parent_executable_path: Optional[str] = None
    parent_is_system_executable: Optional[bool] = None
    executable_depth_diff: Optional[int] = None
    process_vs_parent_freq_ratio: Optional[float] = None


@dataclass
class FileEvent(BaseTelemetryEvent):
    """
    Telemetry event capturing file operations and path transformations.
    Maps to Model V2 features: File_created, File_Delete_archived,
    File_creation_time_changed, file-related, extension_similarity, file_name_entropy.
    """
    event_type: TelemetryEventType = TelemetryEventType.FileModify
    source: str = "watchdog"
    path: str = ""
    old_path: Optional[str] = None
    extension: Optional[str] = None
    file_name_entropy: Optional[float] = None
    entropy: Optional[float] = None
    is_high_entropy: Optional[bool] = None
    extension_similarity: Optional[int] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None


@dataclass
class RegistryEvent(BaseTelemetryEvent):
    """
    Telemetry event capturing registry modifications.
    Maps to Model V2 features: Registry_value_set.
    """
    event_type: TelemetryEventType = TelemetryEventType.RegistryValueSet
    source: str = "Sysmon"
    key_path: str = ""
    value_name: Optional[str] = None
    value_type: Optional[str] = None
    value_data: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None


@dataclass
class NetworkEvent(BaseTelemetryEvent):
    """
    Telemetry event capturing network socket connections.
    Maps to Model V2 features: network-related.
    """
    event_type: TelemetryEventType = TelemetryEventType.NetworkConnection
    source: str = "Sysmon"
    pid: int = 0
    process_name: Optional[str] = None
    source_address: str = "127.0.0.1"
    source_port: Optional[int] = None
    destination_address: str = "0.0.0.0"
    destination_port: int = 0
    protocol: str = "TCP"
    connection_type: Optional[str] = None


@dataclass
class PipeEvent(BaseTelemetryEvent):
    """
    Telemetry event capturing named pipe creations and connections.
    Maps to Model V2 features: Pipe_Created.
    """
    event_type: TelemetryEventType = TelemetryEventType.PipeCreated
    source: str = "Sysmon"
    pipe_name: str = ""
    pid: Optional[int] = None
    process_name: Optional[str] = None


@dataclass
class SystemEvent(BaseTelemetryEvent):
    """
    Generic system or Windows Event Log observation.
    Captures raw event IDs (e.g. Sysmon Event ID 1-26, Windows Security 4688).
    """
    event_type: TelemetryEventType = TelemetryEventType.SystemEvent
    source: str = "Windows Event Log"
    sysmon_event_id: Optional[int] = None
    provider_name: str = "Microsoft-Windows-Sysmon"
    channel: str = "Microsoft-Windows-Sysmon/Operational"
    raw_data: Optional[Dict[str, Any]] = None
    pid: Optional[int] = None
