"""
RansomShield AI — Microsoft-Windows-Sysmon Operational Collector
Phase 2B: Windows Endpoint Monitoring Agent — Live Collectors

Subscribes to or queries the Microsoft-Windows-Sysmon/Operational channel via win32evtlog.
Gracefully detects whether Sysmon is installed on the host and fails safely if unavailable.
Captures Sysmon Event IDs:
- Event ID 1: Process Creation
- Event ID 2: File Creation Time Alteration (Timestomping)
- Event ID 3: Network Connection
- Event ID 11: File Creation
- Event ID 13: Registry Value Set
- Event ID 17/18: Named Pipe Creation/Connection
- Event ID 23/26: File Deletion
"""

import time
import platform
import threading
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Any

try:
    import win32evtlog
    import win32evtlogutil
    PYWIN32_AVAILABLE = True
except ImportError:
    win32evtlog = None
    win32evtlogutil = None
    PYWIN32_AVAILABLE = False

from agent.collectors.base import SysmonCollectorInterface
from agent.models.telemetry import (
    BaseTelemetryEvent,
    ProcessEvent,
    FileEvent,
    RegistryEvent,
    NetworkEvent,
    PipeEvent,
    SystemEvent,
    TelemetryEventType,
)
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer


class SysmonCollector(SysmonCollectorInterface):
    """
    Windows Sysmon operational channel subscriber with graceful fallback.
    """

    CHANNEL_NAME = "Microsoft-Windows-Sysmon/Operational"

    def __init__(
        self,
        buffer: Optional[InMemoryTelemetryBuffer] = None,
        poll_interval: float = 2.0,
        name: str = "SysmonCollector",
    ):
        super().__init__(name=name)
        self.buffer = buffer
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._channel_available: Optional[bool] = None

    def is_available(self) -> bool:
        """
        Tests whether the operating system is Windows, pywin32 is installed,
        and the Sysmon operational event log channel exists.
        """
        if platform.system().lower() != "windows" or not PYWIN32_AVAILABLE:
            return False

        if self._channel_available is not None:
            return self._channel_available

        try:
            flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            query_handle = win32evtlog.EvtQuery(self.CHANNEL_NAME, flags)
            self._channel_available = query_handle is not None
            return self._channel_available
        except Exception:
            self._channel_available = False
            return False

    def start(self) -> None:
        """Starts Sysmon event polling loop if the channel is available."""
        if not self.is_available():
            return

        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._poll_loop,
                name="SysmonCollectorWorker",
                daemon=True,
            )
            self._worker_thread.start()

    def stop(self) -> None:
        """Stops Sysmon polling thread cleanly."""
        with self._lock:
            if not self._is_running:
                return
            self._stop_event.set()
            self._is_running = False

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

    def _poll_loop(self) -> None:
        """Background polling loop querying recent Sysmon events."""
        while not self._stop_event.is_set():
            try:
                events = self.collect()
                if self.buffer is not None and events:
                    self.buffer.extend(events)
            except Exception:
                pass

            self._stop_event.wait(timeout=self.poll_interval)

    def collect(self) -> List[BaseTelemetryEvent]:
        """
        Queries recent events from the Sysmon operational channel.
        """
        if not self.is_available():
            return []

        events: List[BaseTelemetryEvent] = []
        now = time.time()

        try:
            flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            query_handle = win32evtlog.EvtQuery(self.CHANNEL_NAME, flags)
            
            # Fetch up to 20 recent events
            raw_events = win32evtlog.EvtNext(query_handle, 20)
            for raw_ev in raw_events:
                xml_content = win32evtlog.EvtRender(raw_ev, win32evtlog.EvtRenderEventXml)
                parsed_ev = self._parse_sysmon_xml(xml_content, now)
                if parsed_ev:
                    events.append(parsed_ev)
        except Exception:
            pass

        return events

    def _parse_sysmon_xml(self, xml_str: str, default_time: float) -> Optional[BaseTelemetryEvent]:
        """Parses a rendered Sysmon XML event into a typed telemetry model."""
        try:
            root = ET.fromstring(xml_str)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            system_elem = root.find("ns:System", ns)
            if system_elem is None:
                return None

            event_id_elem = system_elem.find("ns:EventID", ns)
            event_id = int(event_id_elem.text) if (event_id_elem is not None and event_id_elem.text) else 0

            # Extract event data elements
            data_dict = {}
            event_data_elem = root.find("ns:EventData", ns)
            if event_data_elem is not None:
                for data_item in event_data_elem.findall("ns:Data", ns):
                    name_attr = data_item.attrib.get("Name")
                    if name_attr:
                        data_dict[name_attr] = data_item.text or ""

            # Map specific Sysmon Event IDs to typed telemetry events
            if event_id == 1:  # Process Create
                return ProcessEvent(
                    timestamp=default_time,
                    event_type=TelemetryEventType.ProcessCreate,
                    source="Sysmon",
                    pid=int(data_dict.get("ProcessId", 0)),
                    parent_pid=int(data_dict.get("ParentProcessId", 0)) if "ParentProcessId" in data_dict else None,
                    process_name=data_dict.get("OriginalFileName", data_dict.get("Image", "")),
                    executable_path=data_dict.get("Image"),
                    command_line=data_dict.get("CommandLine"),
                    user=data_dict.get("User"),
                )
            elif event_id == 11:  # File Create
                return FileEvent(
                    timestamp=default_time,
                    event_type=TelemetryEventType.FileCreate,
                    source="Sysmon",
                    path=data_dict.get("TargetFilename", ""),
                    pid=int(data_dict.get("ProcessId", 0)) if "ProcessId" in data_dict else None,
                )
            elif event_id in (23, 26):  # File Delete
                return FileEvent(
                    timestamp=default_time,
                    event_type=TelemetryEventType.FileDeleteArchived if event_id == 26 else TelemetryEventType.FileDelete,
                    source="Sysmon",
                    path=data_dict.get("TargetFilename", ""),
                    pid=int(data_dict.get("ProcessId", 0)) if "ProcessId" in data_dict else None,
                )
            elif event_id == 13:  # Registry Value Set
                return RegistryEvent(
                    timestamp=default_time,
                    event_type=TelemetryEventType.RegistryValueSet,
                    source="Sysmon",
                    key_path=data_dict.get("TargetObject", ""),
                    value_name=data_dict.get("Details", ""),
                    pid=int(data_dict.get("ProcessId", 0)) if "ProcessId" in data_dict else None,
                )
            elif event_id in (17, 18):  # Pipe Created / Connected
                return PipeEvent(
                    timestamp=default_time,
                    event_type=TelemetryEventType.PipeCreated if event_id == 17 else TelemetryEventType.PipeConnected,
                    source="Sysmon",
                    pipe_name=data_dict.get("PipeName", ""),
                    pid=int(data_dict.get("ProcessId", 0)) if "ProcessId" in data_dict else None,
                )
            else:
                return SystemEvent(
                    timestamp=default_time,
                    event_type=TelemetryEventType.SystemEvent,
                    source="Sysmon",
                    sysmon_event_id=event_id,
                    provider_name="Microsoft-Windows-Sysmon",
                    raw_data=data_dict,
                )
        except Exception:
            return None

    def status(self) -> Dict[str, Any]:
        """Returns diagnostic status."""
        stat = super().status()
        stat["channel"] = self.CHANNEL_NAME
        stat["sysmon_detected"] = self.is_available()
        return stat
