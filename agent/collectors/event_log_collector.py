"""
RansomShield AI — Windows Event Log Collector
Phase 2B: Windows Endpoint Monitoring Agent — Live Collectors

Monitors Windows Event Log channels (System/Application/Security) via win32evtlog.
Captures system execution records (e.g., Security Event ID 4688, shadow copy commands)
with graceful fallback when unprivileged or running on non-Windows environments.
"""

import time
import platform
import threading
from typing import List, Optional, Dict, Any

try:
    import win32evtlog
    import win32evtlogutil
    PYWIN32_AVAILABLE = True
except ImportError:
    win32evtlog = None
    win32evtlogutil = None
    PYWIN32_AVAILABLE = False

from agent.collectors.base import WindowsEventLogCollectorInterface
from agent.models.telemetry import (
    BaseTelemetryEvent,
    SystemEvent,
    TelemetryEventType,
)
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer


class WindowsEventLogCollector(WindowsEventLogCollectorInterface):
    """
    Windows Event Log monitor with unprivileged graceful fallback.
    """

    def __init__(
        self,
        buffer: Optional[InMemoryTelemetryBuffer] = None,
        channel: str = "Application",
        poll_interval: float = 3.0,
        name: str = "WindowsEventLogCollector",
    ):
        super().__init__(name=name)
        self.buffer = buffer
        self.channel = channel
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._log_handle = None

    def is_available(self) -> bool:
        if platform.system().lower() != "windows" or not PYWIN32_AVAILABLE:
            return False

        try:
            handle = win32evtlog.OpenEventLog(None, self.channel)
            if handle:
                win32evtlog.CloseEventLog(handle)
                return True
            return False
        except Exception:
            return False

    def start(self) -> None:
        """Starts Windows Event Log polling loop."""
        if not self.is_available():
            return

        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._poll_loop,
                name="WindowsEventLogCollectorWorker",
                daemon=True,
            )
            self._worker_thread.start()

    def stop(self) -> None:
        """Stops event log polling loop cleanly."""
        with self._lock:
            if not self._is_running:
                return
            self._stop_event.set()
            self._is_running = False

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

    def _poll_loop(self) -> None:
        """Background thread polling loop."""
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
        Reads recent event log records.
        """
        if not self.is_available():
            return []

        events: List[BaseTelemetryEvent] = []
        now = time.time()
        handle = None

        try:
            handle = win32evtlog.OpenEventLog(None, self.channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_records = win32evtlog.ReadEventLog(handle, flags, 0)
            
            # Read up to 10 recent records
            for record in (raw_records[:10] if raw_records else []):
                evt_id = record.EventID & 0xFFFF
                src_name = str(record.SourceName)
                
                sys_ev = SystemEvent(
                    timestamp=now,
                    event_type=TelemetryEventType.SystemEvent,
                    source="Windows Event Log",
                    sysmon_event_id=evt_id,
                    provider_name=src_name,
                    channel=self.channel,
                    raw_data={
                        "event_category": int(record.EventCategory),
                        "record_number": int(record.RecordNumber),
                        "time_generated": str(record.TimeGenerated),
                    },
                )
                events.append(sys_ev)
        except Exception:
            pass
        finally:
            if handle:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass

        return events
