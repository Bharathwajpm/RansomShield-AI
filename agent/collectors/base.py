"""
RansomShield AI — Collector Interfaces & Base Classes
Phase 2A: Windows Agent Foundation

Defines the formal contracts and interfaces for endpoint telemetry collectors:
- ProcessCollectorInterface (psutil process tree inspection)
- FileCollectorInterface (watchdog filesystem events)
- SysmonCollectorInterface (Microsoft-Windows-Sysmon operational channel)
- WindowsEventLogCollectorInterface (Windows Security Event 4688 / Task Scheduler)
- NetworkCollectorInterface (psutil socket telemetry / Sysmon Event 3)
"""

import abc
import platform
from typing import List, Dict, Any, Optional
from agent.models.telemetry import BaseTelemetryEvent


class BaseCollector(abc.ABC):
    """
    Abstract base interface for all telemetry collectors.
    """

    def __init__(self, name: str):
        self.name = name
        self._is_running: bool = False

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Checks if the underlying OS capability/library is available."""
        pass

    @abc.abstractmethod
    def start(self) -> None:
        """Starts the collector monitoring routine."""
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """Stops the collector and releases resources."""
        pass

    @abc.abstractmethod
    def collect(self) -> List[BaseTelemetryEvent]:
        """
        Collects pending telemetry events.
        In Phase 2A, returns an empty list or stub until Phase 2B implements live polling.
        """
        pass

    def status(self) -> Dict[str, Any]:
        """Returns the current operational status of the collector."""
        return {
            "name": self.name,
            "running": self._is_running,
            "available": self.is_available(),
            "platform": platform.system(),
        }


class ProcessCollectorInterface(BaseCollector):
    """
    Interface for process lifecycle and hierarchy monitoring (psutil).
    """

    def __init__(self, name: str = "ProcessCollector"):
        super().__init__(name)

    def is_available(self) -> bool:
        try:
            import psutil
            return True
        except ImportError:
            return False

    def start(self) -> None:
        if self.is_available():
            self._is_running = True

    def stop(self) -> None:
        self._is_running = False

    def collect(self) -> List[BaseTelemetryEvent]:
        """Stub for Phase 2A — live polling implemented in Phase 2B."""
        return []


class FileCollectorInterface(BaseCollector):
    """
    Interface for filesystem modification, rename, and deletion monitoring (watchdog).
    """

    def __init__(self, monitored_paths: Optional[List[str]] = None, name: str = "FileCollector"):
        super().__init__(name)
        self.monitored_paths = monitored_paths or []

    def is_available(self) -> bool:
        try:
            import watchdog
            return True
        except ImportError:
            return False

    def start(self) -> None:
        if self.is_available():
            self._is_running = True

    def stop(self) -> None:
        self._is_running = False

    def collect(self) -> List[BaseTelemetryEvent]:
        """Stub for Phase 2A — live watchdog event queue implemented in Phase 2B."""
        return []


class SysmonCollectorInterface(BaseCollector):
    """
    Interface for Microsoft-Windows-Sysmon operational channel subscriber.
    """

    def __init__(self, name: str = "SysmonCollector"):
        super().__init__(name)

    def is_available(self) -> bool:
        # Requires Windows OS and pywin32 / win32evtlog
        if platform.system().lower() != "windows":
            return False
        try:
            import win32evtlog
            return True
        except ImportError:
            return False

    def start(self) -> None:
        if self.is_available():
            self._is_running = True

    def stop(self) -> None:
        self._is_running = False

    def collect(self) -> List[BaseTelemetryEvent]:
        """Stub for Phase 2A — live Sysmon event parsing implemented in Phase 2B."""
        return []


class WindowsEventLogCollectorInterface(BaseCollector):
    """
    Interface for Windows Security & System Event Log reader (Event ID 4688, etc.).
    """

    def __init__(self, name: str = "WindowsEventLogCollector"):
        super().__init__(name)

    def is_available(self) -> bool:
        if platform.system().lower() != "windows":
            return False
        try:
            import win32evtlog
            return True
        except ImportError:
            return False

    def start(self) -> None:
        if self.is_available():
            self._is_running = True

    def stop(self) -> None:
        self._is_running = False

    def collect(self) -> List[BaseTelemetryEvent]:
        """Stub for Phase 2A — live Windows Security event log reader implemented in Phase 2B."""
        return []


class NetworkCollectorInterface(BaseCollector):
    """
    Interface for socket connection and network activity monitoring.
    """

    def __init__(self, name: str = "NetworkCollector"):
        super().__init__(name)

    def is_available(self) -> bool:
        try:
            import psutil
            return True
        except ImportError:
            return False

    def start(self) -> None:
        if self.is_available():
            self._is_running = True

    def stop(self) -> None:
        self._is_running = False

    def collect(self) -> List[BaseTelemetryEvent]:
        """Stub for Phase 2A — live psutil net_connections implemented in Phase 2B."""
        return []
