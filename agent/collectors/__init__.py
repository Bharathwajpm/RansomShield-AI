"""
RansomShield AI — Agent Collectors Package
Phase 2B: Live Telemetry Collectors

Exports all interface contracts and concrete live collector implementations.
"""

from agent.collectors.base import (
    BaseCollector,
    ProcessCollectorInterface,
    FileCollectorInterface,
    SysmonCollectorInterface,
    WindowsEventLogCollectorInterface,
    NetworkCollectorInterface,
)
from agent.collectors.process_collector import ProcessCollector
from agent.collectors.file_collector import FileCollector
from agent.collectors.network_collector import NetworkCollector
from agent.collectors.sysmon_collector import SysmonCollector
from agent.collectors.event_log_collector import WindowsEventLogCollector

__all__ = [
    # Interfaces
    "BaseCollector",
    "ProcessCollectorInterface",
    "FileCollectorInterface",
    "SysmonCollectorInterface",
    "WindowsEventLogCollectorInterface",
    "NetworkCollectorInterface",
    # Live Collector Implementations
    "ProcessCollector",
    "FileCollector",
    "NetworkCollector",
    "SysmonCollector",
    "WindowsEventLogCollector",
]
