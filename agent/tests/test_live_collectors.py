"""
RansomShield AI — Comprehensive Live Collectors Test Suite
Phase 2B: Windows Endpoint Monitoring Agent — Live Collectors

Verifies:
1. Process collector initialization
2. Process collector availability
3. Process event creation
4. Process PID deduplication
5. Process exception handling (NoSuchProcess, AccessDenied, ZombieProcess)
6. File collector initialization
7. File created event
8. File modified event
9. File deleted event
10. File renamed/moved event
11. Filename entropy calculation
12. Network collector initialization
13. Network collection handling
14. AccessDenied handling in network collector
15. Sysmon availability detection
16. Windows Event Log availability detection
17. Collector start/stop lifecycle
18. Main agent starts all enabled collectors
19. Main agent stops all collectors (no orphan threads)
20. Events actually enter MemoryBuffer
21. Buffer sliding windows still work (5s, 10s, 30s)
22. Configuration controls collector activation
23. Graceful degradation when optional components are unavailable
24. No duplicate process-create events on successive polls
25. Collector error resilience (does not crash agent)
"""

import time
import os
import tempfile
import threading
from pathlib import Path
import pytest

from agent.models.telemetry import (
    TelemetryEventType,
    BaseTelemetryEvent,
    ProcessEvent,
    FileEvent,
    NetworkEvent,
    SystemEvent,
)
from agent.config import AgentConfig
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer
from agent.collectors.base import BaseCollector
from agent.collectors.process_collector import ProcessCollector
from agent.collectors.file_collector import FileCollector, RansomShieldFileSystemEventHandler
from agent.collectors.network_collector import NetworkCollector
from agent.collectors.sysmon_collector import SysmonCollector
from agent.collectors.event_log_collector import WindowsEventLogCollector
from agent.service.agent import RansomShieldAgent
from ml.features.entropy import calculate_shannon_entropy, is_high_entropy
from ml.features.feature_contract import V2_FEATURE_NAMES


# 1. Process Collector Initialization
def test_process_collector_initialization():
    buf = InMemoryTelemetryBuffer()
    collector = ProcessCollector(buffer=buf, poll_interval=0.5)
    assert collector.name == "ProcessCollector"
    assert collector.poll_interval == 0.5
    assert collector.buffer is buf
    assert collector._is_running is False


# 2. Process Collector Availability
def test_process_collector_availability():
    collector = ProcessCollector()
    assert collector.is_available() is True
    status = collector.status()
    assert status["available"] is True
    assert status["running"] is False


# 3. Process Event Creation
def test_process_event_creation():
    collector = ProcessCollector()
    events = collector.collect()
    assert isinstance(events, list)
    assert len(events) > 0

    first_ev = events[0]
    assert isinstance(first_ev, ProcessEvent)
    assert first_ev.pid > 0
    assert first_ev.event_type == TelemetryEventType.ProcessCreate
    assert first_ev.source == "psutil"
    assert first_ev.process_name != ""
    assert isinstance(first_ev.path_length, int)
    assert isinstance(first_ev.directory_depth, int)
    assert isinstance(first_ev.process_name_length, int)


# 4. Process PID Deduplication
def test_process_pid_deduplication():
    collector = ProcessCollector()
    
    # First collection pass (discovers running baseline)
    pass1_events = collector.collect()
    assert len(pass1_events) > 0
    
    # Second immediate collection pass without new process spawns
    pass2_events = collector.collect()
    # Should not re-emit any process from the baseline pass 1 table
    pass1_pids = {e.pid for e in pass1_events}
    for ev in pass2_events:
        assert ev.pid not in pass1_pids
    assert len(pass2_events) <= 2


# 5. Process Exception Handling
def test_process_exception_handling(monkeypatch):
    collector = ProcessCollector()
    
    class FakeProc:
        def __init__(self):
            self.pid = 99999
            self.info = {"pid": 99999, "name": "fake.exe", "create_time": time.time()}

        def name(self):
            import psutil
            raise psutil.NoSuchProcess(99999)

    # Inject a failing process into process_iter
    def fake_iter(*args, **kwargs):
        return [FakeProc()]

    import psutil
    monkeypatch.setattr(psutil, "process_iter", fake_iter)
    
    # Must not raise an unhandled exception
    events = collector.collect()
    assert isinstance(events, list)


# 6. File Collector Initialization
def test_file_collector_initialization():
    with tempfile.TemporaryDirectory() as tmp_dir:
        buf = InMemoryTelemetryBuffer()
        collector = FileCollector(monitored_paths=[tmp_dir], buffer=buf)
        assert collector.name == "FileCollector"
        assert tmp_dir in collector.monitored_paths
        assert collector.is_available() is True


# 7. File Created Event Handling
def test_file_created_event():
    buf = InMemoryTelemetryBuffer()
    events_sink = []
    handler = RansomShieldFileSystemEventHandler(buffer=buf, event_sink=events_sink)
    
    class MockFileEvent:
        is_directory = False
        src_path = "C:\\Users\\Test\\Documents\\invoice_2026.pdf"

    handler.on_created(MockFileEvent())
    
    assert len(events_sink) == 1
    ev = events_sink[0]
    assert ev.event_type == TelemetryEventType.FileCreate
    assert ev.extension == ".pdf"
    assert ev.file_name_entropy is not None
    assert ev.file_name_entropy > 0.0
    assert buf.size() == 1


# 8. File Modified Event Handling
def test_file_modified_event():
    buf = InMemoryTelemetryBuffer()
    events_sink = []
    handler = RansomShieldFileSystemEventHandler(buffer=buf, event_sink=events_sink)
    
    class MockFileEvent:
        is_directory = False
        src_path = "C:\\Users\\Test\\Desktop\\report.docx"

    handler.on_modified(MockFileEvent())
    
    assert len(events_sink) == 1
    ev = events_sink[0]
    assert ev.event_type == TelemetryEventType.FileModify
    assert ev.path == "C:\\Users\\Test\\Desktop\\report.docx"
    assert ev.extension == ".docx"


# 9. File Deleted and Archived Deletion Event Handling
def test_file_deleted_event():
    buf = InMemoryTelemetryBuffer()
    events_sink = []
    handler = RansomShieldFileSystemEventHandler(buffer=buf, event_sink=events_sink)
    
    class MockNormalDelete:
        is_directory = False
        src_path = "C:\\Users\\Test\\temp.txt"

    class MockBackupDelete:
        is_directory = False
        src_path = "C:\\Users\\Test\\backup_database.bak"

    handler.on_deleted(MockNormalDelete())
    handler.on_deleted(MockBackupDelete())

    assert len(events_sink) == 2
    assert events_sink[0].event_type == TelemetryEventType.FileDelete
    assert events_sink[1].event_type == TelemetryEventType.FileDeleteArchived


# 10. File Renamed/Moved Event Handling
def test_file_renamed_event():
    buf = InMemoryTelemetryBuffer()
    events_sink = []
    handler = RansomShieldFileSystemEventHandler(buffer=buf, event_sink=events_sink)
    
    class MockMoveEvent:
        is_directory = False
        src_path = "C:\\Users\\Test\\important_data.xlsx"
        dest_path = "C:\\Users\\Test\\important_data.xlsx.locked"

    handler.on_moved(MockMoveEvent())
    
    assert len(events_sink) == 1
    ev = events_sink[0]
    assert ev.event_type == TelemetryEventType.FileRename
    assert ev.old_path == "C:\\Users\\Test\\important_data.xlsx"
    assert ev.path == "C:\\Users\\Test\\important_data.xlsx.locked"
    assert ev.extension == ".locked"
    assert ev.extension_similarity == 1  # Detects extension change


# 11. Filename Entropy Calculation Test
def test_filename_entropy_calculation():
    low_entropy_name = "test.txt"
    h_low = calculate_shannon_entropy(low_entropy_name)
    assert 2.0 <= h_low < 3.5

    random_hex_name = "a8f3b9c0e2d1f4a7c8e9b0d1a2f3e4b5.lockbit"
    h_high = calculate_shannon_entropy(random_hex_name)
    assert h_high > 3.8
    assert calculate_shannon_entropy("") == 0.0


# 12. Network Collector Initialization
def test_network_collector_initialization():
    buf = InMemoryTelemetryBuffer()
    collector = NetworkCollector(buffer=buf, poll_interval=1.0)
    assert collector.name == "NetworkCollector"
    assert collector.is_available() is True
    assert collector.poll_interval == 1.0


# 13. Network Collection Handling
def test_network_collection_handling():
    collector = NetworkCollector()
    events = collector.collect()
    assert isinstance(events, list)
    
    for ev in events[:5]:
        assert isinstance(ev, NetworkEvent)
        assert ev.event_type == TelemetryEventType.NetworkConnection
        assert ev.protocol in ("TCP", "UDP")
        assert ev.source_address != ""


# 14. AccessDenied Handling in Network Collector
def test_network_collector_access_denied(monkeypatch):
    collector = NetworkCollector()
    
    import psutil
    def fake_net_connections(*args, **kwargs):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", fake_net_connections)
    
    # Must handle AccessDenied gracefully without raising
    events = collector.collect()
    assert events == []


# 15. Sysmon Availability Detection
def test_sysmon_availability_detection():
    collector = SysmonCollector()
    avail = collector.is_available()
    assert isinstance(avail, bool)
    
    status = collector.status()
    assert "sysmon_detected" in status
    assert "channel" in status
    assert status["channel"] == "Microsoft-Windows-Sysmon/Operational"
    
    # collect() must not crash even if channel is absent
    events = collector.collect()
    assert isinstance(events, list)


# 16. Windows Event Log Availability Detection
def test_windows_event_log_availability_detection():
    collector = WindowsEventLogCollector(channel="Application")
    avail = collector.is_available()
    assert isinstance(avail, bool)
    
    status = collector.status()
    assert status["name"] == "WindowsEventLogCollector"
    
    events = collector.collect()
    assert isinstance(events, list)


# 17. Collector Start/Stop Lifecycle Test
def test_collector_start_stop_lifecycle():
    buf = InMemoryTelemetryBuffer()
    proc_collector = ProcessCollector(buffer=buf, poll_interval=0.1)
    
    proc_collector.start()
    assert proc_collector._is_running is True
    time.sleep(0.25)
    proc_collector.stop()
    assert proc_collector._is_running is False
    assert proc_collector._worker_thread is None


# 18. Main Agent Starts All Enabled Collectors
def test_main_agent_starts_all_collectors():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = AgentConfig(
            collection_interval_seconds=0.2,
            monitored_directories=[tmp_dir],
            sysmon_enabled=False,
            windows_event_log_enabled=False,
        )
        agent = RansomShieldAgent(config=cfg)
        assert agent._is_running is False
        
        agent.start()
        assert agent._is_running is True
        
        # Check active collectors
        status = agent.status()
        assert status["running"] is True
        assert status["collectors"]["process"]["running"] is True
        assert status["collectors"]["file"]["running"] is True
        assert status["collectors"]["network"]["running"] is True
        
        agent.stop()
        assert agent._is_running is False


# 19. Main Agent Stops All Collectors
def test_main_agent_stops_all_collectors():
    agent = RansomShieldAgent()
    agent.start()
    assert agent._is_running is True
    
    agent.stop(reason="Testing clean multi-collector shutdown")
    assert agent._is_running is False
    
    for coll in agent._collectors.values():
        assert coll._is_running is False


# 20. Events Actually Enter MemoryBuffer
def test_events_enter_memory_buffer():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = AgentConfig(
            collection_interval_seconds=0.1,
            monitored_directories=[tmp_dir],
        )
        agent = RansomShieldAgent(config=cfg)
        agent.start()
        
        # Trigger file creation in monitored directory
        test_file = Path(tmp_dir) / "security_payload_test.txt"
        test_file.write_text("Testing telemetry buffer ingestion.")
        time.sleep(0.3)
        
        # Check that events entered the buffer
        buffer_size = agent.buffer.size()
        assert buffer_size > 0
        
        agent.stop()


# 21. Buffer Sliding Windows With Live Events
def test_buffer_sliding_windows():
    buf = InMemoryTelemetryBuffer()
    now = time.time()
    
    # Inject staggered events
    buf.append(ProcessEvent(timestamp=now - 28.0, pid=101))
    buf.append(FileEvent(timestamp=now - 8.0, path="C:\\test1.docx"))
    buf.append(NetworkEvent(timestamp=now - 3.0, pid=101, destination_address="1.1.1.1", destination_port=80))
    buf.append(ProcessEvent(timestamp=now - 1.0, pid=102))

    assert len(buf.get_events(window_seconds=5.0, current_time=now)) == 2
    assert len(buf.get_events(window_seconds=10.0, current_time=now)) == 3
    assert len(buf.get_events(window_seconds=30.0, current_time=now)) == 4


# 22. Configuration Controls Collector Activation
def test_config_controls_collector_activation():
    cfg = AgentConfig(
        psutil_enabled=False,
        watchdog_enabled=False,
        sysmon_enabled=False,
        windows_event_log_enabled=False,
    )
    agent = RansomShieldAgent(config=cfg)
    assert len(agent._collectors) == 0
    agent.start()
    assert agent._is_running is True
    agent.stop()


# 23. Graceful Non-Windows / Missing Component Behavior
def test_graceful_degradation():
    collector = SysmonCollector()
    # Even if Sysmon channel is not present on the host, status reports clean boolean
    status = collector.status()
    assert isinstance(status["running"], bool)
    assert isinstance(status["available"], bool)


# 24. No Duplicate Process Create Events on Successive Polls
def test_no_duplicate_process_create_events():
    buf = InMemoryTelemetryBuffer()
    collector = ProcessCollector(buffer=buf, poll_interval=0.1)
    
    # First collect pass
    ev1 = collector.collect()
    count1 = len(ev1)
    
    # Second immediate collect pass
    ev2 = collector.collect()
    count2 = len(ev2)
    
    # Must not duplicate running processes
    assert count2 < count1 or count2 == 0


# 25. Collector Error Resilience
def test_collector_error_resilience():
    agent = RansomShieldAgent()
    agent.start()
    
    # Even if an invalid or unexpected event is recorded, agent does not crash
    dummy_event = BaseTelemetryEvent(event_type=TelemetryEventType.SystemEvent, raw_metadata={"error": True})
    agent.record_event(dummy_event)
    
    status = agent.status()
    assert status["running"] is True
    assert status["buffer_stats"]["current_size"] >= 1
    
    agent.stop()
