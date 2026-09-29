"""
RansomShield AI — Windows Agent Foundation Test Suite
Phase 2A: Windows Agent Foundation

Tests:
1. Telemetry model creation
2. Optional telemetry fields handling
3. Event type validation
4. Buffer insertion
5. Buffer retrieval within time window
6. 5-second window retrieval
7. 10-second window retrieval
8. 30-second window retrieval
9. Expired event cleanup
10. Thread-safe buffer access
11. Configuration loading and validation
12. Agent start lifecycle
13. Agent stop lifecycle
14. Agent status reporting
15. Collector availability interfaces
16. Model V2 feature contract verification (19 features in exact order)
"""

import time
import threading
import pytest
from pathlib import Path
from typing import List

from agent.models.telemetry import (
    TelemetryEventType,
    BaseTelemetryEvent,
    ProcessEvent,
    FileEvent,
    RegistryEvent,
    NetworkEvent,
    PipeEvent,
    SystemEvent,
)
from agent.config import AgentConfig
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer
from agent.service.agent import RansomShieldAgent
from agent.collectors.base import (
    ProcessCollectorInterface,
    FileCollectorInterface,
    SysmonCollectorInterface,
    WindowsEventLogCollectorInterface,
    NetworkCollectorInterface,
)
from ml.features.feature_contract import V2_FEATURE_NAMES, V2_FEATURE_DEFINITIONS


# 1. Telemetry Model Creation Tests
def test_telemetry_model_creation():
    proc_ev = ProcessEvent(pid=1234, process_name="cmd.exe", command_line="cmd.exe /c whoami")
    assert proc_ev.pid == 1234
    assert proc_ev.process_name == "cmd.exe"
    assert proc_ev.event_type == TelemetryEventType.ProcessCreate
    assert proc_ev.source == "psutil"

    file_ev = FileEvent(path="C:\\Users\\Test\\file.docx", extension=".docx")
    assert file_ev.path == "C:\\Users\\Test\\file.docx"
    assert file_ev.extension == ".docx"
    assert file_ev.event_type == TelemetryEventType.FileModify

    reg_ev = RegistryEvent(key_path="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", value_name="SecurityAgent")
    assert "Run" in reg_ev.key_path
    assert reg_ev.event_type == TelemetryEventType.RegistryValueSet

    net_ev = NetworkEvent(pid=1234, destination_address="192.168.1.50", destination_port=443)
    assert net_ev.destination_port == 443
    assert net_ev.event_type == TelemetryEventType.NetworkConnection

    pipe_ev = PipeEvent(pipe_name="\\pipe\\ransomshield_ipc")
    assert pipe_ev.pipe_name == "\\pipe\\ransomshield_ipc"
    assert pipe_ev.event_type == TelemetryEventType.PipeCreated

    sys_ev = SystemEvent(sysmon_event_id=1, channel="Microsoft-Windows-Sysmon/Operational")
    assert sys_ev.sysmon_event_id == 1
    assert sys_ev.event_type == TelemetryEventType.SystemEvent


# 2. Optional Telemetry Fields Tests
def test_optional_telemetry_fields():
    # Process event without optional fields
    p = ProcessEvent(pid=5678, process_name="notepad.exe")
    assert p.parent_pid is None
    assert p.executable_path is None
    assert p.is_signed is None
    assert p.executable_depth_diff is None
    assert p.process_vs_parent_freq_ratio is None

    # Serialization should include all defined fields without error
    d = p.to_dict()
    assert d["pid"] == 5678
    assert d["event_type"] == "ProcessCreate"
    assert d["parent_pid"] is None


# 3. Event Type Validation Tests
def test_event_type_validation():
    assert TelemetryEventType.ProcessCreate.value == "ProcessCreate"
    assert TelemetryEventType.FileCreate.value == "FileCreate"
    assert TelemetryEventType.FileDelete.value == "FileDelete"
    assert TelemetryEventType.FileRename.value == "FileRename"
    assert TelemetryEventType.FileTimeChanged.value == "FileTimeChanged"
    assert TelemetryEventType.FileDeleteArchived.value == "FileDeleteArchived"
    assert TelemetryEventType.RegistryValueSet.value == "RegistryValueSet"
    assert TelemetryEventType.NetworkConnection.value == "NetworkConnection"
    assert TelemetryEventType.PipeCreated.value == "PipeCreated"
    assert TelemetryEventType.SystemEvent.value == "SystemEvent"


# 4. Buffer Insertion Tests
def test_buffer_insertion():
    buf = InMemoryTelemetryBuffer[BaseTelemetryEvent]()
    assert buf.size() == 0

    ev1 = ProcessEvent(pid=100)
    buf.append(ev1)
    assert buf.size() == 1

    ev2 = FileEvent(path="C:\\test.txt")
    ev3 = NetworkEvent(pid=100, destination_address="8.8.8.8", destination_port=53)
    buf.extend([ev2, ev3])
    assert buf.size() == 3


# 5. Buffer Retrieval Within Time Window Tests
def test_buffer_retrieval_within_window():
    buf = InMemoryTelemetryBuffer[BaseTelemetryEvent]()
    base_time = 1000.0

    buf.append(ProcessEvent(timestamp=base_time - 25.0, pid=1))
    buf.append(ProcessEvent(timestamp=base_time - 8.0, pid=2))
    buf.append(ProcessEvent(timestamp=base_time - 3.0, pid=3))
    buf.append(ProcessEvent(timestamp=base_time - 1.0, pid=4))

    # Retrieve with window = 10.0s (should get events within [990.0, 1000.0])
    events = buf.get_events(window_seconds=10.0, current_time=base_time)
    pids = [getattr(e, "pid", None) for e in events]
    assert pids == [2, 3, 4]


# 6. 5-Second Window Retrieval Test
def test_5_second_window_retrieval():
    buf = InMemoryTelemetryBuffer[BaseTelemetryEvent]()
    now = 5000.0

    buf.append(FileEvent(timestamp=now - 6.0, path="old.txt"))
    buf.append(FileEvent(timestamp=now - 4.5, path="a.txt"))
    buf.append(FileEvent(timestamp=now - 2.0, path="b.txt"))
    buf.append(FileEvent(timestamp=now - 0.5, path="c.txt"))

    events_5s = buf.get_events(window_seconds=5.0, current_time=now)
    assert len(events_5s) == 3
    assert [e.path for e in events_5s] == ["a.txt", "b.txt", "c.txt"]


# 7. 10-Second Window Retrieval Test
def test_10_second_window_retrieval():
    buf = InMemoryTelemetryBuffer[BaseTelemetryEvent]()
    now = 5000.0

    buf.append(RegistryEvent(timestamp=now - 12.0, key_path="Key0"))
    buf.append(RegistryEvent(timestamp=now - 9.0, key_path="Key1"))
    buf.append(RegistryEvent(timestamp=now - 4.0, key_path="Key2"))
    buf.append(RegistryEvent(timestamp=now - 1.0, key_path="Key3"))

    events_10s = buf.get_events(window_seconds=10.0, current_time=now)
    assert len(events_10s) == 3
    assert [e.key_path for e in events_10s] == ["Key1", "Key2", "Key3"]


# 8. 30-Second Window Retrieval Test
def test_30_second_window_retrieval():
    buf = InMemoryTelemetryBuffer[BaseTelemetryEvent]()
    now = 5000.0

    buf.append(ProcessEvent(timestamp=now - 45.0, pid=10))
    buf.append(ProcessEvent(timestamp=now - 28.0, pid=20))
    buf.append(ProcessEvent(timestamp=now - 15.0, pid=30))
    buf.append(ProcessEvent(timestamp=now - 2.0, pid=40))

    events_30s = buf.get_events(window_seconds=30.0, current_time=now)
    assert len(events_30s) == 3
    assert [e.pid for e in events_30s] == [20, 30, 40]


# 9. Expired Event Cleanup Test
def test_expired_event_cleanup():
    buf = InMemoryTelemetryBuffer[BaseTelemetryEvent]()
    now = 10000.0

    # Add old events and fresh events
    buf.append(ProcessEvent(timestamp=now - 150.0, pid=1))
    buf.append(ProcessEvent(timestamp=now - 130.0, pid=2))
    buf.append(ProcessEvent(timestamp=now - 40.0, pid=3))
    buf.append(ProcessEvent(timestamp=now - 10.0, pid=4))

    assert buf.size() == 4
    # Purge events older than 120 seconds
    purged = buf.cleanup_expired(retention_seconds=120.0, current_time=now)
    assert purged == 2
    assert buf.size() == 2

    remaining_pids = [getattr(e, "pid", None) for e in buf.get_events(window_seconds=100.0, current_time=now)]
    assert remaining_pids == [3, 4]


# 10. Thread-Safe Buffer Access Test
def test_thread_safe_buffer_access():
    buf = InMemoryTelemetryBuffer[BaseTelemetryEvent]()
    num_threads = 8
    events_per_thread = 250

    def worker_writer(thread_id: int):
        for i in range(events_per_thread):
            buf.append(ProcessEvent(pid=thread_id * 1000 + i, process_name=f"proc_{thread_id}_{i}"))

    def worker_reader():
        for _ in range(50):
            _ = buf.get_events(window_seconds=60.0)
            time.sleep(0.001)

    threads: List[threading.Thread] = []
    for t_id in range(num_threads):
        threads.append(threading.Thread(target=worker_writer, args=(t_id,)))
        threads.append(threading.Thread(target=worker_reader))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert buf.size() == num_threads * events_per_thread


# 11. Configuration Loading & Validation Tests
def test_agent_configuration():
    # Default configuration
    cfg = AgentConfig()
    assert cfg.collection_interval_seconds == 1.0
    assert cfg.sliding_window_durations == [5, 10, 30]
    assert cfg.buffer_retention_seconds >= 30.0
    assert len(cfg.monitored_directories) > 0

    # Custom dict loading
    custom_data = {
        "agent_id": "soc-endpoint-test",
        "collection_interval_seconds": 0.5,
        "sliding_window_durations": [5, 10, 30],
        "sysmon_enabled": False,
    }
    cfg_custom = AgentConfig.from_dict(custom_data)
    assert cfg_custom.agent_id == "soc-endpoint-test"
    assert cfg_custom.collection_interval_seconds == 0.5
    assert cfg_custom.sysmon_enabled is False

    # Invalid configuration validation
    with pytest.raises(ValueError):
        AgentConfig(collection_interval_seconds=-1.0).validate()

    with pytest.raises(ValueError):
        AgentConfig(sliding_window_durations=[]).validate()


# 12. Agent Start Lifecycle Test
def test_agent_start_lifecycle():
    agent = RansomShieldAgent()
    assert agent._is_running is False
    agent.start()
    assert agent._is_running is True
    agent.stop()


# 13. Agent Stop Lifecycle Test
def test_agent_stop_lifecycle():
    agent = RansomShieldAgent()
    agent.start()
    assert agent._is_running is True
    agent.stop(reason="Test clean shutdown")
    assert agent._is_running is False


# 14. Agent Status Reporting Test
def test_agent_status_reporting():
    agent = RansomShieldAgent()
    try:
        agent.start()
        # Clear any initial scan events before recording deterministic event
        agent.buffer.clear()
        agent.record_event(ProcessEvent(pid=9999, process_name="test.exe"))
        status = agent.status()

        assert status["running"] is True
        assert status["version"] == "0.1.0"
        assert "Phase 2" in status["phase"]
        assert status["sliding_windows"] == [5, 10, 30]
        assert status["buffer_stats"]["current_size"] == 1
        assert "collectors" in status
        assert "process" in status["collectors"]
    finally:
        agent.stop()


# 15. Collector Availability Interfaces Test
def test_collector_availability_interfaces():
    proc_coll = ProcessCollectorInterface()
    assert isinstance(proc_coll.is_available(), bool)
    assert proc_coll.collect() == []

    file_coll = FileCollectorInterface()
    assert isinstance(file_coll.is_available(), bool)
    assert file_coll.collect() == []

    sysmon_coll = SysmonCollectorInterface()
    assert isinstance(sysmon_coll.is_available(), bool)
    assert sysmon_coll.collect() == []

    evt_coll = WindowsEventLogCollectorInterface()
    assert isinstance(evt_coll.is_available(), bool)
    assert evt_coll.collect() == []

    net_coll = NetworkCollectorInterface()
    assert isinstance(net_coll.is_available(), bool)
    assert net_coll.collect() == []


# 16. Model V2 Feature Contract Exact Match Verification
def test_model_v2_feature_contract_compatibility():
    """
    CRITICAL: Verifies the exact 19 Model V2 feature names and sequence
    against the established Phase 1 ML contract.
    """
    EXPECTED_V2_FEATURES = [
        "File_Delete_archived",
        "File_created",
        "File_creation_time_changed",
        "Pipe_Created",
        "Process_Create",
        "Registry_value_set",
        "process-related",
        "network-related",
        "file-related",
        "suspicious_path",
        "system_executable",
        "path_length",
        "directory_depth",
        "process_name_length",
        "process_vs_parent_freq_ratio",
        "executable_depth_diff",
        "parent_is_system_executable",
        "extension_similarity",
        "file_name_entropy",
    ]

    assert len(V2_FEATURE_NAMES) == 19
    assert len(EXPECTED_V2_FEATURES) == 19
    assert V2_FEATURE_NAMES == EXPECTED_V2_FEATURES

    # Verify each feature has a valid definition and category
    for defn in V2_FEATURE_DEFINITIONS:
        assert defn.name in EXPECTED_V2_FEATURES
        assert defn.classification.value in ["DIRECT", "DERIVED", "APPROXIMATION"]
        assert len(defn.calculation) > 0
