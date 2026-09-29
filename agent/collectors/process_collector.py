"""
RansomShield AI — Process Lifecycle & Hierarchy Collector (psutil)
Phase 2B: Windows Endpoint Monitoring Agent — Live Collectors

Periodically inspects Windows process lifecycle and parent-child hierarchy using psutil.
Extracts telemetry attributes required for Model V2 process/path features:
Process_Create, process-related, suspicious_path, system_executable, path_length,
directory_depth, process_name_length, process_vs_parent_freq_ratio, executable_depth_diff,
and parent_is_system_executable.
"""

import time
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

try:
    import psutil
except ImportError:
    psutil = None

from agent.collectors.base import ProcessCollectorInterface
from agent.models.telemetry import ProcessEvent, TelemetryEventType
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer


class ProcessCollector(ProcessCollectorInterface):
    """
    Live process monitor collecting process lifecycle and hierarchy telemetry via psutil.
    """

    def __init__(
        self,
        buffer: Optional[InMemoryTelemetryBuffer] = None,
        poll_interval: float = 1.0,
        name: str = "ProcessCollector",
    ):
        super().__init__(name=name)
        self.buffer = buffer
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._known_pids: Dict[int, float] = {}
        self._process_freq_counts: Dict[str, int] = {}
        self._lock = threading.RLock()
        self._initial_scan_done = False

    def is_available(self) -> bool:
        return psutil is not None

    def start(self) -> None:
        """Starts the process collector background polling thread."""
        if not self.is_available():
            return

        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._poll_loop,
                name="ProcessCollectorWorker",
                daemon=True,
            )
            self._worker_thread.start()

    def stop(self) -> None:
        """Stops the process collector background polling thread cleanly."""
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
            
            # Wait for poll interval or stop event
            self._stop_event.wait(timeout=self.poll_interval)

    def collect(self) -> List[ProcessEvent]:
        """
        Scans running processes and detects new process creations and hierarchy features.
        """
        if not self.is_available():
            return []

        events: List[ProcessEvent] = []
        current_pids: Set[int] = set()
        now = time.time()

        try:
            for proc in psutil.process_iter(attrs=["pid", "name", "create_time"]):
                try:
                    pid = proc.info["pid"]
                    if pid == 0:
                        continue
                    current_pids.add(pid)

                    # On initial baseline scan or when new PID appears
                    is_new_process = pid not in self._known_pids
                    if is_new_process:
                        self._known_pids[pid] = proc.info.get("create_time", now)
                        event = self._extract_process_event(proc, now)
                        if event:
                            events.append(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass

        # Cleanup terminated PIDs from known dictionary
        with self._lock:
            terminated_pids = set(self._known_pids.keys()) - current_pids
            for term_pid in terminated_pids:
                del self._known_pids[term_pid]

        self._initial_scan_done = True
        return events

    def _extract_process_event(self, proc: Any, timestamp: float) -> Optional[ProcessEvent]:
        """Safely extracts process hierarchy and path metrics from a psutil Process instance."""
        try:
            pid = proc.pid
            name = proc.name() or ""
            
            # Safe executable path and command line retrieval
            exe_path = None
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe_path = None

            cmd_line = None
            try:
                cmd_parts = proc.cmdline()
                if cmd_parts:
                    cmd_line = " ".join(cmd_parts)[:512]  # Truncate to safe length
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmd_line = None

            username = None
            try:
                username = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                username = None

            # Calculate path-based metrics
            path_len = len(exe_path) if exe_path else 0
            dir_depth = exe_path.count("\\") if exe_path else 0
            proc_name_len = len(name)

            # System executable check (C:\Windows\System32)
            is_sys_exe = 0
            if exe_path:
                norm_exe = exe_path.lower()
                if "c:\\windows\\system32" in norm_exe or "c:\\windows\\syswow64" in norm_exe:
                    is_sys_exe = 1

            # Suspicious path check (AppData, Temp, Downloads, etc.)
            is_susp_path = 0
            if exe_path:
                norm_exe = exe_path.lower()
                suspicious_keywords = ["appdata", "\\temp\\", "\\tmp\\", "downloads", "users\\public"]
                if any(kw in norm_exe for kw in suspicious_keywords):
                    is_susp_path = 1

            # Parent process inspection
            ppid = None
            parent_name = None
            parent_exe = None
            parent_is_sys = 0
            exec_depth_diff = dir_depth
            
            try:
                parent = proc.parent()
                if parent:
                    ppid = parent.pid
                    parent_name = parent.name()
                    try:
                        parent_exe = parent.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        parent_exe = None
                        
                    if parent_exe:
                        parent_depth = parent_exe.count("\\")
                        exec_depth_diff = abs(dir_depth - parent_depth)
                        if "c:\\windows\\system32" in parent_exe.lower() or "c:\\windows\\syswow64" in parent_exe.lower():
                            parent_is_sys = 1
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Update process vs parent frequency ratio
            with self._lock:
                self._process_freq_counts[name] = self._process_freq_counts.get(name, 0) + 1
                child_freq = self._process_freq_counts[name]
                parent_freq = self._process_freq_counts.get(parent_name, 1) if parent_name else 1
                freq_ratio = round(float(child_freq) / float(max(1, parent_freq)), 4)

            return ProcessEvent(
                timestamp=timestamp,
                event_type=TelemetryEventType.ProcessCreate,
                source="psutil",
                pid=pid,
                parent_pid=ppid,
                process_name=name,
                executable_path=exe_path,
                command_line=cmd_line,
                user=username,
                is_system_executable=bool(is_sys_exe),
                is_suspicious_path=bool(is_susp_path),
                path_length=path_len,
                directory_depth=dir_depth,
                process_name_length=proc_name_len,
                parent_name=parent_name,
                parent_executable_path=parent_exe,
                parent_is_system_executable=bool(parent_is_sys),
                executable_depth_diff=exec_depth_diff,
                process_vs_parent_freq_ratio=freq_ratio,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
