"""
RansomShield AI — Network Socket & Connection Collector (psutil)
Phase 2B: Windows Endpoint Monitoring Agent — Live Collectors

Periodically inspects active TCP/UDP network connections using psutil.net_connections().
Extracts socket endpoints, protocols, status, and PID associations required for Model V2
network-related telemetry features.
"""

import time
import socket
import threading
from typing import List, Optional, Dict, Any

try:
    import psutil
except ImportError:
    psutil = None

from agent.collectors.base import NetworkCollectorInterface
from agent.models.telemetry import NetworkEvent, TelemetryEventType
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer


class NetworkCollector(NetworkCollectorInterface):
    """
    Live network socket monitor collecting active outbound connection telemetry.
    """

    def __init__(
        self,
        buffer: Optional[InMemoryTelemetryBuffer] = None,
        poll_interval: float = 2.0,
        name: str = "NetworkCollector",
    ):
        super().__init__(name=name)
        self.buffer = buffer
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

    def is_available(self) -> bool:
        return psutil is not None

    def start(self) -> None:
        """Starts background network connection polling loop."""
        if not self.is_available():
            return

        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._poll_loop,
                name="NetworkCollectorWorker",
                daemon=True,
            )
            self._worker_thread.start()

    def stop(self) -> None:
        """Stops background network polling cleanly."""
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

    def collect(self) -> List[NetworkEvent]:
        """
        Enumerates active socket connections and returns NetworkEvent instances.
        """
        if not self.is_available():
            return []

        events: List[NetworkEvent] = []
        now = time.time()

        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                try:
                    # Capture local and remote endpoints
                    src_ip = conn.laddr.ip if conn.laddr else "127.0.0.1"
                    src_port = conn.laddr.port if conn.laddr else None
                    
                    dst_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
                    dst_port = conn.raddr.port if conn.raddr else 0
                    
                    # Protocol
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    pid = conn.pid or 0
                    status = conn.status if hasattr(conn, "status") else "NONE"

                    net_ev = NetworkEvent(
                        timestamp=now,
                        event_type=TelemetryEventType.NetworkConnection,
                        source="psutil",
                        pid=pid,
                        source_address=src_ip,
                        source_port=src_port,
                        destination_address=dst_ip,
                        destination_port=dst_port,
                        protocol=proto,
                        connection_type=status,
                    )
                    events.append(net_ev)
                except Exception:
                    continue
        except (psutil.AccessDenied, PermissionError):
            # Gracefully handle unprivileged socket access
            pass
        except Exception:
            pass

        return events
