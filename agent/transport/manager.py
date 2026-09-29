"""
RansomShield AI — Agent Transport Manager
Phase 3C: Agent ↔ Backend Real-Time Communication

Manages asynchronous, non-blocking telemetry and security event transmission
from the Windows Endpoint Monitoring Agent to the FastAPI backend.
Integrates bounded in-memory queuing, persistent SQLite offline spooling,
exponential backoff retries, and background heartbeat scheduling.
"""

import queue
import time
import threading
import logging
from typing import Dict, Any, Optional, Tuple

from agent.config import AgentConfig
from agent.inference.detection_result import DetectionResult
from agent.detection.alert_manager import DetectionAlert
from agent.detection.incident_manager import Incident
from backend.adapters.agent_adapter import AgentModelAdapter
from agent.transport.client import AgentNetworkClient
from agent.transport.spool import LocalTransportSpool
from agent.transport.retry import compute_backoff_delay, is_retriable_status

logger = logging.getLogger("RansomShieldTransportManager")


class AgentTransportManager:
    """
    Asynchronous transport subsystem for endpoint agents.
    Dispatches detections, alerts, and incidents to the backend without blocking live detection.
    """

    def __init__(
        self,
        config: AgentConfig,
        client: Optional[AgentNetworkClient] = None,
        spool: Optional[LocalTransportSpool] = None,
    ):
        self.config = config
        self.client = client or AgentNetworkClient(
            base_url=config.backend_url,
            timeout=config.backend_request_timeout,
            api_key=getattr(config, "agent_api_key", None),
        )
        self.spool = spool
        if self.spool is None and config.enable_local_spool and config.spool_db_path:
            self.spool = LocalTransportSpool(
                db_path=config.spool_db_path,
                max_records=config.max_spool_records,
            )

        self.queue: queue.Queue = queue.Queue(maxsize=config.transport_queue_size)
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._is_running = False
        self._is_registered = False
        self._lock = threading.RLock()

        # Diagnostic metrics
        self._stats = {
            "enqueued_detections": 0,
            "enqueued_alerts": 0,
            "enqueued_incidents": 0,
            "transmitted_detections": 0,
            "transmitted_alerts": 0,
            "transmitted_incidents": 0,
            "failed_transmissions": 0,
            "spooled_records": 0,
            "heartbeats_sent": 0,
            "registration_success": False,
        }

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def is_registered(self) -> bool:
        return self._is_registered

    def start(self) -> None:
        """Starts background transmission worker and heartbeat threads."""
        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._stop_event.clear()

            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="AgentTransportWorker",
                daemon=True,
            )
            self._worker_thread.start()

            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                name="AgentHeartbeatWorker",
                daemon=True,
            )
            self._heartbeat_thread.start()

            logger.info(f"[TRANSPORT_STARTED] Transport manager started. Target: {self.config.backend_url}")

    def stop(self, timeout: float = 3.0) -> None:
        """Gracefully stops transport threads and closes network client."""
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False
            self._stop_event.set()

        if self._worker_thread:
            if self._worker_thread.is_alive():
                self._worker_thread.join(timeout=timeout)
            self._worker_thread = None

        if self._heartbeat_thread:
            if self._heartbeat_thread.is_alive():
                self._heartbeat_thread.join(timeout=timeout)
            self._heartbeat_thread = None

        self.client.close()
        logger.info("[TRANSPORT_STOPPED] Transport manager cleanly stopped.")

    # --- NON-BLOCKING ENQUEUE METHODS ---

    def enqueue_detection(self, detection: DetectionResult) -> bool:
        """
        Converts DetectionResult and enqueues for transmission without blocking inference.
        """
        ingest_req = AgentModelAdapter.detection_result_to_ingest_request(
            result=detection,
            endpoint_id=self.config.agent_id,
        )
        payload = ingest_req.model_dump()
        return self._enqueue_payload("detection", payload)

    def enqueue_alert(self, alert: DetectionAlert) -> bool:
        """
        Converts DetectionAlert and enqueues for transmission without blocking alerting.
        """
        alert_resp = AgentModelAdapter.alert_to_response(alert)
        payload = alert_resp.model_dump()
        return self._enqueue_payload("alert", payload)

    def enqueue_incident(self, incident: Incident) -> bool:
        """
        Converts Incident and enqueues for transmission without blocking correlation.
        """
        inc_resp = AgentModelAdapter.incident_to_response(incident)
        payload = inc_resp.model_dump()
        return self._enqueue_payload("incident", payload)

    def _enqueue_payload(self, item_type: str, payload: Dict[str, Any]) -> bool:
        """Helper to place payload into in-memory queue or spill to disk spool."""
        with self._lock:
            if item_type == "detection":
                self._stats["enqueued_detections"] += 1
            elif item_type == "alert":
                self._stats["enqueued_alerts"] += 1
            elif item_type == "incident":
                self._stats["enqueued_incidents"] += 1

        try:
            self.queue.put_nowait((item_type, payload))
            return True
        except queue.Full:
            # Queue is full, spill over to SQLite spool if available
            if self.spool:
                self.spool.push(item_type, payload)
                with self._lock:
                    self._stats["spooled_records"] += 1
                logger.warning(f"[QUEUE_OVERFLOW] In-memory queue full. Spooled {item_type} to SQLite disk.")
                return True
            else:
                logger.error(f"[QUEUE_DROP] In-memory queue full and local spool disabled. Dropped {item_type}.")
                return False

    # --- WORKER LOOP & TRANSMISSION ---

    def _register_agent_payload(self) -> Dict[str, Any]:
        return {
            "agent_id": self.config.agent_id,
            "hostname": self.config.agent_name,
            "os_name": "Windows",
            "os_version": "10.0",
            "agent_version": self.config.version,
            "monitored_directories": self.config.monitored_directories,
        }

    def _attempt_registration(self) -> bool:
        """Attempts to register the agent with the backend."""
        payload = self._register_agent_payload()
        success, status_code, data = self.client.register(payload)
        if success:
            with self._lock:
                self._is_registered = True
                self._stats["registration_success"] = True
            logger.info(f"[AGENT_REGISTERED] Successfully registered '{self.config.agent_id}' with backend.")
            return True
        else:
            logger.debug(f"[AGENT_REGISTER_RETRY] Registration attempt returned HTTP {status_code}: {data}")
            return False

    def _dispatch_payload(self, item_type: str, payload: Dict[str, Any]) -> Tuple[bool, int, Any]:
        """Dispatches an item via HTTP client based on its item_type."""
        if item_type == "detection":
            return self.client.send_detection(payload)
        elif item_type == "alert":
            return self.client.send_alert(payload)
        elif item_type == "incident":
            return self.client.send_incident(payload)
        return False, 400, f"Unknown item type '{item_type}'"

    def _drain_spool(self) -> None:
        """Drains pending records from the local SQLite spool when backend is online."""
        if not self.spool:
            return

        batch = self.spool.peek(limit=25)
        if not batch:
            return

        for row_id, item_type, payload in batch:
            if self._stop_event.is_set():
                break

            success, status_code, resp = self._dispatch_payload(item_type, payload)
            if success:
                self.spool.remove([row_id])
                with self._lock:
                    self._stats[f"transmitted_{item_type}s"] += 1
                logger.debug(f"[SPOOL_DELIVERED] Delivered spooled {item_type} (Row {row_id}).")
            else:
                # If failure is retriable, stop draining batch and wait for next cycle
                if is_retriable_status(status_code):
                    self.spool.increment_retry(row_id)
                    logger.debug(f"[SPOOL_BACKOFF] Temporary failure draining spool (HTTP {status_code}). Backing off.")
                    break
                else:
                    # Non-retriable client error (e.g. malformed data), drop from spool
                    self.spool.remove([row_id])
                    logger.error(f"[SPOOL_DROPPED] Non-retriable error for {item_type} (HTTP {status_code}). Removed.")

    def _worker_loop(self) -> None:
        """Continuous background transmission worker loop."""
        retry_attempt = 0

        while not self._stop_event.is_set():
            # 1. Ensure registration is attempted
            if not self._is_registered:
                reg_ok = self._attempt_registration()
                if not reg_ok:
                    delay = compute_backoff_delay(
                        attempt=retry_attempt,
                        base_delay=self.config.backend_retry_base_delay,
                        max_delay=self.config.backend_retry_max_delay,
                    )
                    retry_attempt += 1
                    self._stop_event.wait(timeout=delay)
                    continue
                else:
                    retry_attempt = 0

            # 2. Drain persistent spool first if available
            try:
                self._drain_spool()
            except Exception as e:
                logger.error(f"[SPOOL_DRAIN_ERROR] Error draining spool: {e}")

            # 3. Pull next item from in-memory queue
            try:
                item_type, payload = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue

            # 4. Transmit item
            success, status_code, resp = self._dispatch_payload(item_type, payload)
            if success:
                with self._lock:
                    self._stats[f"transmitted_{item_type}s"] += 1
                retry_attempt = 0
                self.queue.task_done()
                logger.debug(f"[TRANSMISSION_SUCCESS] Transmitted {item_type} to backend.")
            else:
                with self._lock:
                    self._stats["failed_transmissions"] += 1

                if is_retriable_status(status_code):
                    # Spool to disk if enabled so data is preserved during backend outage
                    if self.spool:
                        self.spool.push(item_type, payload)
                        with self._lock:
                            self._stats["spooled_records"] += 1
                        logger.warning(
                            f"[TRANSMISSION_SPOOLED] Retriable failure (HTTP {status_code}). "
                            f"Spooled {item_type} to disk for later delivery."
                        )
                    self.queue.task_done()

                    delay = compute_backoff_delay(
                        attempt=retry_attempt,
                        base_delay=self.config.backend_retry_base_delay,
                        max_delay=self.config.backend_retry_max_delay,
                    )
                    retry_attempt += 1
                    self._stop_event.wait(timeout=delay)
                else:
                    # Permanent client error: do not retry
                    logger.error(f"[TRANSMISSION_REJECTED] Permanent error for {item_type} (HTTP {status_code}): {resp}")
                    self.queue.task_done()

    def _heartbeat_loop(self) -> None:
        """Periodic background heartbeat emitter loop."""
        while not self._stop_event.is_set():
            if self._is_registered:
                success, status_code, data = self.client.send_heartbeat(self.config.agent_id)
                if success:
                    with self._lock:
                        self._stats["heartbeats_sent"] += 1
                    logger.debug(f"[HEARTBEAT_SENT] Heartbeat ping sent for '{self.config.agent_id}'.")
                else:
                    logger.debug(f"[HEARTBEAT_FAILED] Heartbeat ping failed (HTTP {status_code}).")
            else:
                # If unregistered, try registering
                self._attempt_registration()

            self._stop_event.wait(timeout=self.config.heartbeat_interval_seconds)

    def status(self) -> Dict[str, Any]:
        """Returns diagnostic operational status of the transport subsystem."""
        spool_size = self.spool.size() if self.spool else 0
        with self._lock:
            stats_copy = dict(self._stats)

        return {
            "running": self._is_running,
            "registered": self._is_registered,
            "backend_url": self.config.backend_url,
            "queue_size": self.queue.qsize(),
            "spool_size": spool_size,
            "metrics": stats_copy,
        }
