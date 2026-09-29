"""
RansomShield AI — Filesystem Activity & Entropy Collector (watchdog)
Phase 2B: Windows Endpoint Monitoring Agent — Live Collectors

Monitors configurable Windows directories using watchdog event handlers.
Captures file creations, modifications, deletions, renames/extensions, and calculates
filename Shannon entropy using the Phase 1 entropy calculation engine.
"""

import time
import os
import threading
from pathlib import Path
from typing import List, Optional, Dict, Any, Union

try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler,
        FileCreatedEvent,
        FileModifiedEvent,
        FileDeletedEvent,
        FileMovedEvent,
        FileSystemEvent,
    )
    WATCHDOG_AVAILABLE = True
except ImportError:
    Observer = None
    FileSystemEventHandler = object
    WATCHDOG_AVAILABLE = False

from agent.collectors.base import FileCollectorInterface
from agent.models.telemetry import FileEvent, TelemetryEventType
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer
from ml.features.entropy import calculate_shannon_entropy


class RansomShieldFileSystemEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler translating filesystem notifications into FileEvent telemetry.
    """

    def __init__(
        self,
        buffer: Optional[InMemoryTelemetryBuffer] = None,
        event_sink: Optional[List[FileEvent]] = None,
    ):
        super().__init__()
        self.buffer = buffer
        self.event_sink = event_sink

    def _emit(self, event: FileEvent) -> None:
        if self.buffer is not None:
            self.buffer.append(event)
        if self.event_sink is not None:
            self.event_sink.append(event)

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        now = time.time()
        file_path = event.src_path
        filename = Path(file_path).name
        ext = Path(file_path).suffix.lower()
        entropy = calculate_shannon_entropy(filename)

        file_ev = FileEvent(
            timestamp=now,
            event_type=TelemetryEventType.FileCreate,
            source="watchdog",
            path=file_path,
            extension=ext,
            file_name_entropy=entropy,
            entropy=entropy,
        )
        self._emit(file_ev)

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        now = time.time()
        file_path = event.src_path
        filename = Path(file_path).name
        ext = Path(file_path).suffix.lower()
        entropy = calculate_shannon_entropy(filename)

        file_ev = FileEvent(
            timestamp=now,
            event_type=TelemetryEventType.FileModify,
            source="watchdog",
            path=file_path,
            extension=ext,
            file_name_entropy=entropy,
            entropy=entropy,
        )
        self._emit(file_ev)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        now = time.time()
        file_path = event.src_path
        filename = Path(file_path).name
        ext = Path(file_path).suffix.lower()
        entropy = calculate_shannon_entropy(filename)

        # Check if deleted file is an archive/backup/shadow file
        archive_extensions = [".bak", ".zip", ".7z", ".rar", ".tar", ".gz", ".old", ".backup", ".vss"]
        is_archived_deletion = any(file_path.lower().endswith(a_ext) for a_ext in archive_extensions)
        
        event_type = (
            TelemetryEventType.FileDeleteArchived
            if is_archived_deletion
            else TelemetryEventType.FileDelete
        )

        file_ev = FileEvent(
            timestamp=now,
            event_type=event_type,
            source="watchdog",
            path=file_path,
            extension=ext,
            file_name_entropy=entropy,
            entropy=entropy,
        )
        self._emit(file_ev)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        now = time.time()
        src_path = event.src_path
        dest_path = getattr(event, "dest_path", src_path)
        
        dest_filename = Path(dest_path).name
        src_ext = Path(src_path).suffix.lower()
        dest_ext = Path(dest_path).suffix.lower()
        entropy = calculate_shannon_entropy(dest_filename)

        # Extension transformation metric (e.g. .docx -> .locked, .txt -> .enc)
        ext_similarity = 1 if (src_ext and dest_ext and src_ext != dest_ext) else 0

        file_ev = FileEvent(
            timestamp=now,
            event_type=TelemetryEventType.FileRename,
            source="watchdog",
            path=dest_path,
            old_path=src_path,
            extension=dest_ext,
            extension_similarity=ext_similarity,
            file_name_entropy=entropy,
            entropy=entropy,
        )
        self._emit(file_ev)


class FileCollector(FileCollectorInterface):
    """
    Live watchdog filesystem collector monitoring configured directories.
    """

    def __init__(
        self,
        monitored_paths: Optional[List[str]] = None,
        buffer: Optional[InMemoryTelemetryBuffer] = None,
        name: str = "FileCollector",
    ):
        super().__init__(monitored_paths=monitored_paths, name=name)
        self.buffer = buffer
        self._observer: Optional[Observer] = None
        self._handler: Optional[RansomShieldFileSystemEventHandler] = None
        self._collected_events: List[FileEvent] = []
        self._lock = threading.RLock()

    def is_available(self) -> bool:
        return WATCHDOG_AVAILABLE and Observer is not None

    def start(self) -> None:
        """Starts watchdog observers over all valid monitored directories."""
        if not self.is_available():
            return

        with self._lock:
            if self._is_running:
                return

            self._observer = Observer()
            self._handler = RansomShieldFileSystemEventHandler(
                buffer=self.buffer,
                event_sink=self._collected_events,
            )

            # Schedule observer on each existing monitored directory
            valid_dirs = [p for p in self.monitored_paths if os.path.exists(p) and os.path.isdir(p)]
            for directory in valid_dirs:
                try:
                    self._observer.schedule(self._handler, path=directory, recursive=True)
                except Exception:
                    pass

            self._observer.start()
            self._is_running = True

    def stop(self) -> None:
        """Stops watchdog observer and joins watcher threads."""
        with self._lock:
            if not self._is_running:
                return

            if self._observer:
                try:
                    self._observer.stop()
                    self._observer.join(timeout=2.0)
                except Exception:
                    pass
                self._observer = None

            self._is_running = False

    def collect(self) -> List[FileEvent]:
        """Returns and drains recent file events collected since last call."""
        with self._lock:
            events = list(self._collected_events)
            self._collected_events.clear()
            return events
