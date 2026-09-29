"""
RansomShield AI — Thread-Safe In-Memory Telemetry Buffer
Phase 2A: Windows Agent Foundation

Provides an in-memory, thread-safe rolling buffer for timestamped telemetry events.
Supports retrieval across 5s, 10s, and 30s sliding analysis windows and automatic
purging of expired events to prevent memory unbounded growth.
"""

import time
import threading
from collections import deque
from typing import List, Optional, Dict, Any, Callable, TypeVar, Generic

from agent.models.telemetry import BaseTelemetryEvent, TelemetryEventType

T = TypeVar("T", bound=BaseTelemetryEvent)


class InMemoryTelemetryBuffer(Generic[T]):
    """
    Thread-safe in-memory rolling buffer for endpoint telemetry events.
    """

    def __init__(self, max_capacity: int = 100_000):
        self._buffer: deque = deque(maxlen=max_capacity)
        self._lock = threading.RLock()
        self._total_events_appended: int = 0
        self._total_events_purged: int = 0

    def append(self, event: T) -> None:
        """
        Appends a single timestamped telemetry event to the buffer in a thread-safe manner.
        """
        with self._lock:
            self._buffer.append(event)
            self._total_events_appended += 1

    def extend(self, events: List[T]) -> None:
        """
        Appends multiple telemetry events to the buffer atomically.
        """
        with self._lock:
            for ev in events:
                self._buffer.append(ev)
                self._total_events_appended += 1

    def get_events(
        self,
        window_seconds: float,
        current_time: Optional[float] = None,
    ) -> List[T]:
        """
        Retrieves all events that occurred within [current_time - window_seconds, current_time].
        
        Args:
            window_seconds: Window duration in seconds (e.g. 5.0, 10.0, 30.0).
            current_time: Reference epoch timestamp. If None, uses time.time().
        """
        now = current_time if current_time is not None else time.time()
        cutoff = now - window_seconds

        with self._lock:
            # Events in buffer are generally ordered chronologically
            return [ev for ev in self._buffer if ev.timestamp >= cutoff and ev.timestamp <= now]

    def get_events_by_type(
        self,
        event_type: TelemetryEventType,
        window_seconds: float,
        current_time: Optional[float] = None,
    ) -> List[T]:
        """
        Retrieves events matching a specific TelemetryEventType within the sliding window.
        """
        events = self.get_events(window_seconds=window_seconds, current_time=current_time)
        return [ev for ev in events if ev.event_type == event_type]

    def cleanup_expired(
        self,
        retention_seconds: float = 120.0,
        current_time: Optional[float] = None,
    ) -> int:
        """
        Removes all events older than retention_seconds from the buffer.
        
        Returns:
            Number of purged events.
        """
        now = current_time if current_time is not None else time.time()
        cutoff = now - retention_seconds
        purged_count = 0

        with self._lock:
            # Efficiently pop from left while timestamp < cutoff
            while self._buffer and self._buffer[0].timestamp < cutoff:
                self._buffer.popleft()
                purged_count += 1
                
            self._total_events_purged += purged_count

        return purged_count

    def clear(self) -> None:
        """Clears all events from the buffer."""
        with self._lock:
            self._buffer.clear()

    def size(self) -> int:
        """Returns the current number of events in the buffer."""
        with self._lock:
            return len(self._buffer)

    def __len__(self) -> int:
        return self.size()

    def get_stats(self) -> Dict[str, Any]:
        """Returns buffer statistics."""
        with self._lock:
            return {
                "current_size": len(self._buffer),
                "max_capacity": self._buffer.maxlen,
                "total_appended": self._total_events_appended,
                "total_purged": self._total_events_purged,
                "oldest_timestamp": self._buffer[0].timestamp if self._buffer else None,
                "newest_timestamp": self._buffer[-1].timestamp if self._buffer else None,
            }
