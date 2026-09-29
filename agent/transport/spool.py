"""
RansomShield AI — Local Transport Spool (SQLite)
Phase 3C: Agent ↔ Backend Real-Time Communication

Provides a bounded, persistent on-disk spool using SQLite to ensure security events
(detections, alerts, incidents) are preserved locally during backend outages.
Automatically drains in FIFO order when connectivity is restored.
Ensures connections are closed cleanly to avoid Windows file locks.
"""

import json
import sqlite3
import threading
import time
import logging
from typing import List, Tuple, Dict, Any, Optional

logger = logging.getLogger("RansomShieldTransportSpool")


class LocalTransportSpool:
    """
    Thread-safe SQLite-backed queue for durable offline event spooling.
    Bounded by max_records to prevent disk exhaustion.
    """

    def __init__(
        self,
        db_path: str = "agent_transport_spool.db",
        max_records: int = 2000,
    ):
        self.db_path = db_path
        self.max_records = max(10, max_records)
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes spool database table and index."""
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS transport_spool (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            item_type TEXT NOT NULL,
                            payload TEXT NOT NULL,
                            created_at REAL NOT NULL,
                            retry_count INTEGER DEFAULT 0
                        )
                        """
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_spool_created ON transport_spool(created_at)"
                    )
            finally:
                conn.close()

    def push(self, item_type: str, payload: Dict[str, Any]) -> int:
        """
        Stores an item in the spool queue. If spool exceeds max_records,
        purges oldest records in FIFO manner.
        """
        now = time.time()
        payload_str = json.dumps(payload)

        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    cur = conn.cursor()
                    cur.execute(
                        """
                        INSERT INTO transport_spool (item_type, payload, created_at, retry_count)
                        VALUES (?, ?, ?, 0)
                        """,
                        (item_type, payload_str, now),
                    )
                    inserted_id = cur.lastrowid or 0

                    # Check bounding and prune oldest if necessary
                    cur.execute("SELECT COUNT(*) FROM transport_spool")
                    count = cur.fetchone()[0]
                    if count > self.max_records:
                        overflow = count - self.max_records
                        cur.execute(
                            """
                            DELETE FROM transport_spool
                            WHERE id IN (
                                SELECT id FROM transport_spool
                                ORDER BY id ASC
                                LIMIT ?
                            )
                            """,
                            (overflow,),
                        )
                        logger.warning(
                            f"[SPOOL_OVERFLOW] Spool cap exceeded ({count} > {self.max_records}). "
                            f"Purged {overflow} oldest spooled record(s)."
                        )
                    return inserted_id
            finally:
                conn.close()

    def peek(self, limit: int = 50) -> List[Tuple[int, str, Dict[str, Any]]]:
        """
        Retrieves up to limit oldest records from the spool without removing them.
        Returns List of (id, item_type, payload_dict).
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT id, item_type, payload
                    FROM transport_spool
                    ORDER BY id ASC
                    LIMIT ?
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
                results: List[Tuple[int, str, Dict[str, Any]]] = []
                for row in rows:
                    try:
                        data = json.loads(row["payload"])
                        results.append((row["id"], row["item_type"], data))
                    except Exception as e:
                        logger.error(f"[SPOOL_DECODE_ERROR] Failed to deserialize payload for id {row['id']}: {e}")
                return results
            finally:
                conn.close()

    def remove(self, row_ids: List[int]) -> int:
        """Removes successfully transmitted records from the spool queue."""
        if not row_ids:
            return 0

        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    placeholders = ",".join("?" * len(row_ids))
                    cur = conn.cursor()
                    cur.execute(
                        f"DELETE FROM transport_spool WHERE id IN ({placeholders})",
                        row_ids,
                    )
                    return cur.rowcount
            finally:
                conn.close()

    def increment_retry(self, row_id: int) -> None:
        """Increments the retry counter for a spooled item."""
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        "UPDATE transport_spool SET retry_count = retry_count + 1 WHERE id = ?",
                        (row_id,),
                    )
            finally:
                conn.close()

    def size(self) -> int:
        """Returns the total number of items currently spooled."""
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM transport_spool")
                return cur.fetchone()[0]
            finally:
                conn.close()

    def clear(self) -> None:
        """Empties the spool database table."""
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute("DELETE FROM transport_spool")
            finally:
                conn.close()
