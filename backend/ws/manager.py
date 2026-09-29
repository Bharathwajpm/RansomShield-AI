"""
RansomShield AI — WebSocket Connection Manager
Phase 3C: Full Backend Integration

Manages authenticated WebSocket connections, real-time SOC event broadcasting,
dead-connection pruning, and graceful shutdown.
"""

import asyncio
import logging
from typing import Set, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import WebSocket, WebSocketDisconnect

from backend.config.settings import get_settings
from backend.auth.jwt import decode_access_token, JWTError

logger = logging.getLogger("RansomShieldBackend.WebSocketManager")


class WebSocketManager:
    """Thread-safe and async-safe WebSocket connection and event broadcasting manager."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, token: Optional[str] = None) -> bool:
        """
        Validates JWT authentication token and accepts the WebSocket connection.
        If authentication fails, closes the socket with 1008 (Policy Violation).
        """
        app = getattr(websocket, "app", None)
        app_state = getattr(app, "state", None) if app else None
        settings = getattr(app_state, "settings", None) or get_settings()

        if not token:
            logger.warning("[WS_REJECT] Missing authentication token for WebSocket connection")
            await websocket.close(code=1008, reason="Authentication token required")
            return False

        try:
            payload = decode_access_token(
                token=token,
                secret_key=settings.jwt_secret_key,
                algorithm=settings.jwt_algorithm,
            )
            username = payload.get("sub")
            if not username:
                await websocket.close(code=1008, reason="Malformed token claims")
                return False
        except JWTError as e:
            logger.warning(f"[WS_REJECT] Invalid WebSocket auth token: {e}")
            await websocket.close(code=1008, reason=f"Invalid token: {e}")
            return False

        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
            client_count = len(self.active_connections)

        logger.info(f"[WS_CONNECTED] User '{username}' connected to real-time feed. Total clients: {client_count}")
        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        """Removes a disconnected WebSocket client."""
        async with self._lock:
            self.active_connections.discard(websocket)
            client_count = len(self.active_connections)
        logger.info(f"[WS_DISCONNECTED] Client disconnected. Total active clients: {client_count}")

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> int:
        """
        Broadcasts an event message to all connected clients.
        Automatically cleans up any disconnected or stale connections.
        Guaranteed not to raise exceptions to callers so ingestion never fails.
        """
        payload = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        async with self._lock:
            connections = list(self.active_connections)

        if not connections:
            return 0

        dead_connections = []
        successful_sends = 0

        for ws in connections:
            try:
                await ws.send_json(payload)
                successful_sends += 1
            except Exception as e:
                logger.debug(f"[WS_SEND_FAIL] Failed sending to client: {e}")
                dead_connections.append(ws)

        if dead_connections:
            async with self._lock:
                for dead_ws in dead_connections:
                    self.active_connections.discard(dead_ws)
            logger.info(f"[WS_CLEANUP] Pruned {len(dead_connections)} dead connections.")

        return successful_sends

    async def close_all(self) -> None:
        """Gracefully closes all open WebSocket connections during backend shutdown."""
        async with self._lock:
            connections = list(self.active_connections)
            self.active_connections.clear()

        for ws in connections:
            try:
                await ws.close(code=1001, reason="Server shutting down")
            except Exception:
                pass
        logger.info(f"[WS_SHUTDOWN] Closed {len(connections)} WebSocket connections.")


# Singleton WebSocket Manager
ws_manager = WebSocketManager()
