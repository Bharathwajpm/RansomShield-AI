"""
RansomShield AI — Real-Time WebSocket Endpoint
Phase 3C: Full Backend Integration

Provides authenticated WebSocket streaming for live SOC events:
- detection.created
- alert.created
- alert.updated
- incident.created
- incident.updated
- agent.status_changed
"""

from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from backend.ws.manager import ws_manager

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws")
async def websocket_soc_feed(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """
    Real-time SOC WebSocket feed. Requires valid JWT access token in query string.
    Example: ws://localhost:8000/api/v1/ws?token=<jwt_token>
    """
    connected = await ws_manager.connect(websocket, token=token)
    if not connected:
        return

    try:
        while True:
            # Keep connection alive; accept optional client pings/messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await ws_manager.disconnect(websocket)
