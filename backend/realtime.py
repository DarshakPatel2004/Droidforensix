"""WebSocket connection manager and pipeline event emitter."""

import asyncio
import json
import logging
from typing import Set

from fastapi import WebSocket

from backend.events import VALID_EVENT_TYPES, WebSocketEvent
from backend.validators import validate_event

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return
        text = json.dumps(message, default=str)
        disconnected = set()
        # Iterate a snapshot: send_text can suspend, letting another task add or
        # discard connections and raise "Set changed size during iteration".
        for connection in list(self.active_connections):
            try:
                await connection.send_text(text)
            except Exception as e:
                logger.debug("Broadcast failed, removing connection: %s", e)
                disconnected.add(connection)
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------

def make_event_emitter(loop: asyncio.AbstractEventLoop):
    """Create a callback that emits pipeline events via WebSocket."""
    def emit(event_type: str, data: dict):
        logger.debug("Emitting %s to %d connection(s)", event_type, len(manager.active_connections))
        if event_type not in VALID_EVENT_TYPES:
            logger.warning("Dropping event with unknown type %s", event_type)
            return
        event = WebSocketEvent(event_type=event_type, data=data)
        event_dict = event.to_dict()
        if not validate_event(event_dict):
            logger.warning("Dropping %s event that failed validation", event_type)
            return
        # Schedule broadcast on the event loop
        fut = asyncio.run_coroutine_threadsafe(manager.broadcast(event_dict), loop)
        fut.add_done_callback(_log_broadcast_failure)
    return emit


def _log_broadcast_failure(fut) -> None:
    error = fut.exception()
    if error is not None:
        logger.warning("WebSocket broadcast failed: %s", error)
