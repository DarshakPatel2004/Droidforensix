"""
Backend event definitions and serialization for WebSocket streaming.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class WebSocketEvent:
    """Base WebSocket event."""
    event_type: str
    data: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


def create_event(event_type: str, data: Dict[str, Any]) -> WebSocketEvent:
    """Factory for creating events."""
    return WebSocketEvent(event_type=event_type, data=data)


VALID_EVENT_TYPES = {
    # New unified progress events
    "analysis_started",
    "step_started",
    "step_completed",
    "metric_updated",
    "analysis_complete",
    "error",
    "pong",
    # Legacy events (kept for backward compatibility)
    "extraction_complete",
    "strings_enumerated",
    "encoding_detected",
    "payload_decoded",
    "c2_extracted",
    "threat_chain_created",
    "metrics_update",
}
