"""B2-07: /ws must refuse browser origins outside the configured allowlist."""
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.main import app


def test_ws_rejects_foreign_origin():
    client = TestClient(app)
    try:
        with client.websocket_connect("/ws", headers={"origin": "http://evil.example"}) as ws:
            ws.send_text('{"action": "ping"}')
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 1008
    else:
        raise AssertionError("foreign origin was accepted")


def test_ws_accepts_allowed_origin_ping():
    from backend.config import settings

    origin = settings.cors_origins[0]
    client = TestClient(app)
    with client.websocket_connect("/ws", headers={"origin": origin}) as ws:
        ws.send_text('{"action": "ping"}')
        assert '"pong"' in ws.receive_text()
