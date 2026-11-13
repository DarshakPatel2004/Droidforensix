"""Regression tests for backend audit B2 fixes (docs/audit/2026-11-11/B2_backend_api_core.md)."""
import json

import pytest
from fastapi.testclient import TestClient

from backend.routers import reports


@pytest.fixture
def client():
    from backend.main import app

    with TestClient(app) as c:
        yield c


def test_b2_30_non_object_ws_message_keeps_connection(client):
    # A JSON list used to raise AttributeError and drop the socket (B2-30).
    with client.websocket_connect("/ws") as ws:
        ws.send_text("[1, 2]")
        ws.send_text(json.dumps({"action": "ping"}))
        assert json.loads(ws.receive_text())["event_type"] == "pong"


def test_b2_34_unknown_report_mode_rejected(client, monkeypatch):
    monkeypatch.setattr(reports, "load_result", lambda sample_id: {"metadata": {}})
    resp = client.post("/api/sample/abc123/report/pdf", json={"mode": "fulll"})
    assert resp.status_code == 400


def test_b2_34_non_dict_sections_rejected(client, monkeypatch):
    monkeypatch.setattr(reports, "load_result", lambda sample_id: {"metadata": {}})
    resp = client.post("/api/sample/abc123/report/pdf", json={"mode": "quick", "sections": ["metadata"]})
    assert resp.status_code == 400


def test_b2_08_null_family_and_llm_do_not_break_samples_list():
    from backend.transformers import transform_clusters, transform_samples_list

    results = [{"sample_id": "s1", "family_identification": None, "llm_assessment": None,
                "metadata": {"sample_name": "x"}}]
    assert transform_samples_list(results)
    assert transform_clusters(results) is not None


def test_b2_28_analysis_executor_is_bounded():
    from backend.routers import jobs

    assert jobs._ANALYSIS_EXECUTOR._max_workers == 2
