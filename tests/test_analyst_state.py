import json

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.config import settings

SID = "a" * 64
OTHER = "b" * 64


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def sample_dirs():
    for sample_id in (SID, OTHER):
        (settings.WORK_DIR / sample_id).mkdir(parents=True, exist_ok=True)


def test_unreviewed_sample_has_default_state(client, sample_dirs):
    body = client.get(f"/api/sample/{SID}/analyst-state").json()
    assert body == {"sample_id": SID, "status": "new", "tags": [], "notes": "", "updated_utc": None}


def test_put_then_get_round_trip_normalises_tags(client, sample_dirs):
    payload = {"status": "reviewing", "tags": [" dropper ", "dropper", "c2"], "notes": "checked C2"}
    put = client.put(f"/api/sample/{SID}/analyst-state", json=payload)
    assert put.status_code == 200
    assert put.json()["tags"] == ["dropper", "c2"]

    got = client.get(f"/api/sample/{SID}/analyst-state").json()
    assert got["status"] == "reviewing"
    assert got["notes"] == "checked C2"
    assert got["tags"] == ["dropper", "c2"]
    assert got["updated_utc"] is not None


def test_invalid_status_and_too_many_tags_are_rejected(client, sample_dirs):
    bad_status = client.put(f"/api/sample/{SID}/analyst-state", json={"status": "archived"})
    assert bad_status.status_code == 422

    empty_tag = client.put(f"/api/sample/{SID}/analyst-state", json={"status": "new", "tags": [""]})
    assert empty_tag.status_code == 422

    too_many = client.put(
        f"/api/sample/{SID}/analyst-state",
        json={"status": "new", "tags": [f"t{i}" for i in range(21)]},
    )
    assert too_many.status_code == 422


def test_bad_and_missing_sample_ids(client, sample_dirs):
    assert client.get("/api/sample/not-a-hash/analyst-state").status_code == 400
    assert client.get(f"/api/sample/{'c' * 64}/analyst-state").status_code == 404
    assert client.put(f"/api/sample/{'c' * 64}/analyst-state", json={"status": "new"}).status_code == 404


def test_list_filters_by_status(client, sample_dirs):
    client.put(f"/api/sample/{SID}/analyst-state", json={"status": "closed"})
    client.put(f"/api/sample/{OTHER}/analyst-state", json={"status": "new"})

    closed = client.get("/api/analyst-state", params={"status": "closed"}).json()
    assert [row["sample_id"] for row in closed] == [SID]

    everything = client.get("/api/analyst-state").json()
    assert {row["sample_id"] for row in everything} == {SID, OTHER}


def test_state_survives_pipeline_output_rewrite(client, sample_dirs):
    result_path = settings.WORK_DIR / SID / "pipeline_result.json"
    result_path.write_text(json.dumps({"run": 1}), encoding="utf-8")
    client.put(f"/api/sample/{SID}/analyst-state", json={"status": "reviewing", "notes": "keep me"})

    result_path.write_text(json.dumps({"run": 2}), encoding="utf-8")  # re-analysis

    assert client.get(f"/api/sample/{SID}/analyst-state").json()["notes"] == "keep me"


def test_browser_preflight_allows_put_from_frontend_origin(client):
    origin = settings.FRONTEND_URL
    response = client.options(
        f"/api/sample/{SID}/analyst-state",
        headers={"Origin": origin, "Access-Control-Request-Method": "PUT"},
    )
    assert response.status_code == 200
    assert "PUT" in response.headers.get("access-control-allow-methods", "")
