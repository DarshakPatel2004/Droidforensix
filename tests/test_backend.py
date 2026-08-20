import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analysis.pipeline import run_pipeline
from backend.config import settings
from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def test_apk_path() -> Path:
    """Return the first real APK from the benign eval set for pipeline tests."""
    samples_dir = Path("samples/goodware/benign_eval")
    apks = list(samples_dir.glob("*.apk")) if samples_dir.is_dir() else []
    if not apks:
        pytest.skip("No test APK found in samples/goodware/benign_eval/")
    return apks[0]


def _tools_available() -> bool:
    apktool = Path(settings.APKTOOL_PATH)
    return apktool.exists() or shutil.which(settings.APKTOOL_PATH)


def test_health_check(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"


def test_api_samples(client):
    response = client.get("/api/samples")
    assert response.status_code == 200
    data = response.json()
    assert "samples" in data
    assert "total" in data
    assert data["total"] == len(data["samples"])
    if data["total"] > 0:
        assert data["samples"][0]["id"]
        assert "risk_score" in data["samples"][0]


def test_api_sample_detail(client):
    samples = client.get("/api/samples").json()["samples"]
    if not samples:
        pytest.skip("No analyzed samples available")
    sample_id = samples[0]["id"]
    response = client.get(f"/api/sample/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["sample_id"] == sample_id
    assert "llm_assessment" in data
    assert "threat_chains" in data


def test_api_graph(client):
    samples = client.get("/api/samples").json()["samples"]
    if not samples:
        pytest.skip("No analyzed samples available")
    sample_id = samples[0]["id"]
    response = client.get(f"/api/graph/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert data["total_nodes"] >= 1


def test_api_clusters(client):
    response = client.get("/api/clusters")
    assert response.status_code == 200
    data = response.json()
    assert "samples" in data
    assert data["total_samples"] == len(data["samples"])
    if data["samples"]:
        sample = data["samples"][0]
        assert "x" in sample
        assert "y" in sample
        assert "z" in sample


def test_api_timeline(client):
    samples = client.get("/api/samples").json()["samples"]
    if not samples:
        pytest.skip("No analyzed samples available")
    sample_id = samples[0]["id"]
    response = client.get(f"/api/timeline/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert "chains" in data


def test_api_sample_not_found(client):
    response = client.get("/api/sample/nonexistent")
    assert response.status_code == 404


def test_analyze_missing_apk(client):
    response = client.post("/analyze", json={"apk_path": "D:/does/not/exist.apk"})
    assert response.status_code == 400


def test_websocket_connection(client):
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text('{"action": "ping"}')
        data = websocket.receive_text()
        assert "pong" in data


@pytest.mark.skip(reason="Full pipeline test: requires real APK + tools, runs >60s")
def test_full_pipeline_writes_to_work_dir(client, test_apk_path):
    """End-to-end: run the full pipeline on an APK and verify outputs in WORK_DIR."""
    result = run_pipeline(str(test_apk_path))
    sample_id = result["sample_id"]

    result_path = settings.WORK_DIR / sample_id / "pipeline_result.json"
    assert result_path.exists(), f"Expected result at {result_path}"

    response = client.get(f"/api/sample/{sample_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["sample_id"] == sample_id
    assert "metadata" in data


@pytest.mark.skip(reason="Upload test: requires real APK and live backend")
def test_api_upload_and_status(client, test_apk_path):
    """Upload an APK and verify status endpoint returns uploaded state."""
    with open(test_apk_path, "rb") as f:
        response = client.post("/api/upload", files={"file": ("test.apk", f, "application/vnd.android.package-archive")})
    assert response.status_code == 200, response.text
    data = response.json()
    assert "upload_id" in data
    assert data["sha256"]
    assert data["status"] == "uploaded"

    upload_id = data["upload_id"]
    response = client.get(f"/api/sample/{upload_id}/status")
    assert response.status_code == 404  # not analyzed yet


def test_api_graph_node_ids_are_deterministic(client):
    """Graph endpoint should return stable node IDs across calls."""
    samples = client.get("/api/samples").json()["samples"]
    if not samples:
        pytest.skip("No analyzed samples available")
    sample_id = samples[0]["id"]
    resp1 = client.get(f"/api/graph/{sample_id}").json()
    resp2 = client.get(f"/api/graph/{sample_id}").json()
    assert resp1["total_nodes"] == resp2["total_nodes"]
    assert [n["id"] for n in resp1["nodes"]] == [n["id"] for n in resp2["nodes"]]


def test_api_dissection_caches_on_demand(client):
    """Dissection endpoint should generate and cache dissection.json if missing."""
    samples = client.get("/api/samples").json()["samples"]
    if not samples:
        pytest.skip("No analyzed samples available")
    sample_id = samples[0]["id"]
    dissection_path = settings.WORK_DIR / sample_id / "dissection.json"
    if dissection_path.exists():
        dissection_path.unlink()

    response = client.get(f"/api/sample/{sample_id}/dissection")
    assert response.status_code == 200
    assert dissection_path.exists(), "dissection.json should be cached after on-demand generation"
