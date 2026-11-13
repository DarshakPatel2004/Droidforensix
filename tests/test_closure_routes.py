"""Route-level tests for the endpoints the audit found without a test (T-09).

Everything runs against a synthetic pipeline_result.json in the per-test tmp
WORK_DIR (see conftest.isolate_work_dir). LLM calls and the real pipeline are
stubbed so the suite stays offline and deterministic.
"""

import hashlib
import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import backend.main as backend_main
import backend.routers.dissection as dissection_routes
import backend.routers.jobs as jobs
import backend.routers.reports as reports
import backend.routers.samples as samples_routes
from backend.config import settings
from backend.main import app

SAMPLE_ID = hashlib.sha256(b"closure-route-sample").hexdigest()
APK_MAGIC = b"PK\x03\x04"


def _result(sample_id: str = SAMPLE_ID) -> dict:
    return {
        "sample_id": sample_id,
        "metadata": {"sample_name": "closure.apk", "package_name": "com.example.closure", "sha256": sample_id},
        "family_identification": {"family": "ClosureFamily"},
        "llm_assessment": {"threat_level": "high", "severity": "high", "risk_score": 80},
        "threat_chains": [],
        "c2_infrastructure": [
            {
                "c2_id": "c2_001",
                "domain": "evil-c2.example",
                "ip": "203.0.113.5",
                "port": 443,
                "protocol": "https",
                "path": "/gate.php",
                "raw_url": "https://evil-c2.example/gate.php",
                "classification": "c2",
                "status": "active",
                "classification_reason": "hardcoded in dex",
                "package_name": "com.example.closure",
            },
            {
                "c2_id": "c2_002",
                "domain": "www.google.com",
                "ip": "",
                "port": 443,
                "protocol": "https",
                "path": "/",
                "raw_url": "https://www.google.com/",
                "classification": "benign",
                "status": "benign",
                "classification_reason": "well-known host",
            },
        ],
    }


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample(client):
    """Write the synthetic result into the tmp WORK_DIR and return its id."""
    sample_dir = settings.WORK_DIR / SAMPLE_ID
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "pipeline_result.json").write_text(json.dumps(_result()), encoding="utf-8")
    return SAMPLE_ID


def _unique_apk() -> bytes:
    # The upload route dedupes by SHA-256 across the process, so each test needs unique bytes.
    return APK_MAGIC + uuid.uuid4().bytes * 4


# ---------------------------------------------------------------------------
# Threat-intel exports (csv / stix / yara / suricata)
# ---------------------------------------------------------------------------


class TestThreatIntelExports:
    def test_csv_blocklist_content_type_and_rows(self, client, sample):
        resp = client.get(f"/api/sample/{sample}/threat-intel/export/csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert f"droidforensix_{sample[:16]}_blocklist.csv" in resp.headers["content-disposition"]
        lines = resp.text.strip().splitlines()
        assert lines[0].startswith("classification,status,domain,ip,port")
        assert any("evil-c2.example" in line and "hardcoded in dex" in line for line in lines[1:])

    def test_stix_bundle_labels_each_indicator_with_its_classification(self, client, sample):
        resp = client.get(f"/api/sample/{sample}/threat-intel/export/stix")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"
        bundle = resp.json()
        assert bundle["type"] == "bundle"
        by_pattern = {obj["pattern"]: obj for obj in bundle["objects"]}
        assert set(by_pattern) == {
            "[domain-name:value = 'evil-c2.example']",
            "[domain-name:value = 'www.google.com']",
        }
        assert by_pattern["[domain-name:value = 'evil-c2.example']"]["labels"] == ["suspicious", "active", "c2"]
        assert by_pattern["[domain-name:value = 'www.google.com']"]["labels"][0] == "benign"

    def test_stix_rejects_injection_in_domain(self, client, sample):
        result = _result()
        result["c2_infrastructure"] = [{
            "c2_id": "c2_x", "domain": "bad'] OR [x", "classification": "c2", "status": "active",
        }]
        (settings.WORK_DIR / sample / "pipeline_result.json").write_text(json.dumps(result), encoding="utf-8")
        bundle = client.get(f"/api/sample/{sample}/threat-intel/export/stix").json()
        assert bundle["objects"] == []

    def test_yara_rule_names_the_malicious_domain(self, client, sample):
        resp = client.get(f"/api/sample/{sample}/threat-intel/export/yara")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        body = resp.text
        assert body.startswith(f"rule droidforensix_{sample[:16]}")
        assert '"evil-c2.example"' in body
        assert "google.com" not in body
        assert "any of them" in body

    def test_suricata_rules_skip_benign_hosts(self, client, sample):
        resp = client.get(f"/api/sample/{sample}/threat-intel/export/suricata")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        lines = resp.text.strip().splitlines()
        assert len(lines) == 1
        assert 'dns.query; content:"evil-c2.example"' in lines[0]
        assert "sid:1000000;" in lines[0]
        assert "google" not in resp.text

    @pytest.mark.parametrize("suffix", ["csv", "stix", "yara", "suricata"])
    def test_exports_404_for_unknown_or_malformed_sample(self, client, suffix):
        assert client.get(f"/api/sample/{'0' * 64}/threat-intel/export/{suffix}").status_code == 404
        assert client.get(f"/api/sample/..%5Cevil/threat-intel/export/{suffix}").status_code == 404


# ---------------------------------------------------------------------------
# PDF report and report-adjacent routes
# ---------------------------------------------------------------------------


class TestPdfReport:
    def test_quick_report_returns_pdf_attachment(self, client, sample):
        resp = client.post(f"/api/sample/{sample}/report/pdf", json={"mode": "quick"})
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.headers["content-disposition"] == f'attachment; filename="droidforensix_{sample[:12]}_quick.pdf"'
        assert resp.content.startswith(b"%PDF-")

    def test_report_rejects_unknown_mode(self, client, sample):
        resp = client.post(f"/api/sample/{sample}/report/pdf", json={"mode": "medium"})
        assert resp.status_code == 400
        assert resp.json()["detail"] == "mode must be 'quick' or 'full'"

    def test_report_rejects_non_object_sections(self, client, sample):
        resp = client.post(f"/api/sample/{sample}/report/pdf", json={"mode": "quick", "sections": ["metadata"]})
        assert resp.status_code == 400

    def test_report_404_for_unknown_sample(self, client):
        assert client.post(f"/api/sample/{'0' * 64}/report/pdf", json={}).status_code == 404

    def test_explain_chain_uses_llm_result(self, client, sample, monkeypatch):
        seen = {}

        def fake_explain(chain):
            seen["chain"] = chain
            return {"summary": "stub", "threat_type": "dropper", "confidence": 0.5}

        monkeypatch.setattr(reports, "explain_threat_chain", fake_explain)
        resp = client.post(
            f"/api/sample/{sample}/explain-chain",
            json={"chain": {"chain_id": "chain-7", "steps": []}},
        )
        assert resp.status_code == 200
        assert resp.json() == {
            "chain_id": "chain-7",
            "llm": {"summary": "stub", "threat_type": "dropper", "confidence": 0.5},
        }
        assert seen["chain"] == {"chain_id": "chain-7", "steps": []}

    def test_explain_chain_reports_llm_failure_instead_of_500(self, client, sample, monkeypatch):
        def boom(chain):
            raise RuntimeError("backend offline")

        monkeypatch.setattr(reports, "explain_threat_chain", boom)
        resp = client.post(f"/api/sample/{sample}/explain-chain", json={"chain": {"chain_id": "c"}})
        assert resp.status_code == 200
        llm = resp.json()["llm"]
        assert llm["summary"] == "Chain explanation unavailable: backend offline"
        assert llm["confidence"] == 0.0

    def test_deobfuscate_decodes_base64(self, client, sample):
        resp = client.post(
            f"/api/sample/{sample}/deobfuscate",
            json={"text": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["original"] == "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="
        assert any(r["type"] == "base64" and r["value"] == "hello world this is a test" for r in body["results"])

    def test_deobfuscate_404_for_unknown_sample(self, client):
        assert client.post(f"/api/sample/{'0' * 64}/deobfuscate", json={"text": "abc"}).status_code == 404

    def test_explain_method_returns_static_annotations_and_llm(self, client, sample, monkeypatch):
        monkeypatch.setattr(
            dissection_routes,
            "explain_method",
            lambda cls, meth, code, flags: {"summary": f"{cls}.{meth}", "threat_type": "unknown", "confidence": 0.1},
        )
        resp = client.post(
            f"/api/sample/{sample}/dissection/explain-method",
            json={
                "class_name": "com.example.Loader",
                "method_name": "load",
                "method_code": "Class.forName(\"dalvik.system.DexClassLoader\")",
                "flags": ["reflect"],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["class_name"] == "com.example.Loader"
        assert body["method_name"] == "load"
        assert body["llm"]["summary"] == "com.example.Loader.load"
        assert isinstance(body["line_annotations"], (list, dict))

    def test_explain_method_404_for_unknown_sample(self, client):
        resp = client.post(
            f"/api/sample/{'0' * 64}/dissection/explain-method",
            json={"class_name": "A", "method_name": "b", "method_code": "x"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Samples: family, obfuscation, class-methods, sample-id validation
# ---------------------------------------------------------------------------


class TestSampleRoutes:
    def test_family_route_returns_identifier_output(self, client, sample, monkeypatch):
        monkeypatch.setattr(
            samples_routes,
            "identify_family",
            lambda sid, result: {"family": "ClosureFamily", "confidence": 0.9, "sample_id": sid},
        )
        resp = client.get(f"/api/sample/{sample}/family")
        assert resp.status_code == 200
        assert resp.json() == {"family": "ClosureFamily", "confidence": 0.9, "sample_id": sample}

    def test_family_route_404_for_unknown_sample(self, client):
        assert client.get(f"/api/sample/{'0' * 64}/family").status_code == 404

    def test_obfuscation_route_returns_view_for_sample_without_analysis(self, client, sample):
        resp = client.get(f"/api/sample/{sample}/obfuscation")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)

    def test_obfuscation_route_404_for_unknown_sample(self, client):
        assert client.get(f"/api/sample/{'0' * 64}/obfuscation").status_code == 404

    def test_class_methods_404_when_apk_missing(self, client, sample):
        resp = client.get(f"/api/sample/{sample}/dissection/class-methods/com.example.Foo")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "APK file not found for sample"

    def test_class_methods_404_for_unknown_sample(self, client):
        resp = client.get(f"/api/sample/{'0' * 64}/dissection/class-methods/com.example.Foo")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Sample not found"

    @pytest.mark.parametrize("bad_id", ["..", "..%5Cevil", "short", "A" * 64])
    @pytest.mark.parametrize("path", [
        "/api/sample/{sid}/family",
        "/api/sample/{sid}/obfuscation",
        "/api/sample/{sid}/dissection/class-methods/com.example.Foo",
        "/api/sample/{sid}/threat-intel/export/csv",
        "/api/sample/{sid}/threat-intel/export/stix",
        "/api/sample/{sid}/threat-intel/export/yara",
        "/api/sample/{sid}/threat-intel/export/suricata",
    ])
    def test_malformed_sample_id_is_404_on_every_route(self, client, bad_id, path):
        # Routes never read a file for a non-hex id; the 404 must come from the id check, not a crash.
        resp = client.get(path.format(sid=bad_id))
        assert resp.status_code == 404

    def test_malformed_sample_id_on_pdf_and_deobfuscate(self, client):
        assert client.post("/api/sample/..%5Cevil/report/pdf", json={}).status_code == 404
        assert client.post("/api/sample/..%5Cevil/deobfuscate", json={"text": "abc"}).status_code == 404


# ---------------------------------------------------------------------------
# Logging endpoint
# ---------------------------------------------------------------------------


def test_log_error_acknowledges(client):
    resp = client.post("/api/log-error", json={"message": "boom", "stack": "at x"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


# ---------------------------------------------------------------------------
# Upload -> analyze -> WebSocket progress -> status (the main product flow)
# ---------------------------------------------------------------------------


@pytest.fixture
def live_client(monkeypatch):
    """TestClient with the lifespan running, so the portal event loop persists
    across requests and background analysis tasks are not cancelled."""
    monkeypatch.setattr(backend_main, "ensure_ollama_running", lambda: None)
    monkeypatch.setattr(backend_main, "stop_ollama", lambda: None)
    with TestClient(app) as client:
        yield client


def _upload(client, content: bytes):
    return client.post(
        "/api/upload",
        files={"file": ("closure.apk", content, "application/vnd.android.package-archive")},
    )


def _wait_for_status(client, upload_id: str, wanted: str, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    body = {}
    while time.monotonic() < deadline:
        body = client.get(f"/api/sample/{upload_id}/status").json()
        if body["status"] == wanted:
            return body
        time.sleep(0.05)
    raise AssertionError(f"status never reached {wanted!r}: last={body}")


class TestUploadAnalyzeFlow:
    def test_upload_returns_upload_id_and_registers_file(self, live_client):
        resp = _upload(live_client, _unique_apk())
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "uploaded"
        assert body["filename"] == "closure.apk"
        assert len(body["sha256"]) == 64
        assert body["upload_id"] in jobs.upload_registry

    def test_upload_rejects_non_zip_content(self, live_client):
        resp = _upload(live_client, b"not an apk at all" * 4)
        assert resp.status_code == 400
        assert "bad header" in resp.json()["detail"]

    def test_analyze_unknown_upload_is_404(self, live_client):
        assert live_client.post(f"/api/analyze/{uuid.uuid4()}").status_code == 404

    def test_analyze_fails_when_uploaded_file_was_removed(self, live_client):
        upload_id = _upload(live_client, _unique_apk()).json()["upload_id"]
        from pathlib import Path

        Path(jobs.upload_registry[upload_id]["path"]).unlink()
        resp = live_client.post(f"/api/analyze/{upload_id}")
        assert resp.status_code == 400
        assert resp.json()["detail"] == "Uploaded APK file no longer exists"

    def test_analyze_streams_progress_over_websocket_and_completes(self, live_client, monkeypatch):
        calls = []

        def fake_run_pipeline(apk_path, event_emitter=None, **_kwargs):
            calls.append(apk_path)
            event_emitter("analysis_started", {"sample_id": "pending"})
            event_emitter("step_completed", {"step": 1, "name": "extraction"})
            event_emitter("analysis_complete", {"sample_id": SAMPLE_ID})
            return {"sample_id": SAMPLE_ID}

        monkeypatch.setattr(jobs, "run_pipeline", fake_run_pipeline)
        upload_id = _upload(live_client, _unique_apk()).json()["upload_id"]

        with live_client.websocket_connect("/ws") as ws:
            resp = live_client.post(f"/api/analyze/{upload_id}")
            assert resp.status_code == 200
            assert resp.json()["status"] == "queued"

            seen = []
            while True:
                event = ws.receive_json()
                seen.append(event["event_type"])
                if event["event_type"] == "analysis_complete":
                    break

        assert seen == ["analysis_started", "step_completed", "analysis_complete"]
        assert calls == [jobs.upload_registry[upload_id]["path"]]

        status = _wait_for_status(live_client, upload_id, "completed")
        assert status["sample_id"] == SAMPLE_ID
        assert status["error"] is None
        assert jobs.upload_registry[upload_id]["sample_id"] == SAMPLE_ID

    def test_analyze_records_failure_without_raising(self, live_client, monkeypatch):
        def exploding_pipeline(apk_path, event_emitter=None, **_kwargs):
            raise RuntimeError("apktool exploded")

        monkeypatch.setattr(jobs, "run_pipeline", exploding_pipeline)
        upload_id = _upload(live_client, _unique_apk()).json()["upload_id"]
        assert live_client.post(f"/api/analyze/{upload_id}").status_code == 200

        status = _wait_for_status(live_client, upload_id, "failed")
        assert status["error"] == "apktool exploded"

    def test_second_analyze_while_running_does_not_start_another_run(self, live_client, monkeypatch):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        release = threading.Event()
        calls = []

        def blocking_pipeline(apk_path, event_emitter=None, **_kwargs):
            calls.append(apk_path)
            release.wait(timeout=10)
            return {"sample_id": SAMPLE_ID}

        # The production pool is module-level and shared by every test; a worker left blocked
        # by an earlier test would keep this job queued. Give this test its own pool.
        own_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="analysis-test")
        monkeypatch.setattr(jobs, "_ANALYSIS_EXECUTOR", own_pool)
        monkeypatch.setattr(jobs, "run_pipeline", blocking_pipeline)
        upload_id = _upload(live_client, _unique_apk()).json()["upload_id"]
        try:
            assert live_client.post(f"/api/analyze/{upload_id}").json()["status"] == "queued"
            _wait_for_status(live_client, upload_id, "analyzing")

            retry = live_client.post(f"/api/analyze/{upload_id}").json()
            assert retry["status"] == "analyzing"
            assert retry["message"] == "Analysis already in progress for this upload."
        finally:
            release.set()
        _wait_for_status(live_client, upload_id, "completed")
        own_pool.shutdown(wait=True)
        assert len(calls) == 1

    def test_websocket_rejects_foreign_origin(self, live_client):
        with pytest.raises(WebSocketDisconnect):
            with live_client.websocket_connect("/ws", headers={"origin": "https://evil.example"}):
                pass

    def test_websocket_answers_ping_from_allowed_origin(self, live_client):
        origin = settings.FRONTEND_URL
        with live_client.websocket_connect("/ws", headers={"origin": origin}) as ws:
            ws.send_text(json.dumps({"action": "ping"}))
            assert ws.receive_json()["event_type"] == "pong"

    def test_websocket_ignores_non_object_json(self, live_client):
        with live_client.websocket_connect("/ws") as ws:
            ws.send_text("[1, 2, 3]")
            ws.send_text(json.dumps({"action": "ping"}))
            # The list was ignored, not treated as a disconnect: the next ping still answers.
            assert ws.receive_json()["event_type"] == "pong"
