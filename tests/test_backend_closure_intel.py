"""Closure tests for backend audit items B1-08, B1-11, B1-14, B1-19 and B1-27."""

import hashlib
import json
import logging
import threading

import pytest
from fastapi.testclient import TestClient

from backend import censys_enrichment, community_intel, family_id, threat_intel
from backend.main import app

SAMPLE = "cd" * 32


# B1-19: community intel is opt-in
@pytest.fixture
def sample_on_disk(tmp_path):
    from backend.config import settings

    sample_dir = settings.WORK_DIR / SAMPLE
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "pipeline_result.json").write_text(
        json.dumps({"sample_id": SAMPLE, "metadata": {"package_name": "com.example"}}), encoding="utf-8"
    )
    return sample_dir


def test_community_intel_is_forbidden_without_opt_in(monkeypatch, sample_on_disk):
    monkeypatch.delenv("DF_ALLOW_LIVE_LOOKUPS", raising=False)
    response = TestClient(app).get(f"/api/sample/{SAMPLE}/community-intel")
    assert response.status_code == 403


def test_community_intel_is_served_with_opt_in(monkeypatch, sample_on_disk):
    monkeypatch.setenv("DF_ALLOW_LIVE_LOOKUPS", "1")
    from backend.routers import samples

    monkeypatch.setattr(samples, "get_cached_community_intel", lambda *_a: {"posts": []})
    response = TestClient(app).get(f"/api/sample/{SAMPLE}/community-intel")
    assert response.status_code == 200


def test_community_cache_is_keyed_on_package_and_family(monkeypatch):
    calls = []

    def _search(package_name, family):
        calls.append((package_name, family))
        return {"posts": [], "package": package_name}

    monkeypatch.setattr(community_intel, "search_community_intel", _search)
    monkeypatch.setattr(community_intel, "_CACHE", {})
    first = community_intel.get_cached_community_intel(SAMPLE, "com.a", "unknown")
    second = community_intel.get_cached_community_intel(SAMPLE, "com.b", "unknown")
    assert first["package"] == "com.a" and second["package"] == "com.b"
    assert len(calls) == 2


# B1-08: a missing family KB index is an error, not an empty index
def test_missing_kb_index_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(family_id, "_KB_PATH", tmp_path / "missing_kb.json")
    monkeypatch.setattr(family_id, "_KB_LOADED", None)
    with pytest.raises(RuntimeError, match="Family knowledge base"):
        family_id._kb_load()


def test_missing_feature_cache_is_logged_as_error(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(family_id, "_KB_CACHE_PATH", tmp_path / "gap_features_cache.json")
    monkeypatch.setattr(family_id, "_KB_CACHE_LOADED", None)
    with caplog.at_level(logging.ERROR, logger=family_id.logger.name):
        assert family_id._kb_load_cache() == {}
    assert any(r.levelno == logging.ERROR and "missing" in r.getMessage() for r in caplog.records)


# B1-11: list-valued and long fields do not blow up the LLM prompt
def test_family_context_summarises_native_library_list():
    libs = [f"lib{i}.so" for i in range(500)]
    result = {
        "metadata": {"package_name": "com.example"},
        "extraction": {"native_libs_found": libs, "decompiled_classes": 3},
        "obfuscation_analysis": {
            "native_library_analysis": {
                "suspicious": [{"library": "x" * 5000, "reason": "r" * 5000, "detail": "d" * 5000}] * 50,
            },
        },
    }
    context = family_id._family_context(result)
    assert "Native libs found: 500" in context
    assert "lib499.so" not in context
    assert len(context) < 10_000
    assert context.count("Suspicious native libs") == 1


# B1-14: C2 liveness goes to a sidecar; pipeline_result.json and its hash are untouched
def test_c2_liveness_is_written_to_sidecar_and_result_hash_is_kept(monkeypatch, tmp_path):
    from backend.config import settings

    sample_dir = settings.WORK_DIR / SAMPLE
    sample_dir.mkdir(parents=True, exist_ok=True)
    result_path = sample_dir / "pipeline_result.json"
    result = {"sample_id": SAMPLE, "c2_infrastructure": [{"c2_id": "c1", "domain": "nxd.example.test"}]}
    result_path.write_text(json.dumps(result), encoding="utf-8")
    digest_before = hashlib.sha256(result_path.read_bytes()).hexdigest()

    import socket

    def _nxdomain(*_a, **_k):
        raise socket.gaierror(-2, "gone")

    monkeypatch.setenv("DF_ALLOW_LIVE_LOOKUPS", "1")
    monkeypatch.setattr(socket, "getaddrinfo", _nxdomain)
    threat_intel.build_threat_intel(result, SAMPLE)

    sidecar = json.loads((sample_dir / threat_intel.C2_LIVENESS_FILE).read_text(encoding="utf-8"))
    assert sidecar["c1"]["status"] == "dead"
    assert hashlib.sha256(result_path.read_bytes()).hexdigest() == digest_before
    assert not (sample_dir / "step5_c2s.json").exists()


def test_c2_liveness_sidecar_is_reused_without_new_lookups(monkeypatch):
    from backend.config import settings

    sample_dir = settings.WORK_DIR / SAMPLE
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / threat_intel.C2_LIVENESS_FILE).write_text(
        json.dumps({"c1": {"live_dns": {"resolves": False, "ips": []}, "status": "dead"}}), encoding="utf-8"
    )
    monkeypatch.setenv("DF_ALLOW_LIVE_LOOKUPS", "1")

    def _no_dns(*_a, **_k):
        raise AssertionError("resolved C2 must not be looked up again")

    import socket

    monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
    result = {"sample_id": SAMPLE, "c2_infrastructure": [{"c2_id": "c1", "domain": "x.example.test"}]}
    threat_intel.build_threat_intel(result, SAMPLE)
    assert result["c2_infrastructure"][0]["status"] == "dead"


# B1-27: censys cache survives concurrent writers and logs unreadable caches
def test_censys_cache_put_keeps_concurrent_entries(monkeypatch, tmp_path):
    monkeypatch.setattr(censys_enrichment, "CACHE_PATH", tmp_path / "censys_cache.json")
    threads = [
        threading.Thread(target=censys_enrichment._cache_put, args=(f"10.0.0.{i}", {"ip": f"10.0.0.{i}"}))
        for i in range(40)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    saved = json.loads((tmp_path / "censys_cache.json").read_text(encoding="utf-8"))
    assert len(saved) == 40
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]


def test_censys_unreadable_cache_is_logged(monkeypatch, tmp_path, caplog):
    cache_path = tmp_path / "censys_cache.json"
    cache_path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(censys_enrichment, "CACHE_PATH", cache_path)
    with caplog.at_level(logging.WARNING, logger=censys_enrichment.logger.name):
        assert censys_enrichment._load_cache() == {}
    assert any("unreadable" in r.getMessage() for r in caplog.records)
