"""Closure tests for backend audit items B2-15, B2-21, B2-23 (caches and invalidation)."""

import json
import os

import pytest

from backend import cache_utils, dissection, transformers
from backend.cache_utils import StampedLRU, store_timed
from backend.routers import dissection as dissection_router

SAMPLE = "ab" * 32


def _write_result(work_dir, sample_id, payload):
    sample_dir = work_dir / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "pipeline_result.json").write_text(json.dumps(payload), encoding="utf-8")
    return sample_dir / "pipeline_result.json"


def test_stamped_lru_evicts_least_recently_used():
    cache = StampedLRU(max_entries=2)
    cache.put("a", 1, "A")
    cache.put("b", 1, "B")
    assert cache.get("a", 1) == "A"  # touch a so b is the oldest
    cache.put("c", 1, "C")
    assert cache.get("b", 1) is None
    assert cache.get("a", 1) == "A"
    assert len(cache) == 2


def test_stamped_lru_drops_entry_when_stamp_changes():
    cache = StampedLRU(max_entries=4)
    cache.put("a", "mtime-1", "old")
    assert cache.get("a", "mtime-2") is None
    assert len(cache) == 0


def test_store_timed_evicts_expired_and_caps_size():
    store = {}
    store_timed(store, "old", "x", now=0.0, ttl=10, max_entries=3)
    store_timed(store, "k1", "y", now=100.0, ttl=10, max_entries=3)
    assert "old" not in store  # expired entries are evicted on insert, not only skipped on read
    for i in range(5):
        store_timed(store, f"k{i + 2}", i, now=100.0, ttl=10, max_entries=3)
    assert len(store) == 3


def test_atomic_write_json_leaves_no_temp_files(tmp_path):
    target = tmp_path / "data.json"
    cache_utils.atomic_write_json(target, {"a": 1})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]


def test_load_result_returns_independent_copies(tmp_path):
    _write_result(transformers.WORK_DIR, SAMPLE, {"sample_id": SAMPLE, "c2_infrastructure": [{"domain": "a.test"}]})
    first = transformers.load_result(SAMPLE)
    first["c2_infrastructure"][0]["status"] = "mutated"
    second = transformers.load_result(SAMPLE)
    assert "status" not in second["c2_infrastructure"][0]


def test_load_result_reloads_when_pipeline_result_changes():
    path = _write_result(transformers.WORK_DIR, SAMPLE, {"sample_id": SAMPLE, "marker": 1})
    assert transformers.load_result(SAMPLE)["marker"] == 1
    path.write_text(json.dumps({"sample_id": SAMPLE, "marker": 2}), encoding="utf-8")
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000_000))
    assert transformers.load_result(SAMPLE)["marker"] == 2


def test_source_stamp_changes_with_pipeline_result_mtime():
    path = _write_result(transformers.WORK_DIR, SAMPLE, {"sample_id": SAMPLE})
    before = transformers.source_stamp(SAMPLE)
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000_000))
    assert transformers.source_stamp(SAMPLE) != before


def test_dissection_summary_is_regenerated_when_stamp_is_stale(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from backend.main import app

    _write_result(transformers.WORK_DIR, SAMPLE, {"sample_id": SAMPLE, "metadata": {}})
    summary_path = transformers.WORK_DIR / SAMPLE / "dissection_summary.json"
    summary_path.write_text(json.dumps({"source_stamp": "stale", "summary": "old"}), encoding="utf-8")
    calls = []

    async def _fake_dissection(sample_id, refresh=False):
        return {}

    monkeypatch.setattr(dissection_router, "_get_or_create_dissection", _fake_dissection)
    monkeypatch.setattr(dissection_router, "load_dissection", lambda *_a, **_k: {})
    monkeypatch.setattr(dissection_router, "_get_sample_apk_path", lambda _sid: None)

    def _fake_summarize(dissection_data, class_objects):
        calls.append(1)
        return {"status": "ok", "summary": "fresh"}

    monkeypatch.setattr(dissection_router, "summarize_dissection", _fake_summarize)
    body = TestClient(app).get(f"/api/sample/{SAMPLE}/dissection/summary").json()
    assert body["summary"] == "fresh"
    assert calls == [1]


def test_dissection_summary_cache_hit_skips_llm(monkeypatch):
    from fastapi.testclient import TestClient

    from backend.main import app

    _write_result(transformers.WORK_DIR, SAMPLE, {"sample_id": SAMPLE, "metadata": {}})
    stamp = transformers.source_stamp(SAMPLE)
    summary_path = transformers.WORK_DIR / SAMPLE / "dissection_summary.json"
    summary_path.write_text(json.dumps({"source_stamp": stamp, "summary": "cached"}), encoding="utf-8")

    def _boom(*_a, **_k):
        raise AssertionError("LLM must not run on a fresh cache hit")

    monkeypatch.setattr(dissection_router, "summarize_dissection", _boom)
    body = TestClient(app).get(f"/api/sample/{SAMPLE}/dissection/summary").json()
    assert body["summary"] == "cached"


def test_apk_path_lookup_does_not_walk_the_samples_tree(monkeypatch, tmp_path):
    """No recursive fallback: a file that only a deep rglob would find is not returned (audit B2-15)."""
    from backend.config import settings

    # SAMPLES_DIR is not redirected by the autouse fixture, so point it at tmp explicitly.
    monkeypatch.setattr(settings, "SAMPLES_DIR", tmp_path / "samples")
    _write_result(transformers.WORK_DIR, SAMPLE, {"sample_id": SAMPLE, "metadata": {"sample_name": "evil.apk"}})
    deep = settings.SAMPLES_DIR / "malware" / "other" / "nested" / "evil.apk"
    deep.parent.mkdir(parents=True)
    deep.write_bytes(b"PK")
    monkeypatch.setattr(dissection_router, "_APK_PATH_MEMO", {})
    assert dissection_router._get_sample_apk_path(SAMPLE) is None


def test_apk_path_lookup_is_memoised(monkeypatch):
    from backend.config import settings

    apk = settings.UPLOADS_DIR / SAMPLE / "file.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"PK")
    _write_result(transformers.WORK_DIR, SAMPLE, {"sample_id": SAMPLE, "metadata": {"apk_path": str(apk)}})
    monkeypatch.setattr(dissection_router, "_APK_PATH_MEMO", {})
    assert dissection_router._get_sample_apk_path(SAMPLE) == apk

    calls = []
    monkeypatch.setattr(dissection_router, "_find_sample_apk_path", lambda sid: calls.append(sid))
    assert dissection_router._get_sample_apk_path(SAMPLE) == apk
    assert calls == []


def test_dissection_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(dissection, "_TIMED_CACHE_MAX_ENTRIES", 3)
    for i in range(10):
        store_timed(dissection._DISSECTION_CACHE, f"s{i}", {}, now=float(i), ttl=1e9,
                    max_entries=dissection._TIMED_CACHE_MAX_ENTRIES)
    assert len(dissection._DISSECTION_CACHE) == 3


@pytest.mark.parametrize("junk", [None, "x"])
def test_store_timed_accepts_any_value(junk):
    store = {}
    store_timed(store, "k", junk, now=0.0, ttl=10, max_entries=2)
    assert store["k"] == (junk, 0.0)
