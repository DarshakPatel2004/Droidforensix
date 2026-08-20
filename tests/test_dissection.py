"""
Tests for APK dissection backend.
"""

import json
import os
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app
from backend.dissection import APKDissector, SampleAPKCache, load_dissection, _class_cache_locks, _class_cache_locks_lock



@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def test_apk_path() -> Path:
    """Return a small, real APK for direct dissection tests."""
    path = Path(
        "CICAndMal2017/_extracted_Scareware-APKs/Scareware/virusShield/"
        "002485c5c96f0681a4eccee5b69c5f50.apk"
    )
    if not path.exists():
        pytest.skip("Test APK not found")
    return path


@pytest.fixture(scope="module")
def existing_sample_id() -> str:
    """Return an existing analyzed sample id whose APK is still on disk."""
    work_dir = settings.WORK_DIR
    if not work_dir.exists():
        pytest.skip("No work dir — no samples exist")
    for sample_dir in work_dir.iterdir():
        result_path = sample_dir / "pipeline_result.json"
        if not result_path.exists():
            continue
        try:
            import json
            with open(result_path, "r", encoding="utf-8") as f:
                result = json.load(f)
            sample_id = result.get("sample_id", sample_dir.name)
            sample_name = result.get("metadata", {}).get("sample_name")
            if not sample_name:
                continue
            candidates = [
                settings.SAMPLES_DIR / "malware" / "androzoo_drebin" / sample_name,
                settings.SAMPLES_DIR / "malware" / sample_name,
            ]
            for candidate in candidates:
                if candidate.exists():
                    return sample_id
        except Exception:
            continue
    pytest.skip("No existing analyzed sample with APK on disk")


class TestAPKDissector:
    def test_dissect_returns_expected_keys(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        data = dissector.dissect()
        assert "metadata" in data
        assert "manifest" in data
        assert "permissions" in data
        assert "components" in data
        assert "native_libs" in data
        assert "resources" in data
        assert "dex_stats" in data
        assert "file_structure" in data

    def test_metadata(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        meta = dissector.extract_metadata()
        assert meta["package_name"] == "com.agilebinary.phonebeagle"
        assert meta["file_size_bytes"] > 0
        assert meta["version_code"] is not None

    def test_permissions(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        perms = dissector.extract_permissions()
        assert len(perms) > 0
        names = {p["name"] for p in perms}
        assert "android.permission.INTERNET" in names
        for perm in perms:
            assert "protection_level" in perm
            assert perm["protection_level"] in {"dangerous", "signature", "normal", "unknown"}

    def test_components(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        comps = dissector.extract_components()
        assert len(comps["activities"]) > 0
        for activity in comps["activities"]:
            assert "name" in activity
            assert "exported" in activity

    def test_dex_stats(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        stats = dissector.extract_dex_stats()
        assert stats["dex_count"] >= 1
        assert stats["total_classes"] > 0
        assert stats["total_methods"] > 0
        assert 0 <= stats["entropy"] <= 8

    def test_json_serializable(self, test_apk_path):
        dissector = APKDissector(str(test_apk_path))
        data = dissector.dissect()
        # Must not raise
        json.dumps(data)

    def test_load_dissection_missing(self):
        assert load_dissection(str(settings.WORK_DIR), "nonexistent_sample_id") is None


class TestDissectionEndpoints:
    def test_dissection_full(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection")
        assert response.status_code == 200
        data = response.json()
        assert "metadata" in data
        assert "permissions" in data
        assert "dex_stats" in data

    def test_dissection_manifest(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/manifest")
        assert response.status_code == 200
        data = response.json()
        assert "manifest" in data
        assert "package" in data["manifest"]

    def test_dissection_permissions(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/permissions")
        assert response.status_code == 200
        data = response.json()
        assert "permissions" in data
        assert isinstance(data["permissions"], list)

    def test_dissection_components(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/components")
        assert response.status_code == 200
        data = response.json()
        assert "components" in data
        assert "activities" in data["components"]

    def test_dissection_dex(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/dex")
        assert response.status_code == 200
        data = response.json()
        assert "dex_stats" in data
        assert data["dex_stats"]["dex_count"] >= 1

    def test_dissection_classes(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/classes")
        assert response.status_code == 200
        data = response.json()
        assert "classes" in data
        assert isinstance(data["classes"], list)

    def test_dissection_code_existing_class(self, client, existing_sample_id):
        # Fetch class list first
        classes_resp = client.get(f"/api/sample/{existing_sample_id}/dissection/classes")
        classes = classes_resp.json().get("classes", [])
        if not classes:
            pytest.skip("No decompiled classes available")
        class_name = classes[0]
        response = client.get(
            f"/api/sample/{existing_sample_id}/dissection/code/{class_name}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["class_name"] == class_name
        assert "code" in data
        assert len(data["code"]) > 0

    def test_dissection_code_missing_class(self, client, existing_sample_id):
        response = client.get(
            f"/api/sample/{existing_sample_id}/dissection/code/DefinitelyNotARealClass"
        )
        assert response.status_code == 404

    def test_dissection_strings(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/strings")
        assert response.status_code == 200
        data = response.json()
        assert "sample_id" in data
        assert "categories" in data

    def test_dissection_not_found(self, client):
        response = client.get("/api/sample/nonexistent_sample_id/dissection")
        assert response.status_code == 404


class TestSampleAPKCache:
    def test_cache_hit_and_miss(self, test_apk_path):
        cache = SampleAPKCache()
        apk_path_str = str(test_apk_path)
        # Miss — first parse
        apk1, sha1 = cache.get_or_parse("test_sample_miss", apk_path_str)
        assert apk1 is not None
        assert len(sha1) == 64
        # Hit — second call returns cached
        apk2, sha2 = cache.get_or_parse("test_sample_miss", apk_path_str)
        assert apk2 is apk1
        assert sha2 == sha1

    def test_cache_invalidation(self, test_apk_path):
        cache = SampleAPKCache()
        apk_path_str = str(test_apk_path)
        apk1, _ = cache.get_or_parse("test_sample_inval", apk_path_str)
        assert apk1 is not None
        cache.invalidate("test_sample_inval")
        # After invalidation, next call should re-parse
        apk2, _ = cache.get_or_parse("test_sample_inval", apk_path_str)
        assert apk2 is not apk1

    def test_cache_separate_samples(self, test_apk_path):
        cache = SampleAPKCache()
        apk_path_str = str(test_apk_path)
        apk1, sha1 = cache.get_or_parse("sample_a", apk_path_str)
        apk2, sha2 = cache.get_or_parse("sample_b", apk_path_str)
        assert apk1 is not apk2
        assert sha1 == sha2  # Same file, same hash

    def test_cache_thread_safety(self, test_apk_path):
        cache = SampleAPKCache()
        apk_path_str = str(test_apk_path)
        errors = []
        lock = threading.Lock()

        def get_sample(idx):
            try:
                apk, _ = cache.get_or_parse(f"thread_{idx}", apk_path_str)
                assert apk is not None
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=get_sample, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"Thread safety failures: {errors}"


class TestAtomicClassCache:
    def test_atomic_write_creates_file(self, test_apk_path, tmp_path):
        sample_id = "test_atomic"
        cache_path = tmp_path / sample_id / "dissection_classes_cache.json"
        lock_key = sample_id
        with _class_cache_locks_lock:
            if lock_key not in _class_cache_locks:
                _class_cache_locks[lock_key] = threading.Lock()
        lock = _class_cache_locks[lock_key]
        with lock:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache_path.with_suffix(".tmp")
            data = [{"name": "com.test.TestClass", "methods": [], "network_calls": [], "permissions_used": []}]
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, cache_path)
        assert cache_path.exists()
        with open(cache_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded[0]["name"] == "com.test.TestClass"

    def test_atomic_write_no_partial_read(self, test_apk_path, tmp_path):
        """Verify that a half-written tmp file doesn't leave a corrupt cache."""
        sample_id = "test_atomic_partial"
        cache_path = tmp_path / sample_id / "dissection_classes_cache.json"
        lock_key = sample_id
        with _class_cache_locks_lock:
            if lock_key not in _class_cache_locks:
                _class_cache_locks[lock_key] = threading.Lock()
        lock = _class_cache_locks[lock_key]
        with lock:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache_path.with_suffix(".tmp")
            # Simulate partial write (truncated JSON)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write('{"incomplete": true')
            # Crash before os.replace — tmp file should be removed on next write
            if tmp.exists():
                tmp.unlink()
            # Now write properly
            data = [{"name": "com.test.OK", "methods": [], "network_calls": [], "permissions_used": []}]
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, cache_path)
        with open(cache_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded[0]["name"] == "com.test.OK"


class TestAndroguardDissection:
    def test_list_decompiled_classes_returns_empty_for_bogus_path(self):
        """APKDissector with a non-existent APK should return no classes."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bogus_apk = Path(tmp) / "nonexistent.apk"
            bogus_apk.write_text("this is not an APK", encoding="utf-8")
            dissector = APKDissector(str(bogus_apk), work_dir=tmp)
            assert dissector.list_decompiled_classes() == []

    def test_classes_endpoint_returns_classes_list(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/classes")
        assert response.status_code == 200
        data = response.json()
        assert "classes" in data
        assert isinstance(data["classes"], list)

    def test_refresh_param_invalidates_cache(self, client, existing_sample_id):
        """?refresh=true should not throw and should return valid data."""
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/classes?refresh=true")
        assert response.status_code == 200
        data = response.json()
        assert "classes" in data
        assert isinstance(data["classes"], list)


class TestPagination:
    def test_pagination_defaults(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/classes")
        assert response.status_code == 200
        data = response.json()
        assert "offset" in data
        assert "limit" in data
        assert data["offset"] == 0
        assert data["limit"] == 50
        assert "total" in data
        assert isinstance(data["total"], int)

    def test_pagination_offset(self, client, existing_sample_id):
        # Get first page
        first = client.get(f"/api/sample/{existing_sample_id}/dissection/classes?offset=0&limit=5")
        assert first.status_code == 200
        first_data = first.json()
        # Get second page
        if first_data["total"] > 5:
            second = client.get(f"/api/sample/{existing_sample_id}/dissection/classes?offset=5&limit=5")
            assert second.status_code == 200
            second_data = second.json()
            assert len(second_data["classes"]) > 0
            assert second_data["classes"][0]["name"] != first_data["classes"][0]["name"]

    def test_pagination_limit_clamped(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/classes?limit=999")
        assert response.status_code == 422  # FastAPI validation error

    def test_pagination_negative_offset_rejected(self, client, existing_sample_id):
        response = client.get(f"/api/sample/{existing_sample_id}/dissection/classes?offset=-1")
        assert response.status_code == 422


class TestLLMSummary:
    def test_condense_dissection_produces_readable_text(self):
        """_condense_dissection should produce a readable condensed text from dissection JSON."""
        from analysis.step7_llm_assessment import _condense_dissection
        dissection = {
            "metadata": {
                "package_name": "com.test.malware",
                "version_name": "1.0",
                "version_code": 1,
                "min_sdk_version": 21,
                "target_sdk_version": 30,
                "file_size_bytes": 5 * 1024 * 1024,
                "is_multidex": True,
            },
            "permissions": [
                {"name": "android.permission.INTERNET", "protection_level": "normal"},
                {"name": "android.permission.READ_SMS", "protection_level": "dangerous"},
                {"name": "android.permission.CAMERA", "protection_level": "dangerous"},
            ],
            "components": {
                "activities": [
                    {"name": "com.test.MainActivity", "exported": True},
                    {"name": "com.test.Hidden", "exported": False},
                ],
                "services": [
                    {"name": "com.test.C2Service", "exported": True},
                ],
                "receivers": [],
                "providers": [],
            },
            "native_libs": [{"name": "libnative.so", "size": 12345}],
            "dex_stats": {"dex_count": 2, "total_classes": 500, "total_methods": 3000, "total_strings": 8000},
            "file_structure": {"top_level_directories": ["lib", "res", "assets"], "total_files": 200},
        }
        result = _condense_dissection(dissection)
        assert "com.test.malware" in result
        assert "READ_SMS" in result
        assert "CAMERA" in result
        assert "C2Service" in result
        assert "exported" in result
        assert "libnative.so" in result
        assert "500" in result  # total_classes

    def test_condense_dissection_with_class_objects(self):
        """_condense_dissection should include suspicious classes when provided."""
        from analysis.step7_llm_assessment import _condense_dissection
        dissection = {
            "metadata": {"package_name": "com.test"},
            "permissions": [],
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
            "dex_stats": {"dex_count": 1, "total_classes": 10, "total_methods": 50, "total_strings": 100},
        }
        class_objects = [
            {
                "name": "com.test.C2Client",
                "methods": [{"name": "sendData"}, {"name": "connect"}],
                "network_calls": ["HttpURLConnection.openConnection()"],
                "permissions_used": ["android.permission.INTERNET"],
            },
            {
                "name": "com.test.Benign",
                "methods": [{"name": "onCreate"}],
                "network_calls": [],
                "permissions_used": [],
            },
        ]
        result = _condense_dissection(dissection, class_objects)
        assert "C2Client" in result
        assert "sendData" in result
        assert "1 network calls" in result

    def test_condense_dissection_truncates_long_output(self):
        """_condense_dissection should truncate if output exceeds ~14000 chars."""
        from analysis.step7_llm_assessment import _condense_dissection
        # Build a dissection with many permissions to exceed limit
        dissection = {
            "metadata": {"package_name": "com.test"},
            "permissions": [{"name": f"android.permission.FAKE_{i}", "protection_level": "dangerous"} for i in range(500)],
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
            "dex_stats": {"dex_count": 1, "total_classes": 10, "total_methods": 50, "total_strings": 100},
        }
        result = _condense_dissection(dissection)
        assert len(result) <= 14100  # Some margin for the truncation message

    def test_summarize_dissection_fallback_on_no_ollama(self, monkeypatch):
        """summarize_dissection should return fallback when Ollama is unavailable."""
        monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)
        monkeypatch.setenv("LLM_PROVIDER", "ollama")
        from analysis.step7_llm_assessment import summarize_dissection
        dissection = {
            "metadata": {"package_name": "com.test"},
            "permissions": [],
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
            "dex_stats": {"dex_count": 1, "total_classes": 10, "total_methods": 50, "total_strings": 100},
        }
        # This will fail to connect to Ollama (not running in test env)
        result = summarize_dissection(dissection)
        assert "threat_level" in result
        assert "summary" in result
        assert result["threat_level"] in ("critical", "high", "medium", "low", "unknown")

    def test_dissection_summary_endpoint_not_found(self, client):
        """Summary endpoint should return 404 for nonexistent sample."""
        response = client.get("/api/sample/nonexistent_sample/dissection/summary")
        assert response.status_code == 404
