import json
import pytest
from analysis.step16_certificate_analysis import (
    analyze_certificate,
    parse_certificate_from_apk,
    check_known_bad_certificate,
    fingerprint_via_androguard,
    load_known_bad_certs,
    get_known_bad_certs,
    add_known_bad_cert,
    DEFAULT_CERT_DB_PATH,
    _cert_cache,
)


class TestAnalyzeCertificate:
    def test_no_apk(self):
        result = analyze_certificate("")
        assert result["certificate_found"] is False

    def test_nonexistent_apk(self):
        result = analyze_certificate("/nonexistent/path.apk")
        assert result["certificate_found"] is False
        assert "error" in result


class TestCheckKnownBadCertificate:
    def setup_method(self):
        load_known_bad_certs(DEFAULT_CERT_DB_PATH)

    def test_not_bad(self):
        result = check_known_bad_certificate(
            "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33"
        )
        assert isinstance(result, dict)
        assert "known_bad" in result

    def test_empty(self):
        result = check_known_bad_certificate("")
        assert result["known_bad"] is False

    def test_short(self):
        result = check_known_bad_certificate("ab:cd")
        assert result["known_bad"] is False

    def test_known_bad(self):
        load_known_bad_certs(DEFAULT_CERT_DB_PATH)
        result = check_known_bad_certificate(
            "3c:7a:1b:4e:8f:2d:9a:6b:5c:0e:1f:8a:3d:7b:4c:2e:9f:1a:6d:8b:0c:3e:7a:1b:4e:8f:2d:9a:6b:5c:0e:1f"
        )
        assert result["known_bad"] is True
        assert result["family"] == "judy_malware"


class TestParseCertificateFromApk:
    def test_no_apk(self):
        result = parse_certificate_from_apk("")
        assert result is None

    def test_nonexistent(self):
        result = parse_certificate_from_apk("/nonexistent.apk")
        assert result is None


class TestFingerprintFallback:
    def test_garbage_zip_returns_none(self, tmp_path):
        import zipfile

        apk = tmp_path / "fake.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", b"not a cert")
        assert fingerprint_via_androguard(str(apk)) is None

    def test_smssend_campaign_cert_flagged(self):
        load_known_bad_certs(DEFAULT_CERT_DB_PATH)
        db = json.load(open(str(DEFAULT_CERT_DB_PATH), encoding="utf-8"))
        fps = [c["sha256_fingerprint"] for c in db["certificates"]
               if c.get("source") == "campaign-attribution"]
        assert fps, "campaign-attributed cert missing from DB"
        result = check_known_bad_certificate(fps[0])
        assert result["known_bad"] is True
        assert result["family"] == "SmsSend"


class TestLoadKnownBadCerts:
    def setup_method(self):
        global _cert_cache
        _cert_cache = None

    def test_load_missing_file(self, tmp_path):
        missing = tmp_path / "nonexistent.json"
        result = load_known_bad_certs(str(missing))
        assert result == {}

    def test_load_empty_file(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("{}")
        result = load_known_bad_certs(str(empty))
        assert result == {}

    def test_load_empty_certificates(self, tmp_path):
        f = tmp_path / "no_certs.json"
        f.write_text(json.dumps({"certificates": []}))
        result = load_known_bad_certs(str(f))
        assert result == {}

    def test_load_with_certs(self, tmp_path):
        f = tmp_path / "certs.json"
        data = {
            "certificates": [
                {"sha256_fingerprint": "aa:bb:cc:dd", "family": "test_family"},
                {"sha256_fingerprint": "11:22:33:44", "family": "other_family"},
            ]
        }
        f.write_text(json.dumps(data))
        result = load_known_bad_certs(str(f))
        assert result == {"aa:bb:cc:dd": "test_family", "11:22:33:44": "other_family"}

    def test_load_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        result = load_known_bad_certs(str(f))
        assert result == {}


class TestGetKnownBadCerts:
    def setup_method(self):
        global _cert_cache
        _cert_cache = None

    def test_get_cached(self, tmp_path):
        f = tmp_path / "test_get.json"
        data = {"certificates": [{"sha256_fingerprint": "ab:cd:ef", "family": "cached_test"}]}
        f.write_text(json.dumps(data))
        load_known_bad_certs(str(f))
        result = get_known_bad_certs()
        assert result == {"ab:cd:ef": "cached_test"}

    def test_get_auto_loads(self, tmp_path):
        global _cert_cache
        _cert_cache = None
        orig_path = DEFAULT_CERT_DB_PATH
        f = tmp_path / "auto.json"
        data = {"certificates": [{"sha256_fingerprint": "11:22:33:44", "family": "auto_test"}]}
        f.write_text(json.dumps(data))
        load_known_bad_certs(str(f))
        result = get_known_bad_certs()
        assert "11:22:33:44" in result


class TestAddKnownBadCert:
    def setup_method(self):
        global _cert_cache
        _cert_cache = None

    def test_add_to_new_file(self, tmp_path):
        f = tmp_path / "add_test.json"
        add_known_bad_cert("ff:ee:dd:cc", "new_malware", source="test", path=str(f))
        assert f.exists()
        data = json.loads(f.read_text())
        assert len(data["certificates"]) == 1
        assert data["certificates"][0]["sha256_fingerprint"] == "ff:ee:dd:cc"
        assert data["certificates"][0]["family"] == "new_malware"
        assert data["certificates"][0]["source"] == "test"

    def test_add_to_existing(self, tmp_path):
        f = tmp_path / "add_existing.json"
        initial = {
            "certificates": [
                {"sha256_fingerprint": "aa:bb:cc", "family": "existing", "source": "old", "notes": ""},
            ]
        }
        f.write_text(json.dumps(initial))
        add_known_bad_cert("dd:ee:ff", "new_one", source="manual", path=str(f))
        data = json.loads(f.read_text())
        assert len(data["certificates"]) == 2

    def test_add_duplicate_replaces(self, tmp_path):
        f = tmp_path / "add_dup.json"
        initial = {
            "certificates": [
                {"sha256_fingerprint": "aa:bb:cc", "family": "old_family", "source": "old", "notes": ""},
            ]
        }
        f.write_text(json.dumps(initial))
        add_known_bad_cert("aa:bb:cc", "new_family", source="updated", path=str(f))
        data = json.loads(f.read_text())
        assert len(data["certificates"]) == 1
        assert data["certificates"][0]["family"] == "new_family"

    def test_add_updates_cache(self, tmp_path):
        f = tmp_path / "add_cache.json"
        f.write_text(json.dumps({"certificates": []}))
        load_known_bad_certs(str(f))
        add_known_bad_cert("11:22:33", "cache_test", path=str(f))
        cached = get_known_bad_certs()
        assert "11:22:33" in cached
        assert cached["11:22:33"] == "cache_test"
