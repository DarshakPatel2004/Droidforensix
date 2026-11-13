"""B1 audit regression tests: threat intel (backend/threat_intel.py)."""
import json
import socket

import pytest

from backend import threat_intel


def _no_network(*_args, **_kwargs):
    raise AssertionError("live network call made without DF_ALLOW_LIVE_LOOKUPS=1")


@pytest.fixture
def live_lookups_off(monkeypatch):
    monkeypatch.delenv("DF_ALLOW_LIVE_LOOKUPS", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(threat_intel, "urlopen", _no_network)


# B1-12: no request-path network use unless the operator opts in
def test_b1_live_lookups_off_by_default(live_lookups_off):
    assert threat_intel.live_lookups_enabled() is False
    result = {"c2_infrastructure": [{"domain": "c2.example.com", "ip": "8.8.8.8", "port": 443}]}
    threat_intel.build_threat_intel(result, "ab" * 32)  # must not touch DNS or ip-api


def test_b1_live_lookups_need_exact_opt_in(monkeypatch):
    monkeypatch.setenv("DF_ALLOW_LIVE_LOOKUPS", "true")
    assert threat_intel.live_lookups_enabled() is False
    monkeypatch.setenv("DF_ALLOW_LIVE_LOOKUPS", "1")
    assert threat_intel.live_lookups_enabled() is True


def test_b1_isp_lookup_is_not_sent_when_disabled(live_lookups_off, tmp_path, monkeypatch):
    monkeypatch.setattr(threat_intel, "_ISP_CACHE_PATH", tmp_path / "isp_cache.json")
    assert threat_intel._enrich_isp("8.8.8.8") == {"isp": "", "org": "", "as": ""}
    assert not (tmp_path / "isp_cache.json").exists()


# B1-13: a transient DNS failure is not persisted as 'dead'
def test_b1_transient_dns_failure_is_not_marked_dead(monkeypatch):
    monkeypatch.setenv("DF_ALLOW_LIVE_LOOKUPS", "1")

    def _timeout(*_args, **_kwargs):
        raise TimeoutError("resolver timed out")

    monkeypatch.setattr(socket, "getaddrinfo", _timeout)
    c2 = {"domain": "slow.example.com", "port": 443}
    threat_intel.build_threat_intel({"c2_infrastructure": [c2]}, "cd" * 32)
    assert "live_dns" not in c2
    assert c2.get("status") != "dead"


def test_b1_nxdomain_is_still_marked_dead(monkeypatch):
    monkeypatch.setenv("DF_ALLOW_LIVE_LOOKUPS", "1")

    def _nxdomain(*_args, **_kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _nxdomain)
    c2 = {"domain": "gone.example.com", "port": 443}
    threat_intel.build_threat_intel({"c2_infrastructure": [c2]}, "ef" * 32)
    assert c2["live_dns"]["resolves"] is False
    assert c2["status"] == "dead"


# B1-16: commonly abused hosting is not whitelisted as benign SDK infrastructure
@pytest.mark.parametrize("domain", [
    "x1.firebaseio.com", "bucket.s3.amazonaws.com", "d123.cloudfront.net",
    "raw.githubusercontent.com", "bit.ly", "tinyurl.com", "api.box.appmob.cn",
])
def test_b1_abused_hosting_is_not_benign_whitelisted(domain):
    _label, reason = threat_intel.classify_c2({"domain": domain, "port": 443, "protocol": "https"})
    assert reason != "whitelisted SDK domain"


# B1-30: a '%' is one weak signal, not a malicious verdict on its own
def test_b1_percent_domain_is_not_malicious_on_one_signal():
    label, _reason = threat_intel.classify_c2({"domain": "%s.cdn.example.com", "port": 443})
    assert label != "malicious"


# B1-30: IPv6 addresses are valid and classified
def test_b1_ipv6_is_valid_and_classified():
    assert threat_intel._is_valid_ip("2001:db8::1") is True
    assert threat_intel._classify_ip("2001:4860:4860::8888") == "public"
    assert threat_intel._is_valid_ip("not-an-ip") is False


# B1-26: STIX indicators carry only format-checked values, UUID ids and spec_version
def test_b1_stix_drops_unsafe_domain_and_uses_uuid_ids():
    result = {"c2_infrastructure": [
        {"domain": "evil'] OR [x:y = 'z", "c2_id": "c2_1"},
        {"domain": "good.example.com", "c2_id": "c2_2"},
    ]}
    bundle = threat_intel.to_stix(result, "ab" * 32)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert [o["name"] for o in indicators] == ["good.example.com"]
    assert indicators[0]["spec_version"] == "2.1"
    assert indicators[0]["id"].startswith("indicator--")
    assert len(indicators[0]["id"].split("--", 1)[1]) == 36
    assert bundle["id"].startswith("bundle--")


# B1-26: YARA strings and metadata cannot break out of their quotes or split a line
def test_b1_yara_escapes_newlines_and_quotes():
    result = {
        "metadata": {"sha256": "ab" * 32, "package_name": 'com.ev"il'},
        "c2_infrastructure": [{
            "domain": "evil.example.com",
            "raw_url": "http://evil.example.com/a\nb\"c",
            "classification": "malicious",
        }],
    }
    rule = threat_intel.to_yara(result, "ab" * 32)
    string_lines = [line for line in rule.splitlines() if line.lstrip().startswith("$s")]
    assert string_lines, rule
    assert all('\\n' in line or '\n' not in line for line in string_lines)
    assert 'com.ev\\"il' in rule


# B1-14: JSON writes go through a unique temp file and leave no temp behind
def test_b1_atomic_write_leaves_no_temp_files(tmp_path):
    folder = tmp_path / "sample"
    folder.mkdir()
    target = folder / "pipeline_result.json"
    threat_intel._atomic_write_json(target, {"a": 1})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}
    assert sorted(p.name for p in folder.iterdir()) == ["pipeline_result.json"]


def test_b1_save_isp_cache_uses_configured_path(tmp_path, monkeypatch):
    monkeypatch.setattr(threat_intel, "_ISP_CACHE_PATH", tmp_path / "isp_cache.json")
    threat_intel._save_isp_cache({"198.51.100.1": {"isp": "x", "org": "", "as": ""}})
    assert threat_intel._load_isp_cache() == {"198.51.100.1": {"isp": "x", "org": "", "as": ""}}
