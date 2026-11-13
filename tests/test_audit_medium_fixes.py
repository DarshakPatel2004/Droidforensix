"""Regression tests for medium/low audit findings fixed in the final pass."""
from analysis.hardcoded_secrets import _is_placeholder
from analysis.ip_validation import is_version_number


def test_placeholder_short_word_is_whole_token():  # L7
    assert not _is_placeholder("AKIAIOSFODNNTEST7EXA")
    assert not _is_placeholder("latest")
    assert _is_placeholder("test")


def test_version_check_is_anchored_to_the_ip():  # M4
    assert is_version_number("1.2.3.4", "app v1.2.3.4 build")
    assert not is_version_number(
        "45.33.32.156", "app v1.0.0.1 socket connect 45.33.32.156:4444 backdoor")


def test_xor_decodes_high_bytes_like_step3():  # A1-07
    from analysis.step4_decoding import decode_xor

    url = "https://evil.example/gate"
    encoded = "".join(chr(ord(c) ^ 0xAA) for c in url)
    assert decode_xor(encoded, 0xAA) == url.encode("latin-1")


def test_plain_text_is_not_xor_brute_forced():  # A1-11
    from analysis.step3_encoding_detection import xor_brute_force

    assert xor_brute_force(b"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0") == []


def test_c2_chain_step_key_matches_step6():  # A1-22
    from analysis.step9_post_process import _chains_have_c2

    assert _chains_have_c2([{"steps": [{"type": "c2_infrastructure", "artifact": "evil.com"}]}])


def test_secret_value_is_redacted_before_llm():  # A1-18
    from analysis.step7_llm_assessment import _redact_secret

    raw = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA"
    out = _redact_secret(raw)
    assert raw not in out and "MIIEowIBAAKCAQEA" not in out
    assert out.startswith("----***")


def test_abuse_tld_bare_domains_are_not_code_references():  # A1-12
    from analysis.step5_c2_extraction import _is_code_reference

    for domain in ("panel.su", "evil.tk", "api.panel.su", "xx.pw", "bot.ir"):
        assert not _is_code_reference(domain), domain
    assert _is_code_reference("builder.name")  # pseudo-TLD still filtered


def test_apktool_yml_supplies_version_and_sdk(tmp_path):  # A1-08
    from analysis.step1_apk_extraction import extract_manifest_info

    (tmp_path / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (tmp_path / "apktool.yml").write_text(
        "versionInfo:\n  versionCode: '42'\n  versionName: 1.2.3\n"
        "sdkInfo:\n  minSdkVersion: '21'\n  targetSdkVersion: '33'\n",
        encoding="utf-8",
    )
    info = extract_manifest_info(str(tmp_path))
    assert info["version_code"] == 42
    assert info["version_name"] == "1.2.3"
    assert info["min_sdk_version"] == 21
    assert info["target_sdk_version"] == 33


def test_surrogates_stripped_from_keys_too():  # B2-08
    from backend.transformers import _strip_surrogates

    cleaned = _strip_surrogates({"bad\ud800key": {"v\ud800": 1}})
    assert all("\ud800" not in k for k in cleaned)
    assert all("\ud800" not in k for k in next(iter(cleaned.values())))


def test_elf_own_header_is_not_an_embedded_elf():  # B2-05
    from backend.elf_analyzer import ELFBreaker

    # Minimal ELF magic only: the own header must not be reported as an embedded ELF.
    breaker = ELFBreaker("lib.so", b"\x7fELF" + b"\x00" * 60)
    assert not any("Embedded ELF" in ind for ind in breaker._detect_packing().get("indicators", []))



def test_apk_cache_is_bounded(tmp_path, monkeypatch):  # B2-09
    from backend import dissection

    apk_file = tmp_path / "a.apk"
    apk_file.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(dissection, "APK", lambda path: object())
    cache = dissection.SampleAPKCache()
    for i in range(dissection.SampleAPKCache.MAX_ENTRIES + 3):
        cache.get_or_parse(f"id{i}", str(apk_file))
    assert len(cache._cache) == dissection.SampleAPKCache.MAX_ENTRIES
