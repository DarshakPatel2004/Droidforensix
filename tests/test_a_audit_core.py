"""Regression tests for the 2026-11-11 analysis audit (A1 core, A2 modules).

Each test names the finding it pins down.
"""
import zipfile

import pytest


def test_a1_12_uppercase_host_is_a_real_domain():
    from analysis.step5_c2_extraction import _is_code_reference

    assert not _is_code_reference("EvilHost.com")
    assert not _is_code_reference("Panel.SU")  # TLD comparison is case-insensitive
    assert _is_code_reference("builder.name")  # pseudo-TLD still filtered


def test_a1_12_cc_stays_in_junk_list():
    from analysis.step5_c2_extraction import _is_likely_junk_domain

    assert _is_likely_junk_domain("osbridge.cc")


def test_a1_20_analyze_assets_does_not_decompress_res(tmp_path):
    from analysis.step8_obfuscation_analysis import analyze_assets

    apk = tmp_path / "t.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("res/raw/blob.bin", b"\x00" * 1000)
        zf.writestr("assets/a.bin", b"hello")
    result = analyze_assets(apk)
    names = [a["file"] for a in result["asset_files"]]
    assert names == ["assets/a.bin"]


def test_a1_20_payload_blob_is_capped_and_bare_dex_passthrough(tmp_path, monkeypatch):
    from analysis import step0_master_key as s0

    monkeypatch.setattr(s0, "_PAYLOAD_BLOB_CAP", 100)
    kit = tmp_path / "kit.zip"
    with zipfile.ZipFile(kit, "w") as zf:
        zf.writestr("installer.dex", b"A" * 500)
    assert len(s0._payload_blob(kit)) == 100

    bare = tmp_path / "bare.dex"
    bare.write_bytes(b"dex\n" + b"B" * 10)
    assert s0._payload_blob(bare) == bare.read_bytes()


def test_a1_36_smali_fallback_reads_multidex_roots(tmp_path):
    from analysis.step2_string_enumeration import extract_smali_strings

    (tmp_path / "smali").mkdir()
    (tmp_path / "smali" / "A.smali").write_text(
        'const-string v0, "http://first-dex.example.net/x"\n', encoding="utf-8")
    (tmp_path / "smali_classes2").mkdir()
    (tmp_path / "smali_classes2" / "B.smali").write_text(
        'const-string v0, "http://second-dex.example.net/y"\n', encoding="utf-8")
    values = {r["value"] for r in extract_smali_strings(str(tmp_path))}
    assert "http://second-dex.example.net/y" in values


def test_a1_47_empty_ground_truth_is_never_correct():
    from analysis.labels import is_correct

    assert is_correct("", "") is False
    assert is_correct("", "Joker") is False


def test_a2_m4_version_string_only_discounts_its_own_address():
    from analysis.ip_validation import is_version_number

    ctx = "app v1.0.0.1 socket connect 45.33.32.156:4444 backdoor"
    assert not is_version_number("45.33.32.156", ctx)
    assert is_version_number("1.0.0.1", "app v1.0.0.1 build")


def test_a2_m5_suspicious_keywords_are_whole_words():
    from analysis.ip_validation import behavioral_context_score

    assert behavioral_context_score("1.2.3.4", "configuration generated 1.2.3.4") == 0


def test_a2_m10_last_member_survives_repair(tmp_path):
    from analysis.step19_container_repair import repair_container

    src = tmp_path / "in.zip"
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "alpha" * 20)
        zf.writestr("b.txt", "bravo" * 20)
    out = tmp_path / "out.zip"
    result = repair_container(str(src), str(out))
    assert result is not None
    with zipfile.ZipFile(out) as zf:
        assert sorted(zf.namelist()) == ["a.txt", "b.txt"]


@pytest.mark.parametrize("payload", [b"\x00" * 16])
def test_a2_h6_dex_entropy_indicator_fires_on_dex_keys(payload):
    from analysis.step10_binary_packing import analyze_dex_sections

    out = analyze_dex_sections({"classes.dex": {"size": 600_000, "entropy": 7.9}})
    types = {i["type"] for i in out["scored_indicators"]}
    assert "high_entropy_code" in types
