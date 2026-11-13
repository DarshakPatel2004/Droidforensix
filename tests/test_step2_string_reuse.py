import pytest

from analysis.step2_string_enumeration import enumerate_strings


@pytest.fixture
def extraction(tmp_path):
    return {
        "sample_id": "a" * 64,
        "apk_path": str(tmp_path / "sample.apk"),
        "apktool_output_dir": str(tmp_path / "apktool"),
        "native_strings": [],
        "dex_strings": ["https://evil.example/panel", "192.168.1.1:8080", "abc"],
    }


def test_reuses_step1_dex_strings_without_reparsing(extraction, monkeypatch):
    def _boom(apk_path):
        raise AssertionError("must not re-parse the APK when Step 1 strings exist")

    monkeypatch.setattr("analysis.step2_string_enumeration.extract_androguard_strings", _boom)
    result = enumerate_strings(extraction)
    values = {s["value"] for s in result["categories"]["string_literals"]}
    assert "https://evil.example/panel" in values
    assert "192.168.1.1:8080" in values  # IP:port kept for step 5 (audit A1-01)
    assert "abc" not in values  # short literal still dropped


def test_falls_back_to_androguard_when_step1_empty(extraction, monkeypatch):
    extraction["dex_strings"] = []
    monkeypatch.setattr(
        "analysis.step2_string_enumeration.extract_androguard_strings",
        lambda apk_path: [{"category": "string_literal", "value": "https://c2.example/", "entropy": 0.5, "source": "dex"}],
    )
    result = enumerate_strings(extraction)
    values = {s["value"] for s in result["categories"]["string_literals"]}
    assert "https://c2.example/" in values