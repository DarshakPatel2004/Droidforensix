"""B1 audit regression tests: family attribution (backend/family_id.py)."""
import json
import sys
import types
import zipfile

import pytest

from backend import family_id
from backend.family_id import (
    _extract_native_symbols,
    _kb_passes_strict_gate,
    _llm_family,
    _match_family_signatures,
    _string_pattern_matches,
    cert_issuer_boost,
    identify_family,
)

PERMS_SMS = [
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
]


def _result(**overrides):
    base = {
        "metadata": {"sha256": "ab" * 32, "package_name": "com.example.app"},
        "certificate_analysis": {},
        "strings": {"string_literals": []},
        "c2_infrastructure": [],
        "extraction": {"decompiled_classes": 200, "native_libs_found": []},
        "permissions": [],
    }
    base.update(overrides)
    return base


def _fake_openrouter(monkeypatch, content):
    """Route the OpenRouter branch of _llm_family to a canned model reply."""

    class _Completions:
        def create(self, **_kwargs):
            message = types.SimpleNamespace(content=content)
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=message)])

    class _Client:
        def __init__(self, **_kwargs):
            self.chat = types.SimpleNamespace(completions=_Completions())

    fake_openai = types.ModuleType("openai")
    fake_openai.OpenAI = _Client
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-not-real")
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")


# B1-10: a non-object JSON reply must not raise
@pytest.mark.parametrize("content", ['["DroidKungFu"]', '"DroidKungFu"', "42"])
def test_b1_non_dict_llm_reply_is_discarded(monkeypatch, content):
    _fake_openrouter(monkeypatch, content)
    assert _llm_family(_result()) is None


# B1-02: a free-generated family name is discarded; a known one is canonicalised
def test_b1_llm_invented_family_is_rejected(monkeypatch):
    _fake_openrouter(monkeypatch, '{"family": "TotallyMadeUpFamily", "confidence": 0.99, "reasoning": "x"}')
    assert _llm_family(_result()) is None


def test_b1_llm_known_family_is_canonicalised(monkeypatch):
    _fake_openrouter(monkeypatch, '{"family": "droidkungfu", "confidence": 0.7, "reasoning": "x"}')
    verdict = _llm_family(_result())
    assert verdict is not None
    assert verdict["family"] == "DroidKungFu"


def test_b1_llm_unknown_family_passes_through(monkeypatch):
    _fake_openrouter(monkeypatch, '{"family": "unknown", "confidence": 0.1, "reasoning": "benign"}')
    assert _llm_family(_result())["family"] == "unknown"


def test_b1_prompt_wraps_apk_evidence_as_untrusted(monkeypatch):
    seen = {}

    class _Completions:
        def create(self, **kwargs):
            seen.update(kwargs)
            message = types.SimpleNamespace(content='{"family": "unknown", "confidence": 0.0}')
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=message)])

    class _Client:
        def __init__(self, **_kwargs):
            self.chat = types.SimpleNamespace(completions=_Completions())

    fake_openai = types.ModuleType("openai")
    fake_openai.OpenAI = _Client
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-not-real")
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    _llm_family(_result())
    user_msg = seen["messages"][1]["content"]
    assert "<untrusted_apk_data>" in user_msg and "</untrusted_apk_data>" in user_msg


# B1-03: the strict KB gate rejects weak hits, and the fallback applies it too
def test_b1_weak_kb_hit_fails_strict_gate():
    weak = {
        "confidence": 0.6,
        "candidates": [{"kb_score": 0.4, "reasoning": "a;b"}],
    }
    assert _kb_passes_strict_gate(weak) is False


def test_b1_strong_kb_hit_passes_strict_gate():
    strong = {"confidence": 0.9, "candidates": [{"kb_score": 0.6, "reasoning": "a;b"}]}
    assert _kb_passes_strict_gate(strong) is True


# B1-05: generic substrings must not name a family
def test_b1_flurry_analytics_is_not_flubot():
    result = _result(
        c2_infrastructure=[{"domain": "data.flurry.com", "protocol": "https"}],
        manifest={"uses_permissions": PERMS_SMS},
    )
    match = _match_family_signatures(result)
    assert match is None or match["family"] != "FluBot"


def test_b1_green_tea_string_is_not_teabot():
    result = _result(strings={"string_literals": [{"value": "green tea"}]})
    match = _match_family_signatures(result)
    assert match is None or match["family"] != "TeaBot"


def test_b1_protobuf_message_is_not_icici():
    result = _result(strings={"string_literals": [{"value": "unsupported descriptor type"}]})
    match = _match_family_signatures(result)
    assert match is None or match["family"] != "ICICI"


# B1-07: the substring prefilter must not change the match result
@pytest.mark.parametrize(
    "pattern,blob,expected",
    [
        ("tea", "steady state create config", False),
        ("tea", "other tea value", True),
        ("kmin", "com.kmin.receiver", True),
        ("kmin", "kminx", False),
        ("unsupported descriptor type", "a unsupported descriptor type b", True),
        ("unsupported descriptor type", "unsupported descriptor", False),
    ],
)
def test_b1_string_match_semantics_unchanged(pattern, blob, expected):
    assert _string_pattern_matches(pattern, blob) is expected


# B1-09: the KB fallback reads permissions from the manifest, as the matcher does
def test_b1_kb_features_read_manifest_permissions():
    result = {"manifest": {"uses_permissions": ["android.permission.SET_ALARM"]}}
    features = family_id._kb_extract_features(result, sample_id=None)
    assert "SET_ALARM" in features["permissions"]


# B1-18: a zip-bomb .so is skipped without being inflated whole
def test_b1_oversized_so_is_skipped(tmp_path):
    apk = tmp_path / "bomb.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lib/arm64-v8a/libbig.so", b"\x00" * (11 * 1024 * 1024))
    symbols = _extract_native_symbols(str(apk))
    assert "libbig.so" not in symbols


def test_b1_missing_apk_is_logged(tmp_path, caplog):
    with caplog.at_level("WARNING", logger=family_id.logger.name):
        assert _extract_native_symbols(str(tmp_path / "gone.apk")) == {}
    assert any("JNI symbol matching skipped" in r.getMessage() for r in caplog.records)


# B1-20: a non-matching issuer gets no boost from an unrelated profile
def test_b1_unrelated_issuer_gets_no_cert_boost():
    profiles = {"FakeDoc": {"top_issuer": "CN=Real", "issuer_patterns": [], "top_issuer_coverage": 0.9}}
    assert cert_issuer_boost("CN=Other", "FakeDoc", profiles) == 0.0


def test_b1_exact_issuer_still_boosted():
    profiles = {"FakeDoc": {"top_issuer": "CN=Real", "issuer_patterns": [], "top_issuer_coverage": 0.9}}
    assert cert_issuer_boost("CN=Real", "FakeDoc", profiles) == 0.15


# B1-21: the ground-truth override is opt-in
def test_b1_ground_truth_off_by_default(tmp_path, monkeypatch):
    sha = "cd" * 32
    gt = tmp_path / "ground_truth_test_set.json"
    gt.write_text(json.dumps([{"sha256": sha, "family": "Opfake"}]), encoding="utf-8")
    monkeypatch.setattr(family_id, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(family_id, "GROUND_TRUTH_FILES", ["ground_truth_test_set.json"])
    monkeypatch.delenv("DF_FAMILY_GROUND_TRUTH", raising=False)
    family_id._ground_truth_map.cache_clear()
    try:
        assert family_id._ground_truth_map() == {}
        monkeypatch.setenv("DF_FAMILY_GROUND_TRUTH", "1")
        family_id._ground_truth_map.cache_clear()
        assert family_id._ground_truth_map() == {sha: "Opfake"}
    finally:
        family_id._ground_truth_map.cache_clear()


# B1-24: decompiled_classes: null must not raise
def test_b1_null_class_count_does_not_raise():
    result = _result(extraction={"decompiled_classes": None, "native_libs_found": []})
    _match_family_signatures(result)


# B1-08: a missing knowledge base is reported, not silently emptied
def test_b1_missing_kb_file_is_logged(tmp_path, caplog):
    with caplog.at_level("WARNING", logger=family_id.logger.name):
        assert family_id._kb_read_json(tmp_path / "missing.json", "Family knowledge base") == {}
    assert any("unavailable" in r.getMessage() for r in caplog.records)


# B1-04 (fallback path): an LLM-less identify call still returns a verdict and writes nothing
def test_b1_identify_without_llm_does_not_cache_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(family_id.settings, "WORK_DIR", tmp_path)
    sha = "ef" * 32
    outcome = identify_family(sha, _result(metadata={"sha256": sha}), use_llm=False, use_cache=True)
    assert outcome["method"] == "none"
    assert not (tmp_path / sha / "family.json").exists()

