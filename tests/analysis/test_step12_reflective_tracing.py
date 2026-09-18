import pytest
from analysis.step12_reflective_tracing import (
    find_reflective_calls,
    resolve_reflection_targets,
    scan_source_for_reflection,
    REFLECTION_PATTERNS,
    SENSITIVE_API_MAP,
)


class TestFindReflectiveCalls:
    def test_empty(self):
        result = find_reflective_calls({})
        assert result["total_reflective_calls"] == 0
        assert result["reflective_calls"] == []

    def test_with_source(self, tmp_path):
        source_dir = tmp_path / "sources"
        source_dir.mkdir()
        smali_file = source_dir / "Test.smali"
        smali_file.write_text(
            'const-string v0, "android.telephony.SmsManager"\n'
            'invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;\n'
            'move-result-object v1\n'
            'const-string v0, "sendTextMessage"\n'
            'invoke-virtual {v1, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;\n'
        )
        apk_info = {"extracted_path": str(tmp_path)}
        result = find_reflective_calls(apk_info)
        assert "reflective_calls" in result

    def test_missing_extracted_path(self):
        result = find_reflective_calls({"work_dir": ""})
        assert result["total_reflective_calls"] == 0


class TestResolveReflectionTargets:
    def test_sensitive_targets(self):
        calls = [
            {"target": "android.telephony.SmsManager", "method": "sendTextMessage"},
            {"target": "android.telephony.TelephonyManager", "method": "getDeviceId"},
        ]
        resolved = resolve_reflection_targets(calls)
        assert len(resolved) == 2
        assert resolved[0]["sensitive"] is True

    def test_empty(self):
        assert resolve_reflection_targets([]) == []


class TestScanSourceForReflection:
    def test_smali_pattern(self):
        src = 'const-string v0, "java.lang.Runtime"\ninvoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;'
        calls = scan_source_for_reflection(src, "test.smali")
        assert len(calls) > 0

    def test_no_matches(self):
        calls = scan_source_for_reflection("just normal code", "test.smali")
        assert calls == []


class TestConstants:
    def test_reflection_patterns_defined(self):
        assert len(REFLECTION_PATTERNS) > 0

    def test_sensitive_api_map_defined(self):
        assert len(SENSITIVE_API_MAP) > 0
        assert "android.telephony.SmsManager" in SENSITIVE_API_MAP
