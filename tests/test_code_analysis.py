"""Unit tests for backend/code_analysis.py"""

import pytest

from backend.code_analysis import (
    _parse_method_bodies,
    _detect_techniques,
    _extract_calls,
    _assess_risk,
    _classify_string,
    _reconstruct_attack_flow,
    _SUSPICIOUS_PATTERNS,
)


# ---------------------------------------------------------------------------
# _parse_method_bodies
# ---------------------------------------------------------------------------

SIMPLE_CLASS_SOURCE = """
package com.example;

public class BaseAActivity extends Activity {
    private static final String TAG = "BaseAActivity";

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String version = getVersion();
        if (checkSignature(version)) {
            startMaliciousActivity();
        }
    }

    private String getVersion() {
        return "1.0";
    }

    private boolean checkSignature(String v) {
        String stored = getStoredSignature();
        return stored.equals(v);
    }

    private void startMaliciousActivity() {
        Intent intent = new Intent(this, HiddenService.class);
        startService(intent);
        DexClassLoader loader = new DexClassLoader("/data/data/payload.dex", ...);
        try {
            Runtime.getRuntime().exec("chmod 777 /data/data/payload.dex");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getStoredSignature() {
        return "aGVsbG8gd29ybGQ=";
    }
}
"""


def test_parse_method_bodies_count():
    methods = _parse_method_bodies(SIMPLE_CLASS_SOURCE)
    names = {m["name"] for m in methods}
    assert "onCreate" in names
    assert "getVersion" in names
    assert "checkSignature" in names
    assert "startMaliciousActivity" in names
    assert "getStoredSignature" in names


def test_parse_method_bodies_lines():
    methods = _parse_method_bodies(SIMPLE_CLASS_SOURCE)
    for m in methods:
        assert m["start_line"] >= 1
        assert m["end_line"] > m["start_line"]
        assert "body" in m


def test_parse_method_bodies_empty():
    assert _parse_method_bodies("") == []


def test_parse_method_bodies_no_methods():
    assert _parse_method_bodies("package foo;\nimport bar;") == []


# ---------------------------------------------------------------------------
# _detect_techniques
# ---------------------------------------------------------------------------


def test_detect_reflection():
    body = "    Field f = clazz.getDeclaredField(\"secret\");\n    f.setAccessible(true);"
    techniques, lines = _detect_techniques(body, 5)
    assert "reflection_abuse" in techniques
    assert len(lines) >= 1


def test_detect_service_dropping():
    body = "    Intent i = new Intent(this, Target.class);\n    startService(i);"
    techniques, lines = _detect_techniques(body, 10)
    assert "service_dropping" in techniques


def test_detect_payload_drop():
    body = "    FileOutputStream fos = new FileOutputStream(path);\n    InputStream is = getAssets().open(\"payload.apk\");"
    techniques, lines = _detect_techniques(body, 20)
    assert "payload_drop" in techniques


def test_detect_dynamic_loading():
    body = "    DexClassLoader loader = new DexClassLoader(dexPath, optDir, libPath, parent);"
    techniques, lines = _detect_techniques(body, 15)
    assert "dynamic_loading" in techniques


def test_detect_command_exec():
    body = "    Runtime.getRuntime().exec(\"chmod 777 /data/data/payload\");"
    techniques, lines = _detect_techniques(body, 30)
    assert "command_exec" in techniques


def test_detect_network():
    body = "    HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n    conn.connect();"
    techniques, lines = _detect_techniques(body, 8)
    assert "network" in techniques


def test_detect_no_patterns():
    body = "    int x = 42;\n    String y = \"hello\";\n    return x;"
    techniques, lines = _detect_techniques(body, 1)
    assert techniques == []
    assert lines == []


# ---------------------------------------------------------------------------
# _extract_calls
# ---------------------------------------------------------------------------


def test_extract_calls():
    body = "    doFirst();\n    String x = getMiddle();\n    finishLast(x);"
    calls = _extract_calls(body, 1)
    targets = {c["target"] for c in calls}
    assert "doFirst" in targets
    assert "getMiddle" in targets
    assert "finishLast" in targets


def test_extract_calls_excludes_control_names():
    body = "    if (x > 0) {\n        process(x);\n    }"
    calls = _extract_calls(body, 1)
    targets = {c["target"] for c in calls}
    assert "if" not in targets
    assert "process" in targets


def test_extract_calls_empty():
    assert _extract_calls("int x = 42;", 1) == []


# ---------------------------------------------------------------------------
# _assess_risk
# ---------------------------------------------------------------------------


def test_assess_risk_critical():
    assert _assess_risk(["reflection_abuse"]) == "CRITICAL"
    assert _assess_risk(["payload_drop"]) == "CRITICAL"
    assert _assess_risk(["command_exec"]) == "CRITICAL"


def test_assess_risk_high():
    assert _assess_risk(["network"]) == "HIGH"


def test_assess_risk_medium():
    assert _assess_risk(["crypto"]) == "MEDIUM"
    assert _assess_risk(["anti_analysis"]) == "MEDIUM"


def test_assess_risk_low():
    assert _assess_risk([]) == "LOW"


def test_assess_risk_critical_overrides():
    assert _assess_risk(["crypto", "payload_drop"]) == "CRITICAL"


# ---------------------------------------------------------------------------
# _classify_string
# ---------------------------------------------------------------------------


def test_classify_payload_filename():
    assert _classify_string("SMSApp.apk") == "payload_filename"
    assert _classify_string("payload.dex") == "payload_filename"
    assert _classify_string("update.jar") == "payload_filename"
    assert _classify_string("classes.zip") == "payload_filename"


def test_classify_c2_domain():
    assert _classify_string("https://evil.com/c2") == "c2_domain"
    assert _classify_string("http://192.168.1.1/payload") == "c2_domain"


def test_classify_ip():
    assert _classify_string("192.168.1.1") == "ip_address"
    assert _classify_string("10.0.0.1") == "ip_address"


def test_classify_file_path():
    assert _classify_string("/data/data/com.example/db") == "file_path"
    # .apk takes priority over /sdcard/ path
    assert _classify_string("/sdcard/Download/update.apk") == "payload_filename"


def test_classify_social_engineering():
    assert _classify_string("发现新版本") == "social_engineering"
    assert _classify_string("1秒闪电更新") == "social_engineering"


def test_classify_service_name():
    assert _classify_string("com.android.battery") == "service_name"
    assert _classify_string("com.example.HiddenService") == "service_name"


def test_classify_other():
    assert _classify_string("hello world") == "other"
    assert _classify_string("ABCDEF1234") == "other"


# ---------------------------------------------------------------------------
# _reconstruct_attack_flow
# ---------------------------------------------------------------------------


def test_reconstruct_attack_flow_empty():
    assert _reconstruct_attack_flow([], "") == []


def test_reconstruct_attack_flow_basic():
    methods = [
        {
            "name": "onCreate",
            "start_line": 7,
            "end_line": 14,
            "risk_level": "LOW",
            "techniques": [],
            "calls": [{"target": "getVersion", "line": 9, "action": "Calls getVersion()"}],
            "suspicious_lines": [],
        },
        {
            "name": "startMaliciousActivity",
            "start_line": 25,
            "end_line": 35,
            "risk_level": "CRITICAL",
            "techniques": ["service_dropping", "dynamic_loading", "command_exec"],
            "calls": [],
            "suspicious_lines": [],
        },
    ]
    flow = _reconstruct_attack_flow(methods, "")
    assert len(flow) >= 2
    assert flow[0]["method"] == "onCreate"
    assert any(f["risk_level"] == "CRITICAL" for f in flow)
    assert any("Launches Android services" in f["description"] for f in flow)


def test_reconstruct_attack_flow_entry_order():
    # onCreate should come before onStart, which comes before run, etc.
    methods = [
        {
            "name": "run",
            "start_line": 20, "end_line": 25,
            "risk_level": "CRITICAL", "techniques": ["payload_drop"],
            "calls": [], "suspicious_lines": [],
        },
        {
            "name": "onCreate",
            "start_line": 5, "end_line": 10,
            "risk_level": "LOW", "techniques": [],
            "calls": [], "suspicious_lines": [],
        },
    ]
    flow = _reconstruct_attack_flow(methods, "")
    assert flow[0]["method"] == "onCreate"
    assert flow[-1]["method"] == "run"


# ---------------------------------------------------------------------------
# Integration: full class analysis with real patterns
# ---------------------------------------------------------------------------


def test_full_class_analysis():
    """Test that a class with BaseAActivity-like structure produces expected analysis."""
    source = """
public class MainActivity extends Activity {
    protected void onCreate(Bundle b) {
        String sig = getSignature();
        if (check(sig)) {
            startEvil();
        }
    }

    private void startEvil() {
        Intent i = new Intent(this, Hidden.class);
        startService(i);
        DexClassLoader d = new DexClassLoader("/data/data/payload.dex", null, null, null);
        try {
            Runtime.getRuntime().exec("pm install payload.apk");
        } catch (Exception e) {}
    }

    private String getSignature() {
        return "aGVsbG8=";
    }

    private boolean check(String v) {
        return getSig().equals(v);
    }
}
"""
    methods = _parse_method_bodies(source)
    assert len(methods) >= 4

    parsed = []
    for m in methods:
        tech, lines = _detect_techniques(m["body"], m["start_line"])
        calls = _extract_calls(m["body"], m["start_line"])
        risk = _assess_risk(tech)
        parsed.append({
            "name": m["name"],
            "start_line": m["start_line"],
            "end_line": m["end_line"],
            "risk_level": risk,
            "techniques": tech,
            "calls": calls,
            "suspicious_lines": lines,
        })

    risk_map = {p["name"]: p["risk_level"] for p in parsed}
    assert risk_map["startEvil"] == "CRITICAL"
    assert "onCreate" in risk_map

    tech_map = {p["name"]: p["techniques"] for p in parsed}
    assert "service_dropping" in tech_map["startEvil"]
    assert "dynamic_loading" in tech_map["startEvil"]
    assert "command_exec" in tech_map["startEvil"]
    assert "payload_drop" not in tech_map.get("onCreate", [])

    flow = _reconstruct_attack_flow(parsed, source)
    assert len(flow) >= 2
    assert flow[0]["method"] == "onCreate"
    assert any(f["method"] == "startEvil" for f in flow)
    assert any("Launches Android services" in f["description"] for f in flow)


def test_all_patterns_have_risk_levels():
    """Every suspicious pattern must have a defined risk level."""
    for name, info in _SUSPICIOUS_PATTERNS.items():
        assert info["risk"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL"), f"{name} missing risk"
        assert "patterns" in info, f"{name} missing patterns"
        assert len(info["patterns"]) > 0, f"{name} has no patterns"
