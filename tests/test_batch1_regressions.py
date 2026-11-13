"""Regression tests for audit Batch 1 (steps 11-17 wiring, step 14 crash)."""
from analysis.step12_reflective_tracing import find_reflective_calls
from analysis.step14_network_protocol_analysis import (
    analyze_network_protocols,
    classify_endpoint,
)


def test_malformed_endpoint_is_skipped_not_fatal():
    # Format-string URL used to raise ValueError from urlparse().port and abort step 14.
    assert classify_endpoint("http://%s:%d/api") is None
    result = analyze_network_protocols(["http://%s:%d/api", "http://45.77.12.9:4444/gate.php"])
    assert isinstance(result, dict)


def test_step12_reads_apktool_output_dir_and_smali_classes_n(tmp_path):
    smali_dir = tmp_path / "smali_classes2"
    smali_dir.mkdir(parents=True)
    (smali_dir / "A.smali").write_text(
        '.class public LA;\n.method public run()V\n    const-string v0, "android.telephony.SmsManager"\n'
        '    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;\n'
        '.end method\n',
        encoding="utf-8",
    )
    result = find_reflective_calls({"apktool_output_dir": str(tmp_path)})
    assert result["total_reflective_calls"] > 0
    assert any(t["resolved_class"] == "android.telephony.SmsManager" for t in result["sensitive_targets"])


def test_c2_cap_keeps_non_c2_malicious_verdict_at_medium():
    # A1-04: the cap's own note contained "C2", forcing low/25 on a non-C2 verdict.
    from analysis.step7_llm_assessment import sanity_check

    out = sanity_check(
        {"severity": "high", "risk_score": 75, "narrative": "Spyware with SMS exfil.", "recommended_actions": []},
        {}, {"total_c2s": 0},
    )
    assert out["severity"] == "medium"
    assert out["risk_score"] == 50


def test_secrets_raise_is_not_overwritten_by_obfuscation_rule():
    # A1-05: secrets raised the verdict to high/70; the obfuscation rule then reset it to medium/30.
    from analysis.step7_llm_assessment import sanity_check

    out = sanity_check(
        {"severity": "low", "risk_score": 20, "narrative": "n", "recommended_actions": []},
        {},
        {"total_c2s": 1},
        {"obfuscation_score": 60, "indicators": {"dangerous_permissions": ["SEND_SMS"]}},
        {"hardcoded_secrets": [{"severity": "critical"}]},
    )
    assert out["severity"] == "high"
    assert out["risk_score"] >= 70


def test_tiny_dex_rule_skipped_when_obfuscation_timed_out():
    # A1-06: a timed-out step 8 has no indicators, so 0 methods must not read as a "tiny DEX".
    from analysis.step9_post_process import correct_tiny_dex

    result = correct_tiny_dex({
        "obfuscation_analysis": {"timed_out": True, "indicators": {}},
        "extraction": {"decompiled_classes": 5000},
        "llm_assessment": {"severity": "low", "risk_score": 25},
        "c2_infrastructure": [],
    })
    assert result["llm_assessment"]["severity"] == "low"
    assert result["llm_assessment"]["risk_score"] == 25
