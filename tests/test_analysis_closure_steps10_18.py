"""Integration: steps 10-18 on a synthetic APK-shaped fixture, with the same argument shapes pipeline.py passes (A2-M8)."""

import random
import zipfile

import pytest

from analysis.step10_binary_packing import detect_binary_packing
from analysis.step11_string_clustering import cluster_high_entropy_strings
from analysis.step12_reflective_tracing import find_reflective_calls
from analysis.step13_native_elf_analysis import analyze_native_libraries_from_apk
from analysis.step14_network_protocol_analysis import analyze_network_protocols
from analysis.step15_reflective_permission_correlation import (
    correlate_reflective_permission_usage,
)
from analysis.step16_certificate_analysis import analyze_certificate
from analysis.step17_family_clustering import cluster_family
from analysis.step18_threat_synthesis import synthesize_threat_profile


@pytest.fixture
def fixture_apk(tmp_path):
    """Zip with a large random classes.dex, plus an apktool-style tree with reflection in smali."""
    rng = random.Random(7)
    dex = bytes(rng.getrandbits(8) for _ in range(400_000))
    apk = tmp_path / "synthetic.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", dex)
        zf.writestr("AndroidManifest.xml", "<manifest/>")
    apktool_dir = tmp_path / "apktool"
    smali = apktool_dir / "smali" / "com" / "example"
    smali.mkdir(parents=True)
    (smali / "Loader.smali").write_text(
        ".class public Lcom/example/Loader;\n"
        ".method public run()V\n"
        "    const-string v0, \"dalvik.system.DexClassLoader\"\n"
        "    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;\n"
        "    const-string v1, \"http://45.77.12.9:7771/gate.php\"\n"
        "    return-void\n"
        ".end method\n",
        encoding="utf-8",
    )
    return apk, apktool_dir


def test_steps_10_to_18_run_on_pipeline_shaped_inputs(fixture_apk):
    apk, apktool_dir = fixture_apk
    extraction = {"sample_id": "x", "package_name": "com.example", "apktool_output_dir": str(apktool_dir)}

    packing = detect_binary_packing({"apk_path": str(apk)})
    assert packing["obfuscation_score"] >= 30  # oversized classes.dex must score (H6 regression)

    strings = ["http://45.77.12.9:7771/gate.php", "plain text value"]
    assert "total_clusters" in cluster_high_entropy_strings(strings)

    reflective = find_reflective_calls(extraction)
    assert reflective["total_reflective_calls"] >= 1  # H2 regression: apktool_output_dir is read

    native = analyze_native_libraries_from_apk(str(apk), str(apktool_dir))
    assert isinstance(native, dict)

    network = analyze_network_protocols(strings)
    assert network is not None

    perms = correlate_reflective_permission_usage([], reflective.get("sensitive_targets", []))
    assert isinstance(perms, dict)

    cert = analyze_certificate(str(apk))
    assert cert["certificate_found"] is False  # unsigned fixture: no cert blob, no error

    family = cluster_family("x", extraction, {})
    assert isinstance(family, dict)

    synthesis = synthesize_threat_profile({
        "packing": packing,
        "reflective_tracing": reflective,
        "permissions": perms,
        "network": network,
        "strings": {},
        "native_elf": native,
        "certificate": cert,
        "family_clustering": family,
    })
    assert "zero_day_risk_score" in synthesis
