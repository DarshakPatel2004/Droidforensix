"""Corpus acceptance for the master key breaker (opt-in, slow).

Run with:  $env:DFX_BREAKER_ACCEPTANCE=1; .venv\\Scripts\\python.exe -m pytest tests/test_breaker_corpus.py -v
"""
import hashlib
import os
from pathlib import Path

import pytest

from analysis.payload_evidence import collect_payload_evidence
from packers.breaker.engine import break_apk

ROOT = Path(__file__).resolve().parent.parent
PENDRIVE = ROOT / "PENDRIVE DATA" / "PENDRIVE DATA"
OUT = ROOT / "analysis" / "master_key_breaker"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(os.environ.get("DFX_BREAKER_ACCEPTANCE") != "1",
                       reason="set DFX_BREAKER_ACCEPTANCE=1 to run corpus acceptance"),
]

BOOTSTRAP_DEX = "35b4852821b26aa1ce71eddf43e24e5b094b754705071cfd61b534ed2e017110"

# (apk, member, recovered-payload sha256; None = not pinned)
MYG0N_CASES = [
    (ROOT / "RTO.apk", "assets/myg0N",
     "d414cb8fe9fa87441200412f8608210cb2ff87ed161b4976d66e586453b614d1"),
    (PENDRIVE / "apk fraud" / "21" / "RTO E CHALLAN (1).apk", "assets/UZrF0u",
     "51040a408a581db79c6d5909c4c3c1d764427fff9ac1324a665b69cd76f1fb31"),
    (PENDRIVE / "new apk files" / "PNB One.apk", "assets/ZoCv0N", None),
    (PENDRIVE / "new apk files" / "Repair service.apk", "assets/LAZx0b", None),
]

# (apk, member, payload sha256, dex member, dex size, dex sha256)
LUMOLIGHT_CASES = [
    (PENDRIVE / "apk fraud" / "21" / "PNB ONE ACTIVATION.apk",
     "assets/wyvhtvmqlcbfmi9w/bhtn0kbg",
     "66d0aff7053b27aa7a0347dca75335d9bd939045c66a6bb7b3a64ead4016fcfb",
     "classes.dex", 622896,
     "1049fdaa00583352c09623a86434dd9fd3a8f44dde083a116a1979e8cf934af7"),
    (PENDRIVE / "apk fraud" / "Central bank india" / "M PARIWAHAN CHALAN (12).apk",
     "assets/cmg5ro16lp7g1fvt/kesaj3fo",
     "b38e620cba177e22fc67d857f5633e0bbafc6acbc952e6a5a789c25834be6489",
     "classes.dex", 633128,
     "65efa65709c5a06a391e6937396a690457ecdc0bacdc65cdab7c11a759977d01"),
]

MEDIAPLAYER2 = (
    PENDRIVE / "apk fraud" / "Black mail" / "MediaPlayer2.apk",
    "assets/3664888858717845462",
    "5b5697c9a04c3ff1fab618abaf1002af68244ac7b39dc6ff17fdaa41b0139b5e",
    "classes.dex", 5684096,
    "6babf08ae30f4ac54bf7f6cc46ed44634cc495316a80f43bbec3ef95de98e9a3",
)


def _artifact(hit, name: str) -> dict:
    return next(a for a in hit.artifacts if a["file"] == name)


@pytest.mark.parametrize("apk,member,payload_sha", MYG0N_CASES)
def test_myg0n_family_recovers_from_scratch(apk, member, payload_sha):
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    result = break_apk(apk, OUT / apk.stem)
    hit = next((h for h in result.hits if h.member == member), None)
    assert hit is not None, [h.member for h in result.hits]
    assert hit.provenance == ["prior:myg0n"]
    assert hit.validation == "zip-strict"
    if payload_sha:
        assert hit.payload_sha256 == payload_sha
    assert _artifact(hit, "bootstrap.dex")["sha256"] == BOOTSTRAP_DEX


@pytest.mark.parametrize("apk,member,payload_sha,dex_name,dex_size,dex_sha", LUMOLIGHT_CASES)
def test_lumolight_family_recovers_from_scratch(apk, member, payload_sha, dex_name, dex_size, dex_sha):
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    result = break_apk(apk, OUT / apk.stem)
    hit = next((h for h in result.hits if h.member == member), None)
    assert hit is not None, [h.member for h in result.hits]
    assert hit.provenance == ["prior:gen2-zero-iv"]
    assert hit.payload_sha256 == payload_sha
    artifact = _artifact(hit, dex_name)
    assert artifact["sha256"] == dex_sha and artifact["size"] == dex_size


def test_mediaplayer2_lcg_recovers_autonomously():
    apk, member, payload_sha, dex_name, dex_size, dex_sha = MEDIAPLAYER2
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    result = break_apk(apk, OUT / "MediaPlayer2")
    hit = next((h for h in result.hits if h.member == member), None)
    assert hit is not None, [h.member for h in result.hits]
    assert hit.scheme["cipher"] == "java-lcg"
    assert hit.seed == "3664888858717910997"
    assert hit.provenance == ["numeric:+0xffff"]
    assert hit.validation == "zip-strict"
    assert hit.payload_sha256 == payload_sha
    artifact = _artifact(hit, dex_name)
    assert artifact["sha256"] == dex_sha and artifact["size"] == dex_size


def test_ijiami_dead_ends_produce_no_hits():
    samples = sorted(PENDRIVE.rglob("Calculator*.apk"))
    if not samples:
        pytest.skip("no Ijiami Calculator* samples on this machine")
    for apk in samples:
        result = break_apk(apk, OUT / ("ijiami_" + apk.stem))
        assert result.hits == [], [h.member for h in result.hits]
        assert result.attempts_total > 0


def _dead_end_samples():
    """Spec 11.3's named dead ends: loader samples whose payloads are not static ciphertext."""
    candidates = [
        PENDRIVE / "apk fraud" / "21" / "Tubi-inin.apk",
        PENDRIVE / "new apk files" / "Tubi-inin.apk",
        PENDRIVE / "new apk files" / "Google Video.apk",
    ]
    return [path for path in candidates if path.exists()]


@pytest.mark.parametrize("apk", _dead_end_samples(),
                         ids=lambda path: "%s/%s" % (path.parent.name, path.stem))
@pytest.mark.skipif(not _dead_end_samples(), reason="no dead-end loader samples on this machine")
def test_named_dead_ends_produce_no_hits(apk):
    result = break_apk(apk, OUT / ("deadend_" + apk.parent.name + "_" + apk.stem))
    assert result.hits == [], [h.member for h in result.hits]
    # An encrypted member must have been probed; a loader with nothing encrypted is a skip.
    if result.ciphertext_members:
        assert result.attempts_total > 0


def test_second_chance_cap_decides_mediaplayer2(tmp_path, monkeypatch):
    """The pipeline default (20k) sits deliberately below MP2's 32,960-probe LCG hit.

    Triage and the dispatcher are stubbed (the real dispatcher would spark the emulator
    oracle); everything else - collection, sweep, materialisation, enrichment contract -
    runs against the real MediaPlayer2 APK.
    """
    from analysis import step0_master_key as step0

    apk, _member, payload_sha, _dex_name, _dex_size, _dex_sha = MEDIAPLAYER2
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    monkeypatch.setattr(
        step0, "_load_triage", lambda _apk: {"verdict": "packed_custom", "confidence": 1.0}
    )
    monkeypatch.setattr(step0, "_attempt_unpack", lambda *a, **k: {
        "verdict": "FAILED", "ecode": "E-ZIPCRYPTO-RUNTIME", "artifacts": [],
        "route": "NATIVE", "family": None, "kdf": None, "iocs": {},
    })
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")

    starved = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))
    assert starved["verdict"] == "FAILED", "20k default must not reach MP2's 32,960th probe"
    assert starved["ecode"] == "E-ZIPCRYPTO-RUNTIME"  # unpack verdict, untouched
    assert starved["breaker"]["truncated"] == "attempts"
    assert starved["breaker"]["recovered"] == []

    funded = step0.run_master_key_preprocess(
        str(apk), str(tmp_path / "work2"), breaker_attempts_cap=50_000
    )
    assert funded["verdict"] == "RECOVERED"
    assert funded["should_enrich_strings"] is True
    assert funded["kdf"]["cipher"] == "java-lcg"
    kit = Path(funded["artifacts"][0]["file"])
    assert kit.name == "kit.zip"
    assert hashlib.sha256(kit.read_bytes()).hexdigest() == payload_sha


RECOVERED = ROOT / "analysis" / "recovered"

# (payload, min classes, permission that must be present)
REAL_PAYLOAD_CASES = [
    (RECOVERED / "myg0N_payload" / "payload_split1.apk", 5000, "android.permission.CALL_PHONE"),
    (RECOVERED / "PNB_One" / "payload_split1.apk", 5000, None),
]


@pytest.mark.parametrize("payload_path,min_classes,permission", REAL_PAYLOAD_CASES,
                         ids=lambda value: getattr(value, "name", str(value)))
def test_real_recovered_app_yields_class_and_permission_evidence(payload_path, min_classes, permission):
    if not payload_path.exists():
        pytest.skip(f"payload absent: {payload_path}")
    evidence = collect_payload_evidence([payload_path.read_bytes()])
    assert evidence["payloads"] == 1
    assert evidence["truncated"] == "none", "the caps must not bite on a real recovered app"
    assert evidence["class_count"] > min_classes
    if permission:
        assert permission in evidence["permissions"]


def test_real_recovered_app_yields_native_library_evidence():
    payload_path = RECOVERED / "PNB_One" / "miner.apk"
    if not payload_path.exists():
        pytest.skip(f"payload absent: {payload_path}")
    evidence = collect_payload_evidence([payload_path.read_bytes()])
    assert len(evidence["native_libs"]) == 2
    assert all(name.lower().endswith(".so") or name.lower().startswith("lib/")
               for name in evidence["native_libs"])


def test_pnb_one_activation_evidence_end_to_end(tmp_path, monkeypatch):
    """The genuine sample spec §1 cites, through the real breaker and collector.

    Seven of its eight hits are ZIP payloads (the eighth is `ttf-magic`): one multidex
    payload (63 dex), one full APK with the manifest, one ELF-magic native payload.
    Triage and the dispatcher are stubbed, as in the MediaPlayer2 acceptance test; the
    breaker, materialisation, collection and report attachment all run for real.
    """
    from analysis import step0_master_key as step0

    apk = PENDRIVE / "apk fraud" / "21" / "PNB ONE ACTIVATION.apk"
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    monkeypatch.setattr(step0, "_load_triage",
                        lambda _apk: {"verdict": "packed_custom", "confidence": 1.0})
    monkeypatch.setattr(step0, "_attempt_unpack", lambda *a, **k: {
        "verdict": "FAILED", "ecode": "E-NATIVE-NO-RECOVERY", "artifacts": [],
        "route": "NATIVE", "family": None, "kdf": None, "iocs": {},
    })
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert master_key["verdict"] == "RECOVERED"
    assert master_key["ecode"] is None, "the recovered sample is no longer E-coded"
    evidence = master_key["recovered_evidence"]
    assert evidence["payloads"] == 7, "the ttf-magic hit is not analysed"
    assert evidence["truncated"] == "none", "the caps must not bite on this sample"
    assert evidence["class_count"] > 7000, "the 1146-class third dex payload is counted too"
    assert evidence["errors"] == []
    assert "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" in evidence["permissions"]
    assert "android.permission.SEND_SMS" in evidence["permissions"]
    assert evidence["native_libs"] == [
        "arm64-v8a",
        "armeabi-v7a",
        "lib/arm64-v8a/liblixhokfsmav.so",
        "lib/armeabi-v7a/liblixhokfsmav.so",
    ], "two of these are ELF-magic only - no lib/ path and no .so suffix"
