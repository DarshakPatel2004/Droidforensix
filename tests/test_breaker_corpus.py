"""Corpus acceptance for the master key breaker (opt-in, slow).

Run with:  $env:DFX_BREAKER_ACCEPTANCE=1; .venv\\Scripts\\python.exe -m pytest tests/test_breaker_corpus.py -v
"""
import os
from pathlib import Path

import pytest

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
