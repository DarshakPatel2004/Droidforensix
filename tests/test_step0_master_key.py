"""Second chance wiring: step0_master_key -> master key breaker (packers/breaker/).

The breaker runs only after ``_attempt_unpack`` fails. These tests fix that
contract: a hit must yield a RECOVERED report in the shape the pipeline already
consumes (artifacts on disk + kdf, no key material), and a miss must leave the
unpack verdict/ecode/taxonomy exactly as they were.

``_attempt_unpack`` (decompiler + emulator territory) is stubbed: the seam under
test is the second chance itself, and it must not depend on external tools.
"""
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from Crypto.Cipher import AES

import analysis.step0_master_key as step0

KIT_MEMBER = "assets/myg0N"
# Hand-derived from docs/MASTER_KEY_STRATEGY.md §2: seed = stem + "2",
# key = sha1(seed)[:16], iv = sha256(seed)[:16], AES-CBC, PKCS#7.
KIT_SEED = "myg0N2"
KIT_MARKER = "ZZ_BREAKER_WIRING_MARKER_42"
# The breaker skips members under 512 bytes (packers/breaker/blobs.py MIN_BLOB_SIZE),
# so kit payloads must carry padding past that bound to ever be attacked.
KIT_NATIVE_PAD = 1024

FAILED_REPORT = {
    "verdict": "FAILED",
    "ecode": "E-NATIVE-NOENTRY",
    "artifacts": [],
    "route": "NATIVE",
    "family": "Ijiami",
    "kdf": None,
    "iocs": {},
}


def _kit_payload() -> bytes:
    """A minimal recovered kit: a ZIP whose dex carries one known marker string."""
    dex = b"dex\n035\x00" + b"\x00" * 12 + KIT_MARKER.encode("ascii") + b"\x00" * 64
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("bootstrap.dex", dex)
        archive.writestr("assets/filler.bin", b"\x00" * 1024)
    return buffer.getvalue()


def _kit_payload_with_native() -> bytes:
    """A minimal recovered kit that carries one native member and nothing else useful."""
    dex = b"dex\n035\x00" + b"\x00" * 12 + b"\x00" * KIT_NATIVE_PAD
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("lib/armeabi-v7a/libx.so", b"\x7fELF" + b"\x00" * 32)
        archive.writestr("bootstrap.dex", dex)
    return buffer.getvalue()


def _encrypt_like_myg0n(payload: bytes, stem: str = "myg0N") -> tuple[bytes, bytes]:
    """Encrypt with the published myg0N recipe, derived without the code under test.

    Returns ``(ciphertext, plaintext_as_the_engine_records_it)``: the engine validates
    and hashes the whole decrypted buffer, PKCS#7 padding included, so that padded
    buffer is exactly what a replay must reproduce.
    """
    seed = f"{stem}2".encode("ascii")
    key = hashlib.sha1(seed).digest()[:16]
    iv = hashlib.sha256(seed).digest()[:16]
    padding = 16 - (len(payload) % 16)
    padded = payload + bytes([padding]) * padding
    return AES.new(key, AES.MODE_CBC, iv).encrypt(padded), padded


def _write_apk(path: Path, blob: bytes | None) -> str:
    """Write a tiny APK; ``blob`` is placed at the myg0N asset name when given."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 128)
        if blob is not None:
            archive.writestr(KIT_MEMBER, blob)
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def packed_triage(monkeypatch):
    """Triages as packed and has the unpack dispatcher report a hard failure."""
    monkeypatch.setattr(
        step0, "_load_triage", lambda _apk: {"verdict": "packed_custom", "confidence": 0.9}
    )
    monkeypatch.setattr(step0, "_attempt_unpack", lambda *args, **kwargs: dict(FAILED_REPORT))


def test_second_chance_recovers_prior_scheme_blob(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    payload = _kit_payload()
    ciphertext, padded = _encrypt_like_myg0n(payload)
    apk = tmp_path / "kit.apk"
    digest = _write_apk(apk, ciphertext)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert master_key["verdict"] == "RECOVERED"
    assert master_key["should_enrich_strings"] is True
    assert master_key["ecode"] is None
    assert master_key["is_e_coded"] is False
    assert master_key["breaker"]["outcome"] == "RECOVERED"

    kit = Path(master_key["artifacts"][0]["file"])
    assert kit.name == "kit.zip"
    # Same layout unpack writes: <work_dir>/master_key/<sha16>/kit.zip
    assert kit.parent.name == digest[:16]
    assert kit.parent.parent.name == "master_key"
    assert hashlib.sha256(kit.read_bytes()).hexdigest() == hashlib.sha256(padded).hexdigest()

    kdf = master_key["kdf"]
    assert kdf["cipher"] == "aes-cbc"
    assert kdf["provenance"] == "prior:myg0n"
    assert kdf["validation"] == "zip-strict"

    hit_json = tmp_path / "evidence" / digest[:16] / "hit.json"
    assert hit_json.exists(), "hit.json (local-only key material) must stay under the evidence dir"


def test_miss_keeps_unpack_report_untouched(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    apk = tmp_path / "plain.apk"
    _write_apk(apk, blob=None)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    # Pre-change contract: every one of these is what unpack alone produced.
    assert master_key["verdict"] == "FAILED"
    assert master_key["ecode"] == "E-NATIVE-NOENTRY"
    assert master_key["is_e_coded"] is True
    assert master_key["should_enrich_strings"] is False
    assert master_key["artifacts"] == []
    assert master_key["kdf"] is None
    assert master_key["kt_taxonomy"].startswith("Commercial VMP Ijiami")
    # The miss is typed, just not in the contract field.
    assert master_key["breaker"]["outcome"] == "E-KDF-EXHAUSTED"
    assert master_key["breaker"]["recovered"] == []


def test_engine_fault_is_isolated(packed_triage, tmp_path, monkeypatch):
    import packers.breaker.engine as breaker_engine

    def boom(*_args, **_kwargs):
        raise RuntimeError("crypto unavailable")

    monkeypatch.setattr(breaker_engine, "break_apk", boom)
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(_kit_payload())
    apk = tmp_path / "kit.apk"
    _write_apk(apk, ciphertext)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    # A breaker fault must not become a pipeline failure, nor rewrite the unpack verdict.
    assert master_key["verdict"] == "FAILED"
    assert master_key["ecode"] == "E-NATIVE-NOENTRY"
    assert master_key["is_e_coded"] is True
    assert master_key["breaker"]["outcome"] == "E-ENGINE-FAULT"
    assert "RuntimeError" in master_key["breaker"]["detail"]


def test_result_never_carries_key_material(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(_kit_payload())
    apk = tmp_path / "kit.apk"
    digest = _write_apk(apk, ciphertext)
    key_hex = hashlib.sha1(KIT_SEED.encode("ascii")).digest()[:16].hex()
    iv_hex = hashlib.sha256(KIT_SEED.encode("ascii")).digest()[:16].hex()

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    dumped = json.dumps(master_key)
    assert key_hex not in dumped
    assert iv_hex not in dumped
    assert "key_hex" not in dumped
    # Local-only evidence is the one place key material may live.
    evidence = (tmp_path / "evidence" / digest[:16] / "hit.json").read_text(encoding="utf-8")
    assert key_hex in evidence


def test_clean_static_sample_never_reaches_the_breaker(tmp_path, monkeypatch):
    monkeypatch.setattr(
        step0, "_load_triage", lambda _apk: {"verdict": "clean_static", "confidence": 0.95}
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("breaker must not run on a clean_static sample")

    monkeypatch.setattr(step0, "_breaker_second_chance", forbidden)
    apk = tmp_path / "clean.apk"
    _write_apk(apk, blob=None)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert master_key["route"] == "SKIPPED"
    assert master_key["verdict"] == "SKIPPED"
    assert master_key["breaker"] is None


def test_attempts_cap_is_honoured(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(_kit_payload())
    apk = tmp_path / "kit.apk"
    _write_apk(apk, ciphertext)

    starved = step0.run_master_key_preprocess(
        str(apk), str(tmp_path / "work"), breaker_attempts_cap=0
    )
    assert starved["verdict"] == "FAILED"
    assert starved["ecode"] == "E-NATIVE-NOENTRY"
    assert starved["breaker"]["outcome"] == "E-KDF-BUDGET"
    assert starved["breaker"]["truncated"] == "attempts"
    assert starved["breaker"]["attempts_total"] == 0

    funded = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work2"))
    assert funded["verdict"] == "RECOVERED"


def test_enrich_merges_recovered_kit_strings(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(_kit_payload())
    apk = tmp_path / "kit.apk"
    _write_apk(apk, ciphertext)
    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    strings_result = step0.enrich_strings_with_recovered(
        {"categories": {}, "total_strings": 0}, master_key
    )

    literals = strings_result["categories"]["string_literals"]
    values = [item["value"] if isinstance(item, dict) else item for item in literals]
    assert KIT_MARKER in values


def test_non_zip_payload_is_kept_without_enrichment(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    dex = b"dex\n035\x00" + bytes(range(256)) * 3
    ciphertext, padded = _encrypt_like_myg0n(dex)
    apk = tmp_path / "dex.apk"
    _write_apk(apk, ciphertext)
    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert master_key["verdict"] == "RECOVERED"
    artifact = Path(master_key["artifacts"][0]["file"])
    assert artifact.name == "_recovered.dex"
    assert artifact.read_bytes() == padded

    strings_result = step0.enrich_strings_with_recovered(
        {"categories": {}, "total_strings": 0}, master_key
    )
    # Parity with the unpack path: only ZIP artifacts are mined for strings.
    assert strings_result == {"categories": {}, "total_strings": 0}


def test_two_non_zip_recoveries_do_not_collide(packed_triage, tmp_path, monkeypatch):
    """Two payloads written under one file name would report two hashes for one path."""
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    first_dex = b"dex\n035\x00" + b"F" * 600
    second_dex = b"dex\n035\x00" + b"S" * 600
    apk = tmp_path / "two.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 128)
        archive.writestr("assets/AAAA", _encrypt_like_myg0n(first_dex, "AAAA")[0])
        archive.writestr("assets/BBBB", _encrypt_like_myg0n(second_dex, "BBBB")[0])

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert master_key["verdict"] == "RECOVERED"
    assert len(master_key["breaker"]["recovered"]) == 2, "both members must be reported"
    assert len(master_key["artifacts"]) == 1
    artifact = master_key["artifacts"][0]
    # The single artifact must describe the bytes actually on disk.
    assert artifact["sha256"] == hashlib.sha256(Path(artifact["file"]).read_bytes()).hexdigest()


def test_recovery_attaches_recovered_evidence(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(_kit_payload_with_native())
    apk = tmp_path / "kit.apk"
    _write_apk(apk, ciphertext)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    evidence = master_key["recovered_evidence"]
    assert evidence["payloads"] == 1
    assert evidence["members_scanned"] == 2
    assert evidence["native_libs"] == ["lib/armeabi-v7a/libx.so"]


def test_miss_has_no_recovered_evidence_key(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    apk = tmp_path / "plain.apk"
    _write_apk(apk, blob=None)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert "recovered_evidence" not in master_key


def test_non_zip_recovery_has_no_recovered_evidence(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(b"dex\n035\x00" + bytes(range(256)) * 3)
    apk = tmp_path / "dex.apk"
    _write_apk(apk, ciphertext)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert master_key["verdict"] == "RECOVERED"
    assert "recovered_evidence" not in master_key


def test_every_zip_recovery_is_analysed_not_only_the_written_kit(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    first = _kit_payload_with_native()
    second = _kit_payload_with_native()
    apk = tmp_path / "two.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 128)
        archive.writestr("assets/AAAA", _encrypt_like_myg0n(first, "AAAA")[0])
        archive.writestr("assets/BBBB", _encrypt_like_myg0n(second, "BBBB")[0])

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert len(master_key["artifacts"]) == 1, "only the first kit is materialised"
    assert master_key["recovered_evidence"]["payloads"] == 2, "both ZIP recoveries are analysed"


def test_recovered_evidence_is_not_bound_for_the_taxonomy(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(_kit_payload_with_native())
    apk = tmp_path / "kit.apk"
    _write_apk(apk, ciphertext)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    # Evidence is additive: it changes no contract field and no taxonomy wording.
    assert master_key["ecode"] is None
    assert master_key["kt_taxonomy"].startswith("at-rest asset blob recovered on second chance")
