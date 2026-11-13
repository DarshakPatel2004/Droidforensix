"""Regression tests for the analysis closure pass (audit 2026-11-11: A1-32/33/40/46, A2-M12, A2-L1/L2/L5/L6/L13/L24, B1-02)."""

import datetime
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from analysis import cipher_tracing as ct
from analysis import custody
from analysis import step1_apk_extraction as s1
from analysis import step7_llm_assessment as s7
from analysis import step8_obfuscation_analysis as s8
from analysis import step12_reflective_tracing as s12
from analysis import step13_native_elf_analysis as s13
from analysis import step16_certificate_analysis as s16
from analysis.step5_c2_extraction import is_ad_network

REPO = Path(__file__).resolve().parent.parent


def test_reflective_forname_counted_once():
    # A1/L1: Class.forName("x") used to match two patterns and count twice.
    calls = s12.scan_source_for_reflection('Class.forName("com.a.B")\n', "x.java")
    assert len(calls) == 1
    assert calls[0]["line"] == 1


def test_reflective_line_numbers_are_exact():
    text = "a\nb\n\nClass.forName(\"com.a.B\")\n"
    calls = s12.scan_source_for_reflection(text, "x.smali")
    assert [c["line"] for c in calls] == [4]


def test_smali_unescape_is_single_pass():
    # L6: an escaped backslash followed by n must stay a literal backslash-n.
    bs = chr(92)
    assert ct.smali_unescape(bs + bs + "n") == bs + "n"
    assert ct.smali_unescape("a" + bs + "nb") == "a\nb"
    assert ct.smali_unescape(bs + "u0041") == "A"


def test_match_symbols_uses_word_boundaries():
    # L24: 'des' must not hit 'destroy', 'trace' must not hit 'stacktrace'.
    out = s13.match_symbols(["destroy_all", "stacktrace_dump", "AES_encrypt", "ptrace"])
    assert out["crypto_functions"] == ["AES_encrypt"]
    assert out["anti_analysis"] == ["ptrace"]


def test_printable_strings_regex_matches_minimum_length():
    # A1-40: regex extraction keeps runs of >= 6 printable bytes only.
    assert s1._extract_printable_strings(b"\x00abcdef\x01ab\x02hello world!\xff") == ["abcdef", "hello world!"]


def test_native_strings_capped_per_library(tmp_path, monkeypatch):
    # A1-40: one library cannot contribute more than MAX_NATIVE_STRINGS_PER_LIB strings.
    lib = tmp_path / "lib" / "arm64"
    lib.mkdir(parents=True)
    (lib / "libbig.so").write_bytes(b"".join(b"string_%06d\x00" % i for i in range(50)))
    monkeypatch.setattr(s1, "MAX_NATIVE_STRINGS_PER_LIB", 10)
    monkeypatch.setattr(s1.shutil, "which", lambda name: None)
    found = s1.extract_native_strings(str(tmp_path))
    assert len(found) == 10


def test_custody_append_chain_verifies(tmp_path):
    # A1-46: appends go through the lock and keep seq/prev consistent.
    custody.append_event(tmp_path, "a", {"n": 1})
    custody.append_event(tmp_path, "b", {"n": 2})
    result = custody.verify(tmp_path)
    assert result["valid"] is True
    assert result["entries"] == 2


def test_custody_concurrent_appends_keep_chain_valid(tmp_path):
    # A1-46: two processes appending at once must not write the same seq twice.
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        "from analysis import custody;"
        "[custody.append_event(sys.argv[2], 'p', {'i': i}) for i in range(20)]"
    )
    procs = [subprocess.Popen([sys.executable, "-c", code, str(REPO), str(tmp_path)]) for _ in range(3)]
    for p in procs:
        assert p.wait(timeout=120) == 0
    result = custody.verify(tmp_path)
    assert result["valid"] is True
    assert result["entries"] == 60


def test_exfiltration_group_uses_all_permissions():
    # A1-32: INTERNET is not a dangerous permission, so the group must read the full list.
    groups = s8._match_behavior_groups(["SEND_SMS", "READ_CONTACTS", "INTERNET"])
    assert "exfiltration" in {g["group"] for g in groups}
    assert s7._match_behavior_groups is s8._match_behavior_groups


def test_validate_assessment_rejects_bool_risk_score():
    base = {"severity": "high", "narrative": "n", "recommended_actions": []}
    assert s7.validate_assessment({**base, "risk_score": True}) is False
    assert s7.validate_assessment({**base, "risk_score": 70}) is True


def test_ad_network_subdomain_match_unchanged():
    assert is_ad_network("api.airpush.com") is True
    assert is_ad_network("example.org") is False


def test_pkcs7_signing_blob_yields_certificate_fields(tmp_path):
    # A2-M12: jarsigner-style PKCS#7 (.RSA) blobs must parse into subject/issuer/fingerprint.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Closure Test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    blob = (
        pkcs7.PKCS7SignatureBuilder().set_data(b"manifest")
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary])
    )
    parsed = s16._load_signing_certificate(blob, x509, None)
    assert parsed is not None
    assert "Closure Test" in parsed.subject.rfc4514_string()
