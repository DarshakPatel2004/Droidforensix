"""Tests for the static packer oracle framework (packers/)."""
import hashlib
import io
import zipfile

import pytest

from packers import (
    KDFScheme,
    PackerFamily,
    derive_key,
    shannon_entropy,
    validate_dex,
    validate_zip,
    verify_unpack,
)
from packers.myg0n import MYG0N_SCHEME, MyG0NOracle

# Ground-truth values captured at runtime (rto_analysis/PHASE4_FINDINGS.md).
RTO_SEED = "myg0N2"
RTO_KEY_HEX = "6eada2ac127d60e3c17e4940981c5bc6"
RTO_IV_HEX = "d0045d33d393892263a7b43ccac6e578"


def _make_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", "hello world")
    return buf.getvalue()


class TestDeriveKey:
    def test_rto_reference_values(self):
        key, iv = derive_key(RTO_SEED, MYG0N_SCHEME)
        assert key.hex() == RTO_KEY_HEX
        assert iv.hex() == RTO_IV_HEX

    def test_key_len_and_type(self):
        key, iv = derive_key("seed", MYG0N_SCHEME)
        assert len(key) == 16 and len(iv) == 16

    def test_no_iv_scheme(self):
        scheme = KDFScheme(key_hash="md5", key_len=16, iv_hash=None)
        key, iv = derive_key("seed", scheme)
        assert key == hashlib.md5(b"seed").digest()
        assert iv == b""

    def test_rejects_unknown_hash(self):
        scheme = KDFScheme(key_hash="not-a-hash", key_len=16, iv_hash=None)
        with pytest.raises(ValueError):
            derive_key("seed", scheme)


class TestVerifyUnpack:
    def test_zip_accepted(self):
        verdict = verify_unpack(_make_zip())
        assert verdict.ok and verdict.kind.value == "zip"

    def test_dex_accepted(self):
        verdict = verify_unpack(b"dex\n035\x00" + b"\x00" * 128)
        assert verdict.ok and verdict.kind.value == "dex"

    def test_garbage_rejected(self):
        verdict = verify_unpack(b"\xde\xad\xbe\xef" * 64)
        assert not verdict.ok

    def test_entropy_thresholds(self):
        assert shannon_entropy(b"\x00" * 1024) == 0.0
        assert shannon_entropy(bytes(range(256)) * 4) > 7.9


class TestValidators:
    def test_validate_zip_roundtrip(self):
        ok, info = validate_zip(_make_zip())
        assert ok and info["entries"] == 1

    def test_validate_zip_rejects_plaintext(self):
        ok, info = validate_zip(b"hello")
        assert not ok and isinstance(info, str)

    def test_validate_dex(self):
        assert validate_dex(b"dex\n035\x00" + b"\x00" * 200)
        assert not validate_dex(b"PK\x03\x04")


class TestMyG0NOracle:
    def test_classify_real_rto(self):
        oracle = MyG0NOracle()
        from pathlib import Path

        rto = Path(__file__).resolve().parent.parent / "RTO.apk"
        if not rto.exists():
            pytest.skip("RTO.apk not present")
        assert oracle.classify(str(rto)) is PackerFamily.RTO_MYG0N

    def test_seed_rule(self):
        from pathlib import Path

        rto = Path(__file__).resolve().parent.parent / "RTO.apk"
        if not rto.exists():
            pytest.skip("RTO.apk not present")
        oracle = MyG0NOracle()
        assert oracle.recover_seed(str(rto)) == "myg0N2"

    def test_full_unpack_zip(self):
        from pathlib import Path

        rto = Path(__file__).resolve().parent.parent / "RTO.apk"
        if not rto.exists():
            pytest.skip("RTO.apk not present")
        oracle = MyG0NOracle()
        plaintext, verdict = oracle.unpack(str(rto))
        assert verdict.ok and verdict.kind.value == "zip"
        assert plaintext[:2] == b"PK"
