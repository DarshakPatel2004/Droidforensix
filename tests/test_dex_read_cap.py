"""Zip members read in full by step21 and step16 are refused above their declared-size cap."""

import io
import zipfile

import pytest

import analysis.step16_certificate_analysis as step16
import analysis.step21_string_deobfuscation as step21


def _zip_with(name: str, payload: bytes) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, payload)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_read_dex_capped_returns_member_under_cap(monkeypatch):
    monkeypatch.setattr(step21, "MAX_DEX_READ_BYTES", 1024)
    zf = _zip_with("classes.dex", b"dex\n035" + b"x" * 100)
    assert step21._read_dex_capped(zf, "classes.dex").startswith(b"dex")


def test_read_dex_capped_refuses_member_over_cap(monkeypatch):
    monkeypatch.setattr(step21, "MAX_DEX_READ_BYTES", 1024)
    zf = _zip_with("classes.dex", b"x" * 4096)
    with pytest.raises(ValueError, match="declared size exceeds"):
        step21._read_dex_capped(zf, "classes.dex")


def test_certificate_parse_refuses_oversized_signature_block(tmp_path, monkeypatch):
    apk = tmp_path / "t.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/CERT.RSA", b"x" * (2 * 1024 * 1024))
    # Oversized block must be rejected (returns None) without raising out of the step.
    assert step16.parse_certificate_from_apk(str(apk)) is None
