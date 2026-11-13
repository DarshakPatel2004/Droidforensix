"""Regression tests for the packers/ audit findings P1-P9 (docs/audit/2026-11-11/E_eval_packers_root.md)."""
import io
import json
import os
import struct
import zipfile

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from packers.breaker.blobs import (
    PROBE_MAGICS,
    SKIPPED_UNREADABLE,
    SKIPPED_ZIPCRYPTO,
    _flagged_content,
    collect_from_zip,
)
from packers.breaker.engine import break_apk, validate_payload
from packers.framework import validate_zip, verify_unpack
from packers.myg0n import MYG0N_SCHEME, MyG0NOracle, derive_key

LOCAL_SIG = b"PK\x03\x04"
CENTRAL_SIG = b"PK\x01\x02"


def _random_bytes(size: int) -> bytes:
    return os.urandom(size)


def _zip_bytes(members: dict[str, bytes], method: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _patch_u16(data: bytes, signature: bytes, field_offset: int, value: int) -> bytes:
    """Overwrite a 2-byte header field in every local (or central) entry of a ZIP."""
    out = bytearray(data)
    at = out.find(signature)
    while at != -1:
        struct.pack_into("<H", out, at + field_offset, value)
        at = out.find(signature, at + 4)
    return bytes(out)


def _set_method(data: bytes, method: int) -> bytes:
    data = _patch_u16(data, LOCAL_SIG, 8, method)
    return _patch_u16(data, CENTRAL_SIG, 10, method)


def _set_flag(data: bytes, bit: int) -> bytes:
    data = _patch_u16(data, LOCAL_SIG, 6, bit)
    return _patch_u16(data, CENTRAL_SIG, 8, bit)


def test_p1_unknown_method_member_is_read_as_stored(tmp_path):
    payload = _random_bytes(600)
    data = _set_method(_zip_bytes({"assets/blob": payload}), 99)
    collection = collect_from_zip(data, depth=0)
    record = {r.name: r for r in collection.records}["assets/blob"]
    assert record.outcome != SKIPPED_ZIPCRYPTO
    assert record.outcome != SKIPPED_UNREADABLE
    assert [blob.data for blob in collection.blobs] == [payload]
    assert collection.blobs[0].content == "stored"


def test_p1_unreadable_plain_member_is_skipped_unreadable_not_zipcrypto():
    data = bytearray(_zip_bytes({"assets/blob": _random_bytes(600)}))
    # Corrupt one stored payload byte: zipfile raises a CRC error, and the manual read fails too.
    data[data.find(LOCAL_SIG) + 30 + len("assets/blob") + 10] ^= 0xFF
    collection = collect_from_zip(bytes(data), depth=0)
    record = {r.name: r for r in collection.records}["assets/blob"]
    assert record.outcome == SKIPPED_UNREADABLE
    assert not collection.blobs


def test_p2_plaintext_zip_members_are_recursed_into(tmp_path):
    payload = _random_bytes(4096)
    inner = _zip_bytes({"assets/blob": payload})
    apk = tmp_path / "app.apk"
    apk.write_bytes(_zip_bytes({"assets/inner.jar": inner}))
    out = tmp_path / "out"
    break_apk(apk, out, attempts_cap=1000, budget_s=30.0)
    coverage = json.loads(next(out.iterdir()).joinpath("coverage.json").read_text(encoding="utf-8"))
    assert "assets/inner.jar!assets/blob" in {row["name"] for row in coverage["members"]}


def test_p3_padded_json_payload_validates():
    body = b'{"a": 1}'
    padded = body + bytes([8]) * 8
    assert validate_payload(padded).kind == "json"
    assert validate_payload(body).kind == "json"


def test_p5_validate_zip_never_raises_on_encrypted_member():
    data = _set_flag(_zip_bytes({"a": b"hello"}), 0x1)
    ok, detail = validate_zip(data)
    assert ok is False
    assert detail.startswith("unreadable zip")
    assert verify_unpack(data).ok is False


def test_p4_declared_size_over_cap_is_rejected_before_testzip(monkeypatch):
    import packers.framework as framework

    monkeypatch.setattr(framework, "MAX_VALIDATE_BYTES", 10)
    ok, detail = validate_zip(_zip_bytes({"a": b"x" * 100}))
    assert ok is False
    assert "exceeds validation cap" in detail


def test_p6_truncated_flagged_local_header_is_reported_not_raised():
    info = zipfile.ZipInfo("a")
    info.header_offset = 0
    info.compress_size = 4
    content, _kind, detail = _flagged_content(LOCAL_SIG + b"\x00" * 5, info)
    assert content is None
    assert detail == "truncated local header"


def test_p7_json_probe_needs_two_bytes_not_a_lone_brace():
    assert all(signature != b"{" for signature, _kind in PROBE_MAGICS)
    assert any(signature == b'{"' for signature, _kind in PROBE_MAGICS)


def test_p8_extensionless_low_entropy_asset_is_not_a_container(tmp_path):
    apk = tmp_path / "plain.apk"
    apk.write_bytes(_zip_bytes({"assets/LICENSE": b"MIT license text " * 100}))
    assert MyG0NOracle().classify(str(apk)).value == "unknown"


def test_p8_high_entropy_extensionless_asset_is_a_container(tmp_path):
    apk = tmp_path / "packed.apk"
    apk.write_bytes(_zip_bytes({"assets/myg0N": _random_bytes(4096)}))
    assert MyG0NOracle().classify(str(apk)).value == "rto_myg0n"


def test_p9_decrypt_asset_unpads_and_rejects_non_containers(tmp_path):
    oracle = MyG0NOracle()
    seed = "abcdef2"
    key, iv = derive_key(seed, MYG0N_SCHEME)
    plaintext = b"zip-like payload " * 5
    good = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    apk = tmp_path / "good.apk"
    apk.write_bytes(_zip_bytes({"assets/abcdef": good}))
    assert oracle.decrypt_asset(str(apk), seed, asset="assets/abcdef") == plaintext

    # Whole blocks but invalid PKCS#5 padding (last byte 'x'), and a non-block-aligned length.
    for ciphertext in (AES.new(key, AES.MODE_CBC, iv).encrypt(b"x" * 16), good[:-1]):
        apk_bad = tmp_path / "bad.apk"
        apk_bad.write_bytes(_zip_bytes({"assets/abcdef": ciphertext}))
        with pytest.raises(ValueError, match="not an AES-CBC container"):
            oracle.decrypt_asset(str(apk_bad), seed, asset="assets/abcdef")
