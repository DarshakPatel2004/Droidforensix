"""step19 must not inflate a hostile member without bound (zip bomb)."""

import zlib

import pytest

import analysis.step19_container_repair as step19


def _raw_deflate(data: bytes) -> bytes:
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    return comp.compress(data) + comp.flush()


def test_inflate_capped_returns_full_output_under_cap():
    assert step19._inflate_capped(_raw_deflate(b"hello world")) == b"hello world"


def test_inflate_capped_rejects_output_over_cap(monkeypatch):
    monkeypatch.setattr(step19, "MAX_MEMBER_INFLATE_BYTES", 1024 * 1024)
    bomb = _raw_deflate(b"\x00" * (8 * 1024 * 1024))  # ~8 KB of deflate, 8 MB of output
    assert len(bomb) < 64 * 1024
    with pytest.raises(zlib.error):
        step19._inflate_capped(bomb)


def test_inflate_capped_rejects_truncated_stream():
    full = _raw_deflate(b"A" * 10000)
    with pytest.raises(zlib.error):
        step19._inflate_capped(full[: len(full) // 2])


def test_recover_member_gives_empty_for_bomb(monkeypatch):
    monkeypatch.setattr(step19, "MAX_MEMBER_INFLATE_BYTES", 1024 * 1024)
    bomb = _raw_deflate(b"\x00" * (8 * 1024 * 1024))
    entry = {"usize": 8 * 1024 * 1024, "csize": len(bomb), "crc": 0}
    assert step19._recover_member(entry, bomb) == b""
