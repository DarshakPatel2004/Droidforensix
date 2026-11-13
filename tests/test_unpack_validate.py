"""P5: a DEX is only RECOVERED when its header validates (magic, file_size, Adler-32)."""
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from unpack import validate_dex  # noqa: E402


def _dex(size=256):
    body = bytearray(size)
    body[0:8] = b"dex\n035\x00"
    body[32:36] = struct.pack("<I", size)                 # file_size
    body[12:] = bytes(body[12:])
    body[8:12] = struct.pack("<I", zlib.adler32(bytes(body[12:])) & 0xFFFFFFFF)
    return bytes(body)


def test_well_formed_dex_validates():
    assert validate_dex(_dex())


def test_magic_with_junk_body_is_rejected():
    junk = b"dex\n035\x00" + b"\x01" * 300
    assert not validate_dex(junk)


def test_truncated_dex_is_rejected():
    assert not validate_dex(_dex()[:200])
