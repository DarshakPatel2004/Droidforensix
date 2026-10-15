"""The search engine: probe cheaply, validate strongly, then attack inside a budget.

Validation is deliberately two-stage. The probe decrypts a 16-byte-aligned prefix and
looks for a payload magic, which is cheap enough to run hundreds of thousands of times
but can match by chance (roughly one in 2^16 for a two-byte magic). Only a probe match
earns a full decrypt plus :func:`validate_payload`, and only strong validation can
produce a hit. Probe matches that fail validation are counted, never reported.
"""
from __future__ import annotations

import json
import struct
import zlib
from dataclasses import dataclass

from packers.breaker.blobs import PROBE_MAGICS
from packers.breaker.schemes import Scheme, decrypt
from packers.framework import validate_dex, validate_zip

PROBE_LEN = 48
BLOCK_SIZE = 16
EOCD_SEARCH_WINDOW = 65557
ZIP_EOCD_SIG = b"PK\x05\x06"
DEX_MAGIC = b"dex\n"
ELF_MAGIC = b"\x7fELF"
TTF_MAGIC = b"\x00\x01\x00\x00"
JSON_MAGIC = b"{"


@dataclass(frozen=True)
class Validation:
    """What a successful candidate turned out to be, and how strongly we know it."""

    kind: str
    evidence: str


def probe_matches(scheme: Scheme, data: bytes) -> bool:
    """Decrypt a 16-byte-aligned prefix of ``data`` and look for a payload magic."""
    if len(data) < BLOCK_SIZE:
        return False
    length = PROBE_LEN if len(data) >= PROBE_LEN else len(data) - (len(data) % BLOCK_SIZE)
    if length < BLOCK_SIZE:
        return False
    try:
        plaintext = decrypt(scheme, data[:length])
    except (ValueError, TypeError):
        return False
    return any(plaintext.startswith(signature) for signature, _kind in PROBE_MAGICS)


def validate_payload(data: bytes) -> Validation | None:
    """Strong structural validation, strongest evidence first. Never raises."""
    zip_evidence = _zip_evidence(data)
    if zip_evidence:
        return Validation("zip", zip_evidence)
    dex_evidence = _dex_evidence(data)
    if dex_evidence:
        return Validation("dex", dex_evidence)
    if _is_gzip(data):
        return Validation("gzip", "gzip")
    if _is_elf(data):
        return Validation("elf", "elf")
    if _is_json(data):
        return Validation("json", "json")
    if data.startswith(TTF_MAGIC):
        return Validation("ttf", "ttf-magic")
    return None


def _zip_evidence(data: bytes) -> str | None:
    if data[:4] != b"PK\x03\x04":
        return None
    try:
        ok, _info = validate_zip(data)
    except Exception:
        # zipfile can raise struct/OS errors on hostile input; a broken payload must never
        # abort a batch run. Fall through to the weaker evidence level instead.
        ok = False
    if ok:
        return "zip-strict"
    if ZIP_EOCD_SIG in data[-EOCD_SEARCH_WINDOW:]:
        return "zip-eocd"
    return None


def _dex_evidence(data: bytes) -> str | None:
    if not validate_dex(data):
        return None
    if len(data) >= 36 and struct.unpack("<I", data[32:36])[0] == len(data):
        return "dex-header"
    return "dex-magic"


def _is_gzip(data: bytes) -> bool:
    if data[:2] != b"\x1f\x8b":
        return False
    try:
        zlib.decompress(data, 16 + zlib.MAX_WBITS)
    except zlib.error:
        return False
    return True


def _is_elf(data: bytes) -> bool:
    return data.startswith(ELF_MAGIC) and len(data) > 64 and data[4] in (1, 2)


def _is_json(data: bytes) -> bool:
    if data[:1] != JSON_MAGIC:
        return False
    try:
        json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return False
    return True
