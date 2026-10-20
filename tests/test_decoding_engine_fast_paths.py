"""Equivalence checks for the byte-table fast paths in decoding_engine.

printable_ratio and the XOR key loop were rewritten with bytes.translate. These
tests pin them to the plain per-byte definitions they replaced.
"""

import random

from analysis.decoding_engine import _XOR_TABLES, printable_ratio


def _reference_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13)) / len(data)


def test_printable_ratio_matches_reference():
    rng = random.Random(1)
    alphabet = b"abc XYZ\n\t\r\x7f\x80\x00"
    cases = [b"", b"\x00", bytes(range(256))]
    cases += [bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 200))) for _ in range(100)]
    cases += [bytes(rng.choice(alphabet) for _ in range(rng.randint(1, 200))) for _ in range(100)]
    for data in cases:
        assert printable_ratio(data) == _reference_ratio(data)


def test_xor_tables_match_reference():
    data = bytes(range(256))
    for key in (0, 1, 7, 255):
        assert data.translate(_XOR_TABLES[key]) == bytes(b ^ key for b in data)
