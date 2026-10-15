"""Candidate key-derivation schemes and cipher implementations.

The keystream convention was recovered from a shipped sample and is verified
against a pinned vector in ``tests/test_breaker.py``: the keystream is
``Random.nextInt()`` serialised as 4 little-endian bytes per call.
"""

LCG_MULTIPLIER = 0x5DEECE66D
LCG_ADDEND = 0xB
LCG_MASK = (1 << 48) - 1


class JavaRandom:
    """``java.util.Random``'s LCG, enough to reproduce its byte keystream."""

    def __init__(self, seed_int: int) -> None:
        self._state = (seed_int ^ LCG_MULTIPLIER) & LCG_MASK

    def next(self, bits: int) -> int:
        self._state = (self._state * LCG_MULTIPLIER + LCG_ADDEND) & LCG_MASK
        return self._state >> (48 - bits)

    def next_int(self) -> int:
        value = self.next(32)
        return value - (1 << 32) if value >= (1 << 31) else value

    def keystream(self, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            out += self.next_int().to_bytes(4, "little", signed=True)
        return bytes(out[:length])
