"""Candidate key-derivation schemes, seed priors, and cipher implementations.

The keystream convention was recovered from a shipped sample and is verified
against a pinned vector in ``tests/test_breaker.py``: the keystream is
``Random.nextInt()`` serialised as 4 little-endian bytes per call.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass

from Crypto.Cipher import AES

from packers.framework import KDFScheme, derive_key

LCG_MULTIPLIER = 0x5DEECE66D
LCG_ADDEND = 0xB
LCG_MASK = (1 << 48) - 1

HASH_ORDER: tuple[str, ...] = ("sha1", "sha256", "md5", "sha512")
# AES accepts 128/192/256-bit keys only. A 20-byte candidate can never decrypt anything: it
# would raise inside the cipher, burn budget, and inflate the reported space_size. (The spec's
# {16, 20, 24, 32} truncation set is about key material generally; AES uses its valid subset.)
AES_KEY_LENGTHS: tuple[int, ...] = (16, 24, 32)
IV_ORDER: tuple[str, ...] = ("zeros", "sha1", "sha256", "md5", "sha512")
DIGEST_SIZES: dict[str, int] = {"md5": 16, "sha1": 20, "sha256": 32, "sha512": 64}

# The substring window prior (P0d) is quadratic-cubic in the literal length, so it is
# only worth spending on realistic packer stems. The known families need 16-19 chars.
SUBSTRING_LITERAL_CAP = 24
# The step20 recipe table pairs every stem with a digit suffix 0-9.
DIGIT_SUFFIXES = "0123456789"
STEP20_VARIANTS: tuple[tuple[str, str], ...] = (
    ("sha1", "sha256"),
    ("sha1", "zeros"),
    ("sha256", "zeros"),
    ("sha1", "sha1"),
)


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


@dataclass(frozen=True)
class Scheme:
    """One candidate: which cipher, keyed how, from which seed material."""

    seed: str
    cipher: str
    key_hash: str = ""
    key_len: int = 0
    iv: str = "none"
    xor_mode: str | None = None
    provenance: str = ""


def derive(scheme: Scheme) -> tuple[bytes, bytes]:
    """Return ``(key, iv)`` for a scheme; ``b""`` when the cipher has no IV."""
    if scheme.cipher == "xor":
        if scheme.xor_mode == "seed":
            return scheme.seed.encode("utf-8"), b""
        if scheme.xor_mode == "byte":
            return bytes([int(scheme.seed)]), b""
        digest = hashlib.new(scheme.key_hash, scheme.seed.encode("utf-8")).digest()
        return digest[: scheme.key_len], b""
    if scheme.cipher == "java-lcg":
        return int(scheme.seed).to_bytes(8, "big", signed=True), b""
    kdf = KDFScheme(
        key_hash=scheme.key_hash,
        key_len=scheme.key_len,
        iv_hash=None if scheme.iv in ("none", "zeros") else scheme.iv,
        iv_len=16,
    )
    key, iv = derive_key(scheme.seed, kdf)
    if scheme.iv == "zeros":
        iv = bytes(16)
    return key, iv


def decrypt(scheme: Scheme, data: bytes) -> bytes:
    key, iv = derive(scheme)
    if scheme.cipher == "aes-cbc":
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    if scheme.cipher == "aes-ecb":
        return AES.new(key, AES.MODE_ECB).decrypt(data)
    if scheme.cipher == "xor":
        if not key:
            raise ValueError("xor scheme derived an empty key")
        return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))
    if scheme.cipher == "rc4":
        return _rc4(key, data)
    if scheme.cipher == "java-lcg":
        keystream = JavaRandom(int(scheme.seed)).keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, keystream, strict=True))
    raise ValueError(f"unknown cipher {scheme.cipher!r}")


def _rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def prior_schemes(stem: str) -> list[Scheme]:
    """Known-family recipes, cheapest/most-likely first (P0)."""
    out: list[Scheme] = [
        Scheme(
            seed=f"{stem}2",
            cipher="aes-cbc",
            key_hash="sha1",
            key_len=16,
            iv="sha256",
            provenance="prior:myg0n",
        ),
        Scheme(
            seed=stem,
            cipher="aes-cbc",
            key_hash="sha1",
            key_len=16,
            iv="zeros",
            provenance="prior:gen2-zero-iv",
        ),
    ]
    seen = {(s.cipher, s.seed, s.key_hash, s.key_len, s.iv) for s in out}
    for seed in [f"{stem}1", stem] + [f"{stem}{digit}" for digit in DIGIT_SUFFIXES]:
        for key_hash, iv in STEP20_VARIANTS:
            identity = ("aes-cbc", seed, key_hash, 16, iv)
            if identity in seen:
                continue
            seen.add(identity)
            out.append(
                Scheme(
                    seed=seed,
                    cipher="aes-cbc",
                    key_hash=key_hash,
                    key_len=16,
                    iv=iv,
                    provenance="prior:step20-matrix",
                )
            )
    out.extend(_substring_windows(stem))
    return out


def _substring_windows(stem: str) -> list[Scheme]:
    """Mirror ``scripts/unpack.py:85``: seed = literal[a:b][c:] + "2"."""
    literal = f"{stem}bootstrap.dex"
    if len(literal) > SUBSTRING_LITERAL_CAP:
        return []
    schemes: list[Scheme] = []
    for a in range(len(literal) + 1):
        for b in range(a, len(literal) + 1):
            middle = literal[a:b]
            for c in range(len(middle) + 1):
                schemes.append(
                    Scheme(
                        seed=middle[c:] + "2",
                        cipher="aes-cbc",
                        key_hash="sha1",
                        key_len=16,
                        iv="sha256",
                        provenance="prior:rto-substring",
                    )
                )
    return schemes


def matrix_schemes(seed: str, provenance: str) -> Iterator[Scheme]:
    """The bounded sweep for one seed: 61 schemes (see the pinned count test)."""
    key_specs = [
        (key_hash, key_len)
        for key_hash in HASH_ORDER
        for key_len in AES_KEY_LENGTHS
        if key_len <= DIGEST_SIZES[key_hash]
    ]
    for key_hash, key_len in key_specs:
        for iv in IV_ORDER:
            yield Scheme(
                seed=seed,
                cipher="aes-cbc",
                key_hash=key_hash,
                key_len=key_len,
                iv=iv,
                provenance=provenance,
            )
    for key_hash, key_len in key_specs:
        yield Scheme(
            seed=seed,
            cipher="aes-ecb",
            key_hash=key_hash,
            key_len=key_len,
            provenance=provenance,
        )
    for key_hash in HASH_ORDER:
        yield Scheme(
            seed=seed,
            cipher="xor",
            key_hash=key_hash,
            key_len=16,
            xor_mode="digest16",
            provenance=provenance,
        )
        yield Scheme(
            seed=seed,
            cipher="xor",
            key_hash=key_hash,
            key_len=DIGEST_SIZES[key_hash],
            xor_mode="digest",
            provenance=provenance,
        )
    yield Scheme(seed=seed, cipher="xor", xor_mode="seed", provenance=provenance)
    for key_hash in HASH_ORDER:
        yield Scheme(
            seed=seed,
            cipher="rc4",
            key_hash=key_hash,
            key_len=16,
            provenance=provenance,
        )


def single_byte_xor_schemes() -> Iterator[Scheme]:
    """255 seed-independent XOR keys; tried after the seed-derived candidates.

    Key 0 is excluded: XOR with 0 is the identity, so "decrypting" with it returns the
    ciphertext unchanged. That reported already-plaintext members (a JSON blob validates
    with no decryption at all) as recoveries, which is the weak class phase 1's sweep
    recorded as its first hardening candidate.
    """
    for byte in range(1, 256):
        yield Scheme(
            seed=str(byte),
            cipher="xor",
            xor_mode="byte",
            provenance="xor:single-byte",
        )
