"""Reusable static oracle for Android packer key recovery.

Five layers, mirroring the RTO/myg0N case study (thesis ch. 6):

    Layer 1  classify          -> which packer family?
    Layer 2  extract_kdf       -> what is the KDF scheme?
    Layer 3  recover_seed      -> where is the seed material?
    Layer 4  derive_key        -> apply the known formula
    Layer 5  verify_unpack     -> does the plaintext parse?

A new packer plugs in by subclassing PackerOracle and overriding the
three family-specific methods (classify / extract_kdf_pattern /
recover_seed). Key derivation and verification are shared.
"""
from __future__ import annotations

import hashlib
import io
import math
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, Union


class PackerFamily(str, Enum):
    RTO_MYG0N = "rto_myg0n"
    IJIAMI = "ijiami"
    BANGLE_SECNEO = "bangcle_secneo"
    TENCENT_LEGU = "tencent_legu"
    UNKNOWN = "unknown"


class ArtifactKind(str, Enum):
    ZIP = "zip"
    DEX = "dex"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class KDFScheme:
    """Static description of a packer's key/IV derivation."""

    key_hash: str  # hashlib algorithm name, e.g. "sha1"
    key_len: int  # digest bytes kept (truncate)
    iv_hash: Optional[str]  # hash used for the IV; None for ECB/none
    iv_len: int = 16
    cipher: str = "AES/CBC/PKCS5Padding"
    seed_rule: str = ""  # human-readable seed assembly rule


@dataclass(frozen=True)
class Verdict:
    ok: bool
    kind: ArtifactKind
    detail: str
    entropy: float


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _truncated_digest(hash_name: str, material: bytes, length: int) -> bytes:
    try:
        digest = hashlib.new(hash_name)
    except ValueError as exc:
        raise ValueError(f"unknown hash algorithm: {hash_name!r}") from exc
    digest.update(material)
    out = digest.digest()
    if length > len(out):
        raise ValueError(f"key_len {length} exceeds {hash_name} digest size {len(out)}")
    return out[:length]


def derive_key(seed: str, scheme: KDFScheme) -> Tuple[bytes, bytes]:
    """Layer 4: apply the static formula, e.g. SHA1(seed)[:16], SHA256(seed)[:16]."""
    key = _truncated_digest(scheme.key_hash, seed.encode("utf-8"), scheme.key_len)
    iv = b""
    if scheme.iv_hash is not None:
        iv = _truncated_digest(scheme.iv_hash, seed.encode("utf-8"), scheme.iv_len)
    return key, iv


def validate_dex(data: bytes) -> bool:
    return data[:4] == b"dex\n" and len(data) > 112


# testzip() inflates every member, so validation is bounded by the declared sizes first.
MAX_VALIDATE_BYTES = 256 << 20


def validate_zip(data: bytes) -> Tuple[bool, Union[str, dict]]:
    """ZIP magic + central directory presence + CRC spot check. Never raises."""
    if data[:2] != b"PK" or data[2:4] != b"\x03\x04":
        return False, "no local-file header"
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        declared = sum(info.file_size for info in archive.infolist())
        if declared > MAX_VALIDATE_BYTES:
            return False, f"declared size {declared} exceeds validation cap"
        bad_member = archive.testzip()
    except zipfile.BadZipFile as exc:
        return False, f"bad zip: {exc}"
    except Exception as exc:  # hostile archives raise RuntimeError, NotImplementedError, ...
        return False, f"unreadable zip: {type(exc).__name__}: {exc}"
    if bad_member is not None:
        return False, f"crc fail at {bad_member}"
    return True, {"entries": len(archive.namelist())}


def verify_unpack(decrypted: bytes) -> Verdict:
    """Layer 5: deterministic structural check on decrypted output."""
    entropy = shannon_entropy(decrypted[:65536])
    if validate_dex(decrypted):
        return Verdict(True, ArtifactKind.DEX, "dex magic + size ok", entropy)
    ok, info = validate_zip(decrypted)
    if ok:
        return Verdict(True, ArtifactKind.ZIP, f"zip ok, {info['entries']} entries", entropy)
    return Verdict(False, ArtifactKind.UNKNOWN, f"not dex/zip ({info})", entropy)


class PackerOracle(ABC):
    """One instance per packer family. Shared layers are concrete."""

    family: PackerFamily = PackerFamily.UNKNOWN

    @abstractmethod
    def classify(self, apk_path: str) -> PackerFamily:
        """Layer 1: triage -- does this APK look like this oracle's family?"""

    @abstractmethod
    def extract_kdf_pattern(self, so_path: str) -> KDFScheme:
        """Layer 2: read the native listing/trace; return the KDF scheme."""

    @abstractmethod
    def recover_seed(self, apk_path: str, scheme: KDFScheme) -> str:
        """Layer 3: find seed material (asset name, hardcoded literal, ...)."""

    def derive_key(self, seed: str, scheme: KDFScheme) -> Tuple[bytes, bytes]:
        return derive_key(seed, scheme)

    def verify_unpack(self, decrypted: bytes) -> Verdict:
        return verify_unpack(decrypted)
