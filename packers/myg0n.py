"""Reference PackerOracle implementation: RTO.apk / myg0N (thesis ch. 6).

Ground-truth crypto captured in `rto_analysis/PHASE4_FINDINGS.md`:

    seed = "myg0N" + "2"                      (asset stem + literal "2")
    KEY  = SHA1("myg0N2")[:16]   = 6eada2ac127d60e3c17e4940981c5bc6
    IV   = SHA256("myg0N2")[:16] = d0045d33d393892263a7b43ccac6e578
    AES/CBC/PKCS5Padding(key=KEY, iv=IV) decrypts assets/myg0N -> ZIP
"""
from __future__ import annotations

import re
import zipfile
from typing import Optional, Tuple

from .framework import (
    KDFScheme,
    PackerFamily,
    PackerOracle,
    Verdict,
    derive_key,
    shannon_entropy,
    verify_unpack,
)

MYG0N_SCHEME = KDFScheme(
    key_hash="sha1",
    key_len=16,
    iv_hash="sha256",
    iv_len=16,
    cipher="AES/CBC/PKCS5Padding",
    seed_rule='seed = asset_stem + "2"',
)

# Assets that match this profile are the encrypted container. The name alone also matches
# ordinary files (assets/LICENSE), so the entropy and size gates below decide.
_CONTAINER_RE = re.compile(r"^assets/([A-Za-z0-9]{4,16})$")
MIN_CONTAINER_BYTES = 512
MIN_CONTAINER_ENTROPY = 7.9


def _container_assets(archive: zipfile.ZipFile) -> list[str]:
    names = []
    for info in archive.infolist():
        if not _CONTAINER_RE.match(info.filename) or "." in info.filename.rsplit("/", 1)[-1]:
            continue
        if info.file_size < MIN_CONTAINER_BYTES:
            continue
        if shannon_entropy(archive.read(info.filename)) >= MIN_CONTAINER_ENTROPY:
            names.append(info.filename)
    return names


def _container_asset(apk_path: str) -> Optional[str]:
    try:
        with zipfile.ZipFile(apk_path) as archive:
            names = _container_assets(archive)
    except (zipfile.BadZipFile, OSError):
        return None
    return names[0] if names else None


class MyG0NOracle(PackerOracle):
    family = PackerFamily.RTO_MYG0N

    def classify(self, apk_path: str) -> PackerFamily:
        """Layer 1: extension-less high-entropy asset + no plaintext DEX payload."""
        try:
            with zipfile.ZipFile(apk_path) as archive:
                names = archive.namelist()
                has_container = bool(_container_assets(archive))
        except (zipfile.BadZipFile, OSError):
            return PackerFamily.UNKNOWN
        if has_container and not any(n.endswith(".dex") for n in names if n.startswith("assets/")):
            return self.family
        return PackerFamily.UNKNOWN

    def extract_kdf_pattern(self, so_path: str) -> KDFScheme:
        """Layer 2: myg0N's scheme is fixed; confirmed via JNI trace, not listing walk."""
        return MYG0N_SCHEME

    def recover_seed(self, apk_path: str, scheme: KDFScheme = MYG0N_SCHEME) -> str:
        """Layer 3: stem of the extension-less asset, plus the literal suffix '2'."""
        asset = _container_asset(apk_path)
        if asset is None:
            raise ValueError(f"no myg0N-style container asset found in {apk_path}")
        stem = asset.rsplit("/", 1)[-1]
        return stem + "2"

    def decrypt_asset(self, apk_path: str, seed: str, asset: Optional[str] = None) -> bytes:
        """Run layers 4+5 end to end on the encrypted container."""
        from Crypto.Cipher import AES  # project convention: pycryptodome
        from Crypto.Util.Padding import unpad

        asset = asset or _container_asset(apk_path)
        if asset is None:
            raise ValueError(f"no myg0N-style container asset found in {apk_path}")
        key, iv = derive_key(seed, MYG0N_SCHEME)
        with zipfile.ZipFile(apk_path) as archive:
            ciphertext = archive.read(asset)
        try:
            return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)
        except ValueError as exc:  # wrong length or bad PKCS#5 padding: not a myg0N container
            raise ValueError(f"asset {asset} is not an AES-CBC container: {exc}") from exc

    def unpack(self, apk_path: str) -> Tuple[bytes, Verdict]:
        seed = self.recover_seed(apk_path)
        plaintext = self.decrypt_asset(apk_path, seed)
        return plaintext, verify_unpack(plaintext)
