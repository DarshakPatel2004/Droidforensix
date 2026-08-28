"""
Step 20: Payload KDF Cracking

Recovers Zombinder-family encrypted payloads without execution:
  - gen-1 KDF: seed = <asset>+"2", KEY=SHA1(seed)[:16], IV=SHA256(seed)[:16]
  - gen-2 KDF: seed = <asset>+"1" (top-level) or bare basename (subdir asset),
               KEY=SHA1(seed)[:16], IV=zeros
  - runtime-keyed inner assets: basename+"1", zero IV (RTO dataQpoJzkbmfX scheme)
  - brute-force matrix fallback: seeds {name, name+0..9}, key/IV permutations

Plaintext is fingerprinted by magic (ZIP/DEX/ELF/GZIP/JSON/TTF) and PKCS#7
padding validity; decrypted ZIP/APK members are recursed up to max_depth.
"""

import hashlib
import io
import json
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from Cryptodome.Cipher import AES

MAX_DEPTH = 3

MAGICS = [
    (b"PK\x03\x04", "zip"),
    (b"dex\n", "dex"),
    (b"\x7fELF", "elf"),
    (b"\x1f\x8b", "gzip"),
    (b"{", "json"),
    (b"\x00\x01\x00\x00", "ttf"),
]


def _magic(pt: bytes) -> Optional[str]:
    for sig, label in MAGICS:
        if pt.startswith(sig):
            return label
    return None


def _pkcs7_strip(pt: bytes) -> bytes:
    if not pt:
        return pt
    p = pt[-1]
    if 1 <= p <= 16 and pt[-p:] == bytes([p]) * p:
        return pt[:-p]
    return pt


def _kdf_variants(seed: str):
    """Yield (label, key, iv) tuples for known KDF shapes."""
    sb = seed.encode()
    yield ("gen1_sha1key_sha256iv", hashlib.sha1(sb).digest()[:16],
           hashlib.sha256(sb).digest()[:16])
    yield ("gen2_sha1key_zeroiv", hashlib.sha1(sb).digest()[:16], b"\x00" * 16)
    yield ("sha256key_zeroiv", hashlib.sha256(sb).digest()[:16], b"\x00" * 16)
    yield ("sha1key_sha1iv", hashlib.sha1(sb).digest()[:16],
           hashlib.sha1(sb).digest()[:16])


def decrypt_blob(data: bytes, seed: str, kdf: str) -> Any:
    """Decrypt with a named KDF variant; return (plaintext, kind) or None.
    A hit requires a known magic AND valid PKCS#7 padding (all shipped
    payloads are padded; this kills chance matches)."""
    for label, key, iv in _kdf_variants(seed):
        if label != kdf:
            continue
        if len(data) % 16:
            return None
        try:
            pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
        except ValueError:
            return None
        kind = _magic(pt)
        if not kind:
            return None
        p = pt[-1]
        pad_ok = 1 <= p <= 16 and pt[-p:] == bytes([p]) * p
        if not pad_ok:
            return None
        return _pkcs7_strip(pt), kind
    return None


def crack_asset(data: bytes, asset_name: str, subdir: bool = False) -> Dict[str, Any]:
    """Try the full seed/KDF matrix on one encrypted blob."""
    base = Path(asset_name).name
    seeds = [base + s for s in ("2", "1", "")] + [base + chr(c) for c in range(48, 58)]
    if subdir:
        seeds = [base] + [base + s for s in ("1", "2")] + [base + chr(c) for c in range(48, 58)]
    tried = []
    for seed in seeds:
        for label, _, _ in _kdf_variants(seed):
            tried.append(f"{seed}|{label}")
            res = decrypt_blob(data, seed, label)
            if res:
                return {"seed": seed, "kdf": label, "plaintext": res[0], "kind": res[1]}
    return {"error": "no_kdf_hit", "tried": len(tried)}


def _members(container: bytes):
    """Yield (name, bytes) for zip members using tolerant reads."""
    try:
        z = zipfile.ZipFile(file=io.BytesIO(container))
        for n in z.namelist():
            if n.endswith("/"):
                continue
            try:
                yield n, z.read(n)
            except Exception:
                yield n, b""
    except zipfile.BadZipFile:
        return


def _is_zip(pt: bytes) -> bool:
    return pt[:4] == b"PK\x03\x04"


def crack_apk(apk_path: str, out_dir: str, depth: int = 0,
              prefix: str = "") -> List[Dict[str, Any]]:
    """Enumerate assets of an APK/ZIP and attempt KDF recovery recursively."""
    results: List[Dict[str, Any]] = []
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = Path(apk_path).read_bytes()

    for name, blob in list(_members(data)):
        rel = name.split("assets/")[-1] if "assets/" in name else name
        if not blob or len(blob) < 64:
            continue
        if name.endswith((".png", ".webp", ".jpg", ".gif")) or "dexopt/" in name:
            continue
        kind = _magic(blob[:4].ljust(4, b"\0"))
        if kind:
            # plaintext member: recurse into nested containers
            if _is_zip(blob) and depth < MAX_DEPTH:
                tag = f"{prefix}{rel}"
                sub_out = out / ("unpacked_" + tag.replace("/", "_"))
                results.extend(crack_apk_bytes(blob, str(sub_out), depth + 1,
                                               prefix=tag + "!"))
            continue
        if len(blob) % 16:
            continue
        if name.startswith(("res/", "META-INF/", "lib/")):
            continue  # dropper payloads ship under assets/ or at root
        res = crack_asset(blob, rel, subdir="/" in rel.strip("assets/"))
        if "seed" not in res:
            continue
        tag = f"{prefix}{rel}"
        rec = {"source": apk_path, "member": name, "seed": res["seed"],
               "kdf": res["kdf"], "kind": res["kind"], "size": len(res["plaintext"])}
        suffix = {"zip": ".zip", "dex": ".dex", "elf": ".so", "json": ".json",
                  "ttf": ".ttf", "gzip": ".gz"}.get(res["kind"], ".bin")
        out_file = out / (tag.replace("/", "_").replace("\\", "_") + suffix)
        out_file.write_bytes(res["plaintext"])
        rec["decrypted_path"] = str(out_file)

        # recurse into decrypted containers
        if res["kind"] == "zip" and depth < MAX_DEPTH:
            try:
                inner = zipfile.ZipFile(file=io.BytesIO(res["plaintext"]))
                rec["crc_ok"] = inner.testzip() is None
            except (zipfile.BadZipFile, zlib.error):
                rec["crc_ok"] = False
            if rec.get("crc_ok") and depth + 1 <= MAX_DEPTH:
                sub_tag = tag.replace("/", "_")
                results.extend(crack_apk(str(out_file), str(out / ("stage_" + sub_tag)),
                                         depth + 1, prefix=tag + "!"))
        results.append(rec)
    return results


def crack_apk_bytes(blob: bytes, out_dir: str, depth: int,
                    prefix: str = "") -> List[Dict[str, Any]]:
    """Same as crack_apk but for in-memory container bytes."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tf:
        tf.write(blob)
        tmp = tf.name
    try:
        return crack_apk(tmp, out_dir, depth, prefix)
    finally:
        Path(tmp).unlink(missing_ok=True)


def crack_payload_kdfs(apk_path: str, work_dir: str) -> Dict[str, Any]:
    """Pipeline entry point. Writes cracked payloads under work_dir/kdf_crack/."""
    out_dir = Path(work_dir) / "kdf_crack"
    results = crack_apk(apk_path, str(out_dir))
    summary = {
        "apk": apk_path,
        "assets_cracked": sum(1 for r in results if r.get("seed")),
        "cracks": [{k: v for k, v in r.items() if k != "plaintext"} for r in results],
        "output_dir": str(out_dir),
    }
    (out_dir / "kdf_results.json").write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Zombinder KDF payload cracker")
    ap.add_argument("input", help="APK / zip to crack")
    ap.add_argument("-o", "--out", default="kdf_out")
    args = ap.parse_args()
    print(json.dumps(crack_payload_kdfs(args.input, args.out), indent=2))
