"""
Step 21: String Deobfuscation

Recovers plaintext from three obfuscation families observed in the wild:
  - NPStringFog: hex literals XOR'd with a short key (class obfuse/NPStringFog)
  - Joom Paranoid: hash-chain indexed CJK chunk strings (DeobfuscatorHelper)
  - Generic XOR call-sites in jadx output: helper.a(new byte[]{...}, new byte[]{...})

jadx is used opportunistically (if installed) to obtain call-site ids/keys;
dex-only fallbacks are provided for NPStringFog key harvesting.
"""

import json
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

HEX_RE = re.compile(r"NPStringFog\.decode\(\"([0-9A-Fa-f]+)\"")
GETSTRING_RE = re.compile(r"getString\((-?\d+)L?\)")
XOR_CALLSITE_RE = re.compile(
    r"\.(\w+)\(\s*new byte\[\]\{([\d,\s\-]+)\}\s*,\s*new byte\[\]\{([\d,\s\-]+)\}\s*\)", re.S)


# ---------------------------------------------------------------------------
# dex helpers
# ---------------------------------------------------------------------------

def _mutf8_decode(raw: bytes) -> str:
    units = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b < 0x80:
            units.append(b)
            i += 1
        elif b >> 5 == 0b110:
            units.append(((b & 0x1F) << 6) | (raw[i + 1] & 0x3F))
            i += 2
        elif b >> 4 == 0b1110:
            units.append(((b & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F))
            i += 3
        else:
            raise ValueError("bad MUTF-8 byte")
    return "".join(chr(u) for u in units)


def dex_strings(data: bytes) -> List[str]:
    n, off = struct.unpack_from("<II", data, 0x38)
    out = []
    for i in range(n):
        p = struct.unpack_from("<I", data, off + i * 4)[0]
        while True:
            b = data[p]
            p += 1
            if not b & 0x80:
                break
        end = data.find(b"\x00", p)
        try:
            out.append(_mutf8_decode(data[p:end]))
        except Exception:
            out.append("")
    return out


HEX_CAND_RE = re.compile(r"[0-9A-Fa-f]{16,}")


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    good = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(b)


def harvest_npstringfog(data: bytes):
    """Recover (key, ciphertexts) for NPStringFog directly from dex bytes:
    candidate keys = short alphanumeric strings from the pool; candidate
    ciphertexts = long hex literals. Pick the key whose trial decodes are
    mostly printable."""
    strs = dex_strings(data)
    ciphertexts = [s for s in strs
                   if len(s) >= 16 and len(s) % 2 == 0 and HEX_CAND_RE.fullmatch(s)]
    if not ciphertexts:
        return None, []
    keyset = {s for s in strs if re.fullmatch(r"[A-Za-z0-9]{3,16}", s or "")}
    # also try well-known defaults first
    ordered = ["itnewpag"] + sorted(keyset)
    best, best_score = None, 0.0
    sample = ciphertexts[:40]
    for key in ordered:
        kb = key.encode()
        scores = []
        for ct in sample:
            b = bytes.fromhex(ct)
            dec = bytes(x ^ kb[i % len(kb)] for i, x in enumerate(b))
            scores.append(_printable_ratio(dec))
        score = sum(scores) / len(scores)
        if score > best_score:
            best, best_score = key, score
        if best_score > 0.97:
            break
    if best and best_score > 0.8:
        return best, ciphertexts
    return None, []


def npstringfog_decode(hexstr: str, key: str) -> str:
    b = bytes.fromhex(hexstr)
    kb = key.encode()
    return bytes(x ^ kb[i % len(kb)] for i, x in enumerate(b)).decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Joom Paranoid
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1
_MASK32 = (1 << 32) - 1


def _rotl_short(s: int, i: int) -> int:
    sext = s - (1 << 16) if s >= (1 << 15) else s
    a = (sext & _MASK32) >> (32 - i)
    b = ((sext & _MASK32) << i) & _MASK32
    return (a | b) & 0xFFFF


def _se16(x: int) -> int:
    return (x | (_MASK64 ^ 0xFFFF)) & _MASK64 if x & 0x8000 else x


def _nxt(j: int) -> int:
    j &= _MASK64
    s = j & 0xFFFF
    s2 = (j >> 16) & 0xFFFF
    t1 = _rotl_short((s + s2) & 0xFFFF, 9)
    sr = (t1 + s) & 0xFFFF
    s3 = s2 ^ s
    a = _se16(_rotl_short(s3, 10))
    b = (_se16(sr) << 16) & _MASK64
    mid = ((a | b) << 16) & _MASK64
    lo_t = (_rotl_short(s, 13) ^ s3) & 0xFFFF
    lo = (lo_t ^ (((s3 & _MASK32) << 5) & 0xFFFF)) & 0xFFFF
    return (mid | _se16(lo)) & _MASK64


def _pseed(j: int) -> int:
    m1 = 7109453100751455733 & _MASK64
    m2 = (-3808689974395783757) & _MASK64
    j &= _MASK64
    j2 = ((j ^ (j >> 33)) * m1) & _MASK64
    j3 = ((j2 ^ (j2 >> 28)) * m2) & _MASK64
    return j3 >> 32


_CHUNK = 8191


def paranoid_get_string(idv: int, chunks: List[str]) -> str:
    idu = idv & _MASK64
    n1 = _nxt(_pseed(idu & 0xFFFFFFFF))
    j2 = (n1 >> 32) & 0xFFFF
    n2 = _nxt(n1)
    i = (((idu >> 32) ^ j2 ^ ((n2 >> 16) & 0xFFFFFFFFFFFF0000)) & _MASK32)
    if i >= (1 << 31):
        i -= 1 << 32

    def getchar(idx: int, state: int) -> int:
        c = ord(chunks[idx // _CHUNK][idx % _CHUNK])
        return ((c << 32) ^ _nxt(state)) & _MASK64

    ch = getchar(i, n2)
    ln = (ch >> 32) & 0xFFFF
    out = []
    for k in range(ln):
        ch = getchar(i + k + 1, ch)
        out.append(chr((ch >> 32) & 0xFFFF))
    return "".join(out)


def load_paranoid_chunks_from_bytes(dex_data: bytes) -> List[str]:
    """Extract chunk rows: giant const-strings in the high Unicode range."""
    rows = []
    for s in dex_strings(dex_data):
        if len(s) >= 2000 and ord(s[0]) >= 0xE000:
            rows.append(s)
    rows.sort(key=len, reverse=True)
    return rows[:4]


# ---------------------------------------------------------------------------
# generic XOR call-site miner over jadx sources
# ---------------------------------------------------------------------------

def mine_xor_callsites(sources_dir: str) -> Dict[str, str]:
    src = Path(sources_dir)
    found: Dict[str, str] = {}
    if not src.exists():
        return found

    def parse(s: str) -> bytes:
        return bytes(int(x) & 0xFF for x in re.findall(r"-?\d+", s))

    def xor(d: bytes, k: bytes) -> bytes:
        return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))

    for f in src.rglob("*.java"):
        try:
            txt = f.read_text(errors="replace")
        except Exception:
            continue
        for m in XOR_CALLSITE_RE.finditer(txt):
            data, key = parse(m.group(2)), parse(m.group(3))
            if not data or not key:
                continue
            dec = xor(data, key).decode("utf-8", "replace")
            if dec.isprintable() and len(dec) > 2:
                found.setdefault(dec, f.name)
    return found


# ---------------------------------------------------------------------------
# pipeline entry
# ---------------------------------------------------------------------------

def deobfuscate_strings(apk_path: str, work_dir: str,
                        sources_dir: Optional[str] = None,
                        primary_dex: Optional[str] = None) -> Dict[str, Any]:
    """Decode NPStringFog (+ optional Paranoid/XOR-call-site) strings.

    apk_path: container holding dexes; primary_dex: member name to focus on.
    sources_dir: jadx output (enables Paranoid id extraction + XOR mining).
    """
    import zipfile

    result: Dict[str, Any] = {"apk": apk_path, "families": {}}
    zf = zipfile.ZipFile(apk_path)
    dex_names = [n for n in zf.namelist() if re.fullmatch(r"classes\d*\.dex", n)]

    # ---- NPStringFog across all dexes ----
    key = None
    decoded: Dict[str, str] = {}
    for dn in ([primary_dex] if primary_dex else dex_names):
        if dn not in zf.namelist():
            continue
        try:
            key, cts = harvest_npstringfog(zf.read(dn))
        except Exception:
            key, cts = None, []
        if key:
            for ct in cts:
                try:
                    decoded.setdefault(npstringfog_decode(ct, key), dn)
                except Exception:
                    continue
            break

    if key and decoded:
        result["families"]["npstringfog"] = {
            "key": key, "unique_strings": sorted(decoded),
            "count": len(decoded)}
    else:
        result["families"]["npstringfog"] = {"key": None,
                                             "note": "no NPStringFog key recovered"}

    # ---- Paranoid via jadx sources (optional) ----
    if sources_dir and primary_dex and primary_dex in zf.namelist():
        src = Path(sources_dir)
        ids: set = set()
        for f in src.rglob("*.java"):
            try:
                txt = f.read_text(errors="replace")
            except Exception:
                continue
            found = GETSTRING_RE.findall(txt)
            if found:
                ids.update(int(x) for x in found)
        if ids:
            chunks = load_paranoid_chunks_from_bytes(zf.read(primary_dex))
            ok = {}
            for cid in sorted(ids):
                for chunk_set in ([chunks[0]] if chunks else []):
                    try:
                        s = paranoid_get_string(cid, [chunk_set])
                        ok[str(cid)] = s
                        break
                    except Exception:
                        continue
            clean = {k: v for k, v in ok.items() if v.isprintable()}
            if clean:
                result["families"]["paranoid"] = {"decoded": clean,
                                                  "count": len(clean)}

    # ---- generic XOR call-sites over jadx output ----
    if sources_dir:
        xor = mine_xor_callsites(sources_dir)
        if xor:
            result["families"]["xor_callsites"] = {"strings": sorted(xor),
                                                   "count": len(xor)}

    out = Path(work_dir) / "deobfuscated_strings.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=1))
    result["output"] = str(out)
    return result


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="String deobfuscation (NPStringFog/Paranoid/XOR)")
    ap.add_argument("apk")
    ap.add_argument("--sources", help="jadx sources dir for call-site mining")
    ap.add_argument("--primary-dex", help="dex containing the obfuscator class")
    ap.add_argument("-o", "--out", default=".")
    args = ap.parse_args()
    res = deobfuscate_strings(args.apk, args.out, args.sources, args.primary_dex)
    fams = res.get("families", {})
    for name, info in fams.items():
        print(f"{name}: {info.get('count', 0)} strings")
