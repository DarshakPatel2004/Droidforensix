"""
Step 19: Container Repair

Detects and repairs tampered APK/ZIP containers used by droppers to break
static tooling:
  - bogus compression-method bytes (e.g. method 6217/14088)
  - raw-stored members hidden behind csize=0 headers
  - members split across the entry and the gap before the next local header
  - zero/garbage CRC fields and spurious encrypted flags

Strategy: walk local headers + parse central directory, carve each member's
data region between consecutive local headers, verify via CRC32 (stored or
inflated), rewrite a clean ZIP.
"""

import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List

EOCD_SIG = b"PK\x05\x06"
LFH_SIG = b"PK\x03\x04"


def _central_directory(data: bytes) -> List[Dict[str, Any]]:
    eocd = data.rfind(EOCD_SIG)
    if eocd < 0:
        return []
    cd_size, cd_off = struct.unpack_from("<II", data, eocd + 12)
    entries: List[Dict[str, Any]] = []
    pos = cd_off
    while pos < cd_off + cd_size and struct.unpack_from("<I", data, pos)[0] == 0x02014b50:
        (_vm, _vn, _flag, _meth, _mt, _md, crc, csize, usize,
         nlen, elen, _clen) = struct.unpack_from("<HHHHHHIIIHHH", data, pos + 4)
        extra = struct.unpack_from("<H", data, pos + 30)[0]
        comm = struct.unpack_from("<H", data, pos + 32)[0]
        lho = struct.unpack_from("<I", data, pos + 42)[0]
        name = data[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        entries.append({"name": name, "crc": crc, "csize": csize, "usize": usize, "lho": lho})
        pos += 46 + nlen + elen + extra + comm
    return entries


def _local_headers(data: bytes) -> List[Dict[str, Any]]:
    heads: List[Dict[str, Any]] = []
    off = 0
    while True:
        i = data.find(LFH_SIG, off)
        if i < 0:
            break
        ver, flag, meth, mt, md, crc, csize, usize, nlen, elen = struct.unpack_from(
            "<HHHHHIIIHH", data, i + 4)
        name = data[i + 30:i + 30 + nlen].decode("utf-8", "replace")
        heads.append({"offset": i, "flag": flag, "method": meth, "crc": crc,
                      "csize": csize, "usize": usize, "name": name,
                      "data_start": i + 30 + nlen + elen})
        off = i + 4
    return heads


def _recover_member(entry: Dict[str, Any], region: bytes) -> bytes:
    """Stored-exact then inflate paths, preferring CRC-verified results."""
    cand = region[: entry["usize"]]
    if len(cand) == entry["usize"] and entry["crc"] and zlib.crc32(cand) == entry["crc"]:
        return cand
    for sz in {entry["csize"], len(region)}:
        if sz <= 0 or sz > len(region):
            continue
        try:
            dec = zlib.decompress(region[:sz], -15)
            if not entry["crc"] or zlib.crc32(dec) == entry["crc"]:
                return dec
        except zlib.error:
            continue
    try:
        dec = zlib.decompress(region[: entry["csize"]], -15) if entry["csize"] else b""
        return dec
    except zlib.error:
        return b""


def analyze_container(apk_path: str) -> Dict[str, Any]:
    """Detect container-tamper markers without rewriting anything."""
    data = Path(apk_path).read_bytes()
    anomalies: List[Dict[str, str]] = []
    heads = _local_headers(data)
    entries = _central_directory(data)

    by_lho = {h["offset"]: h for h in heads}
    for e in entries:
        h = by_lho.get(e["lho"])
        if not h:
            anomalies.append({"member": e["name"], "issue": "missing_local_header"})
            continue
        if e["crc"] == 0 and e["usize"] > 0:
            anomalies.append({"member": e["name"], "issue": "zero_crc"})
        if h["method"] not in (0, 8):
            anomalies.append({"member": e["name"], "issue": f"bogus_method_{h['method']}"})
        if (h["flag"] & 0x1) and e["usize"] > 0:
            anomalies.append({"member": e["name"], "issue": "bogus_encrypted_flag"})

    for j, h in enumerate(heads):
        nxt = heads[j + 1]["offset"] if j + 1 < len(heads) else len(data)
        span = nxt - h["data_start"]
        if h["csize"] == 0 and h["usize"] > 0 and span >= h["usize"]:
            anomalies.append({"member": h["name"], "issue": "split_member_gap_carve"})
        elif h["usize"] > h["csize"] and h["csize"] > 0 and span >= h["usize"]:
            anomalies.append({"member": h["name"], "issue": "member_truncated_gap"})

    return {"container_anomaly": bool(anomalies), "anomalies": anomalies,
            "members": len(entries), "local_headers": len(heads)}


def repair_container(apk_path: str, out_path: str) -> Dict[str, Any]:
    """Carve members per central directory and rewrite a clean ZIP."""
    data = Path(apk_path).read_bytes()
    heads = _local_headers(data)
    entries = _central_directory(data)

    spans: Dict[int, Any] = {}
    for j, h in enumerate(heads):
        nxt = heads[j + 1]["offset"] if j + 1 < len(heads) else None
        spans[h["offset"]] = (h["data_start"], nxt)

    recovered, failed = 0, []
    seen = set()
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for e in entries:
            if e["name"] in seen:
                continue
            span = spans.get(e["lho"])
            blob = b""
            if span and span[1]:
                blob = _recover_member(e, data[span[0]:span[1]])
            if not blob:
                failed.append(e["name"])
                continue
            zi = zipfile.ZipInfo(e["name"], date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zout.writestr(zi, blob)
            seen.add(e["name"])
            recovered += 1

    check = zipfile.ZipFile(out_path).testzip() if recovered else None
    return {"repaired_apk": out_path if recovered else None,
            "members_recovered": recovered, "members_failed": failed,
            "crc_check": "ALL_OK" if check is None else f"BAD:{check}",
            "anomalies": analyze_container(apk_path)["anomalies"]}


def repair_if_needed(apk_path: str, work_dir: str) -> Dict[str, Any]:
    """Analyze; repair only when anomalies are found. Returns combined report."""
    report = analyze_container(apk_path)
    report["apk"] = apk_path
    if report["container_anomaly"]:
        Path(work_dir).mkdir(parents=True, exist_ok=True)
        out = str(Path(work_dir) / (Path(apk_path).stem + "_repaired.apk"))
        rep = repair_container(apk_path, out)
        report.update(rep)
    return report


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m analysis.step19_container_repair <apk> [out.apk]")
        raise SystemExit(1)
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else str(Path(src).with_suffix(".repaired.apk"))
    print(json.dumps(repair_if_needed(src, dst), indent=2))
