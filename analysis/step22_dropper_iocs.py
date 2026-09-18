"""
Step 22: Dropper IOC Consolidation

Merges the enrichment steps (19-21) into a dropper-focused IOC set:
  - WebSocket / TCP C2 endpoints
  - Telegram bot tokens and RTDB hosts
  - Firebase API keys, base64-encoded server URLs (BuildConfig pattern)
  - builder licence MACs and subscription windows (payload_config.json)
  - deobfuscated C2 strings from step 21

All extraction is static; nothing is executed or contacted.
"""

import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, List

TG_TOKEN_RE = re.compile(rb"\b(\d{8,10}:[A-Za-z0-9_-]{30,40})\b")
RTDB_RE = re.compile(rb"([a-z0-9][a-z0-9-]{2,30}-default-rtdb(?:\.[a-z0-9.-]+)?)")
FBAPI_RE = re.compile(rb"(AIzaSy[A-Za-z0-9_-]{33})")
WS_RE = re.compile(rb"(wss?://[\w\-.]+(?::\d{2,5})?[/\w]*)")
TCP_URL_RE = re.compile(rb"https?://(\d{1,3}(?:\.\d{1,3}){3})(:\d{2,5})?")
B64URL_RE = re.compile(rb"SERVER_BASE_URL_B64\s*=\s*\"([A-Za-z0-9+/=]{8,120})\"")
LICENCE_MAC_RE = re.compile(rb"messageAuthenticationCode[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/=]{16,32})")
SUB_END_RE = re.compile(rb"subscriptionEndMillis[\"']?\s*[:=]\s*(\d{10,19})")
BUILDER_MACS = {"eVAmHju3UqrVWR56gOMaUQ==": "Zombinder DaaS shared licence"}


def _members(data: bytes):
    import io
    import zipfile
    try:
        z = zipfile.ZipFile(file=io.BytesIO(data))
    except zipfile.BadZipFile:
        return
    for n in z.namelist():
        if n.endswith((".dex", ".json", ".arsc")):
            try:
                yield n, z.read(n)
            except Exception:
                continue


def consolidate(apk_path: str, work_dir: str,
                container_report: Dict[str, Any] = None,
                kdf_report: Dict[str, Any] = None,
                strings_report: Dict[str, Any] = None) -> Dict[str, Any]:
    data = Path(apk_path).read_bytes()

    tg: set = set()
    rtdb: set = set()
    fbapi: set = set()
    ws: set = set()
    tcp_ips: set = set()
    b64_urls: set = set()
    macs: set = set()
    licences: List[Dict[str, Any]] = []

    def scan_blob(blob: bytes):
        tg.update(m.decode() for m in TG_TOKEN_RE.findall(blob))
        rtdb.update(m.decode() for m in RTDB_RE.findall(blob))
        fbapi.update(m.decode() for m in FBAPI_RE.findall(blob))
        ws.update(m.decode() for m in WS_RE.findall(blob))
        tcp_ips.update((m.group(1) + (m.group(2) or b"")).decode()
                       for m in TCP_URL_RE.finditer(blob))
        for m in B64URL_RE.finditer(blob):
            try:
                b64_urls.add(base64.b64decode(m.group(1)).decode("utf-8", "replace"))
            except Exception:
                continue
        macs.update(m.decode() for m in LICENCE_MAC_RE.findall(blob))
        for m in SUB_END_RE.findall(blob):
            ms = int(m)
            if ms < 4_000_000_000_000:
                licences.append({"subscription_end_ms": ms})

    def _scan_nested_zip(path: Path, depth: int = 0):
        """Scan zip members; recurse one level into nested apk/zip members."""
        import io as _io
        import zipfile as _zf
        try:
            zz = _zf.ZipFile(path)
        except Exception:
            return
        for n in zz.namelist():
            try:
                blob = zz.read(n)
            except Exception:
                continue
            if n.endswith((".json", ".dex")):
                scan_blob(blob[:4_000_000])
            elif n.endswith((".apk", ".zip")) and depth < 3 and len(blob) < 60_000_000:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=Path(n).suffix, delete=False) as tf:
                    tf.write(blob)
                    tmp = Path(tf.name)
                try:
                    _scan_nested_zip(tmp, depth + 1)
                finally:
                    tmp.unlink(missing_ok=True)

    for _, blob in _members(data):
        scan_blob(blob)

    # decrypted artifacts from step 20 (recursive: nested stage dirs)
    kdf_dir = Path(work_dir) / "kdf_crack"
    if kdf_dir.exists():
        for f in kdf_dir.rglob("*.json"):
            if f.is_file():
                scan_blob(f.read_bytes())
        for f in list(kdf_dir.rglob("*.zip")) + list(kdf_dir.rglob("*.apk")):
            if f.is_file():
                _scan_nested_zip(f)

    # deobfuscated strings from step 21
    fams = (strings_report or {}).get("families", {})
    dec_strings: List[str] = []
    for fam in ("npstringfog", "xor_callsites"):
        info = fams.get(fam) or {}
        items = info.get("unique_strings") or info.get("strings") or []
        dec_strings.extend(items)
        for s in items:
            scan_blob(s.encode())

    known_builder = sorted({m for m in macs if m in BUILDER_MACS})
    result: Dict[str, Any] = {
        "apk": apk_path,
        "websocket_c2": sorted(ws),
        "http_ip_endpoints": sorted(tcp_ips),
        "telegram_tokens": sorted(tg),
        "firebase_rtdb": sorted(rtdb),
        "firebase_api_keys": sorted(fbapi),
        "base64_server_urls": sorted(b64_urls),
        "licence_macs": sorted(macs),
        "known_builder_match": [
            {"mac": m, "attribution": BUILDER_MACS[m]} for m in known_builder],
        "campaign_windows": licences,
        "deobfuscated_strings_considered": len(dec_strings),
        "container_anomaly": (container_report or {}).get("container_anomaly", False),
    }
    out = Path(work_dir) / "dropper_iocs.json"
    out.write_text(json.dumps(result, indent=2))
    result["output"] = str(out)
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m analysis.step22_dropper_iocs <apk> [work_dir]")
        raise SystemExit(1)
    wd = sys.argv[2] if len(sys.argv) > 2 else "."
    print(json.dumps(consolidate(sys.argv[1], wd), indent=2))
