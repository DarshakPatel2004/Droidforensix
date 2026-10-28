"""Extra static features from the literature (Drebin manifest sets, suspicious API names, packer signals).

Manifest and archive features come from the APK directly. API-name features are matched against
the DEX string set already held in the gap feature cache, so no DEX is re-parsed here.

Usage: extra_features.py <out.json> <apk_map.json> <gap_cache.json> [<gap_cache.json> ...]
  apk_map.json: {sha256: apk_path}
"""

import concurrent.futures
import json
import math
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Suspicious / restricted API names from the Drebin feature paper, plus common loader and crypto calls.
SUSPICIOUS_API = [
    "sendTextMessage", "getDeviceId", "getSubscriberId", "getLine1Number", "getSimSerialNumber",
    "Runtime", "exec", "loadLibrary", "DexClassLoader", "InMemoryDexClassLoader", "PathClassLoader",
    "Cipher", "SecretKeySpec", "setComponentEnabledSetting", "abortBroadcast", "getInstalledPackages",
    "getRunningTasks", "requestLocationUpdates", "HttpURLConnection", "addJavascriptInterface",
    "performGlobalAction", "lockNow", "getWifiState", "setWifiEnabled", "getCellLocation",
    "openFileOutput", "getExternalStorageDirectory", "startActivityForResult", "PackageInstaller",
    "ProcessBuilder", "Base64",
]
LOADER_STRINGS = {"DexClassLoader", "InMemoryDexClassLoader", "PathClassLoader", "loadDex"}


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def manifest_features(apk_path: str) -> dict:
    from androguard.core.apk import APK

    out = {"manifest_error": ""}
    try:
        root = APK(apk_path).get_android_manifest_xml()
    except Exception as exc:  # manifest may be unparseable in packed APKs
        out["manifest_error"] = str(exc)[:120]
        return out
    if root is None:  # androguard returns None when the manifest cannot be decoded
        out["manifest_error"] = "manifest not decodable"
        return out
    for tag in ["activity", "service", "receiver", "provider"]:
        elems = root.findall(f".//{tag}")
        out[f"n_{tag}"] = len(elems)
        out[f"n_exported_{tag}"] = sum(1 for e in elems if e.get(f"{ANDROID_NS}exported") == "true")
    boot = 0
    for rcv in root.findall(".//receiver"):
        actions = [a.get(f"{ANDROID_NS}name", "") for a in rcv.iter("action")]
        if any("BOOT_COMPLETED" in a for a in actions):
            boot += 1
    out["n_boot_receivers"] = boot
    out["n_uses_feature"] = len(root.findall(".//uses-feature"))
    out["n_intent_filters"] = len(root.findall(".//intent-filter"))
    return out


def archive_features(apk_path: str) -> dict:
    out = {"n_dex_files": 0, "n_asset_files": 0, "n_lib_files": 0,
           "max_asset_entropy": 0.0, "max_lib_entropy": 0.0, "max_dex_entropy": 0.0}
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for info in zf.infolist():
                name = info.filename
                if name.endswith(".dex"):
                    out["n_dex_files"] += 1
                    key = "max_dex_entropy"
                elif name.startswith("assets/"):
                    out["n_asset_files"] += 1
                    key = "max_asset_entropy"
                elif name.startswith("lib/") and name.endswith(".so"):
                    out["n_lib_files"] += 1
                    key = "max_lib_entropy"
                else:
                    continue
                if info.file_size > 0:
                    out[key] = max(out[key], round(shannon(zf.read(name)), 4))
    except Exception as exc:
        out["archive_error"] = str(exc)[:120]
    return out


def api_features(gap_entry: dict) -> dict:
    strings = gap_entry.get("strings", []) or []
    joined = "\n".join(strings)
    out = {f"api_{name.lower()}": int(name in joined) for name in SUSPICIOUS_API}
    out["n_suspicious_api"] = sum(out.values())
    out["has_loader"] = int(any(s in joined for s in LOADER_STRINGS))
    return out


def extract(args: tuple) -> tuple:
    sha, apk_path = args
    return sha, {**manifest_features(apk_path), **archive_features(apk_path)}


def main() -> None:
    out_path = Path(sys.argv[1])
    apk_map = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    gap = {}
    for cache_file in sys.argv[3:]:
        gap.update(json.loads(Path(cache_file).read_text(encoding="utf-8")))

    result = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=8) as pool:
        for sha, feats in pool.map(extract, apk_map.items(), chunksize=4):
            entry = gap.get(sha.lower(), {})
            feats.update(api_features(entry))
            result[sha.lower()] = feats
    out_path.write_text(json.dumps(result), encoding="utf-8")
    print(f"wrote {len(result)} rows to {out_path}")


if __name__ == "__main__":
    main()
