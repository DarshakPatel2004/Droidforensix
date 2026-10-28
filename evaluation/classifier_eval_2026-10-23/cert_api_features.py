"""Certificate features (self-signed, test-key, signer count) and an extended suspicious-API set.

Certificate features read the APK. API features reuse the DEX strings already in the gap caches.

Usage: cert_api_features.py <out.json> <apk_map.json> <gap_cache.json> [<gap_cache.json> ...]
"""

import concurrent.futures
import json
import sys
from pathlib import Path

EXTRA_API = [
    "SmsManager", "TelephonyManager", "AccountManager", "getAccounts", "chmod", "busybox",
    "KeyguardManager", "ClipboardManager", "setPrimaryClip", "KeyEvent", "takePicture",
    "MediaRecorder", "AudioRecord", "getLastKnownLocation", "Geocoder", "loadUrl",
    "evaluateJavascript", "getPackageInfo", "getApplicationInfo", "startForeground",
    "ACTION_USER_PRESENT", "ACTION_SCREEN_OFF", "DexFile", "sendMultipartTextMessage",
]


def cert_features(apk_path: str) -> dict:
    from androguard.core.apk import APK

    out = {"cert_error": "", "n_signers": 0, "self_signed": 0, "testkey": 0}
    try:
        certs = APK(apk_path).get_certificates()
    except Exception as exc:
        out["cert_error"] = str(exc)[:120]
        return out
    out["n_signers"] = len(certs)
    if certs:
        issuer = certs[0].issuer.human_friendly
        subject = certs[0].subject.human_friendly
        out["self_signed"] = int(issuer == subject)
        lowered = issuer.lower()
        out["testkey"] = int("android debug" in lowered or "test" in lowered)
    return out


def api2(gap_entry: dict) -> dict:
    strings = gap_entry.get("strings", []) or []
    joined = "\n".join(strings)
    out = {f"api2_{name.lower()}": int(name in joined) for name in EXTRA_API}
    out["n_extra_api"] = sum(out.values())
    return out


def extract(args):
    sha, apk_path = args
    return sha, cert_features(apk_path)


def main() -> None:
    out_path = Path(sys.argv[1])
    apk_map = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    gap = {}
    for cache_file in sys.argv[3:]:
        gap.update(json.loads(Path(cache_file).read_text(encoding="utf-8")))
    result = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=8) as pool:
        for sha, feats in pool.map(extract, apk_map.items(), chunksize=4):
            feats.update(api2(gap.get(sha.lower(), {})))
            result[sha.lower()] = feats
    out_path.write_text(json.dumps(result), encoding="utf-8")
    print(f"wrote {len(result)} rows to {out_path}")


if __name__ == "__main__":
    main()
