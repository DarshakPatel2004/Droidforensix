import logging
import re
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

REFLECTION_PATTERNS = [
    re.compile(r'forName\s*\(\s*"([^"]+)"'),
    re.compile(r'Class\.forName\s*\(\s*"([^"]+)"'),
    re.compile(r'getDeclaredMethod\s*\(\s*"([^"]+)"'),
    re.compile(r'getMethod\s*\(\s*"([^"]+)"'),
    re.compile(r'Method\.invoke\s*\(\s*"[^"]*"\s*,\s*"([^"]+)"'),
    re.compile(r'const-string\s+\w+\s*,\s*"([^"]+)"\s*\n\s*invoke-(?:static|virtual)\s+\{[^}]*\},\s*Ljava/lang/Class;->forName'),
]

SENSITIVE_API_MAP = {
    "android.telephony.SmsManager": ["sendTextMessage", "sendMultipartTextMessage"],
    "android.telephony.TelephonyManager": ["getDeviceId", "getSubscriberId", "getSimSerialNumber"],
    "android.accounts.AccountManager": ["getAccounts", "getPassword", "getAuthToken"],
    "android.location.LocationManager": ["getLastKnownLocation", "requestLocationUpdates"],
    "android.content.Context": ["getContentResolver", "startService", "bindService"],
    "java.net.URL": ["openConnection", "openStream"],
    "java.net.Socket": ["connect", "getOutputStream", "getInputStream"],
    "java.lang.Runtime": ["exec", "load", "loadLibrary"],
    "android.app.ActivityManager": ["getRunningAppProcesses", "getMemoryInfo"],
    "android.content.ContentResolver": ["query", "insert", "delete", "update"],
    "android.os.DexClassLoader": [],
    "dalvik.system.DexClassLoader": [],
    "javax.crypto.Cipher": ["getInstance", "init", "doFinal"],
    "android.webkit.WebView": ["loadUrl", "addJavascriptInterface"],
}


def scan_source_for_reflection(source_text: str, file_path: str) -> List[Dict[str, Any]]:
    calls = []
    for pattern in REFLECTION_PATTERNS:
        for match in pattern.finditer(source_text):
            target = match.group(1) if match.lastindex else match.group(0)
            line_num = source_text[:match.start()].count("\n") + 1
            calls.append({
                "target": target,
                "file": file_path,
                "line": line_num,
                "pattern": pattern.pattern[:60],
            })
    return calls


def find_reflective_calls(apk_info: Dict[str, Any]) -> Dict[str, Any]:
    extracted_path = apk_info.get("extracted_path") or apk_info.get("work_dir", "")
    if not extracted_path:
        return {"total_reflective_calls": 0, "reflective_calls": [], "sensitive_targets": []}

    source_dirs = []
    base = Path(extracted_path)
    for candidate in [base / "sources", base / "smali"]:
        if candidate.is_dir():
            source_dirs.append(candidate)

    if not source_dirs:
        return {"total_reflective_calls": 0, "reflective_calls": [], "sensitive_targets": []}

    all_calls = []
    for src_dir in source_dirs:
        for fpath in src_dir.rglob("*.smali"):
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
                all_calls.extend(scan_source_for_reflection(text, str(fpath.relative_to(base))))
            except Exception:
                continue

        for fpath in src_dir.rglob("*.java"):
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
                all_calls.extend(scan_source_for_reflection(text, str(fpath.relative_to(base))))
            except Exception:
                continue

    resolved = resolve_reflection_targets(all_calls)
    return {
        "total_reflective_calls": len(all_calls),
        "reflective_calls": all_calls,
        "sensitive_targets": resolved,
        "total_sensitive": len(resolved),
    }


def resolve_reflection_targets(calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sensitive = []
    for call in calls:
        target = call["target"]
        for api_class, methods in SENSITIVE_API_MAP.items():
            if api_class.lower() in target.lower():
                sensitive.append({
                    **call,
                    "resolved_class": api_class,
                    "sensitive": True,
                })
                break
        else:
            if any(cls in target for cls in ["Class", "Method", "Field", "ClassLoader"]):
                continue
            sensitive.append({
                **call,
                "resolved_class": "unknown",
                "sensitive": False,
            })
    return sensitive
