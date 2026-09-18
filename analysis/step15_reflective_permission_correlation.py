"""
Step 15: Reflective Permission Usage Correlation.

Measures permission usage evidenced by reflective invocation only.
A permission used exclusively via direct (non-reflective) calls will read
as unused here — this is a scoping choice, not a defect.
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

PERMISSION_API_MAP = {
    "android.permission.SEND_SMS": ["android.telephony.SmsManager"],
    "android.permission.RECEIVE_SMS": ["android.telephony.SmsManager"],
    "android.permission.READ_SMS": ["android.telephony.SmsManager"],
    "android.permission.INTERNET": ["java.net.URL", "java.net.Socket", "java.net.HttpURLConnection",
                                     "javax.net.ssl.HttpsURLConnection", "android.webkit.WebView"],
    "android.permission.ACCESS_NETWORK_STATE": ["android.net.ConnectivityManager"],
    "android.permission.ACCESS_FINE_LOCATION": ["android.location.LocationManager"],
    "android.permission.ACCESS_COARSE_LOCATION": ["android.location.LocationManager"],
    "android.permission.CAMERA": ["android.hardware.Camera", "androidx.camera"],
    "android.permission.RECORD_AUDIO": ["android.media.MediaRecorder", "android.media.AudioRecord"],
    "android.permission.READ_CONTACTS": ["android.provider.ContactsContract"],
    "android.permission.WRITE_CONTACTS": ["android.provider.ContactsContract"],
    "android.permission.READ_CALL_LOG": ["android.provider.CallLog"],
    "android.permission.READ_PHONE_STATE": ["android.telephony.TelephonyManager"],
    "android.permission.CALL_PHONE": ["android.telephony.TelephonyManager"],
    "android.permission.READ_EXTERNAL_STORAGE": ["android.os.Environment"],
    "android.permission.WRITE_EXTERNAL_STORAGE": ["android.os.Environment"],
    "android.permission.GET_ACCOUNTS": ["android.accounts.AccountManager"],
}


PERMISSION_CATEGORIES = {
    "sms": {"SEND_SMS", "RECEIVE_SMS", "READ_SMS"},
    "phone": {"CALL_PHONE", "READ_PHONE_STATE", "READ_CALL_LOG", "WRITE_CALL_LOG",
              "ADD_VOICEMAIL", "USE_SIP", "READ_PRECISE_PHONE_STATE"},
    "location": {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"},
    "camera": {"CAMERA"},
    "microphone": {"RECORD_AUDIO"},
    "contacts": {"READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"},
    "storage": {"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
                "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO"},
    "network": {"INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE",
                "BLUETOOTH", "BLUETOOTH_ADMIN"},
    "calendar": {"READ_CALENDAR", "WRITE_CALENDAR"},
    "sensors": {"BODY_SENSORS", "ACTIVITY_RECOGNITION"},
}


def classify_permission_category(permission: str) -> str:
    short = permission.split(".")[-1]
    for category, perms in PERMISSION_CATEGORIES.items():
        if short in perms:
            return category
    return "other"


def correlate_reflective_permission_usage(
    declared_permissions: List[str],
    reflective_calls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    used_permissions = []
    unused_permissions = []

    for perm in declared_permissions:
        api_classes = PERMISSION_API_MAP.get(perm, [])
        if not api_classes:
            used = False
        else:
            used = any(
                any(api_class.lower() in str(call.get("resolved_class", "")).lower()
                    for api_class in api_classes)
                for call in reflective_calls
            )

        entry = {
            "permission": perm,
            "short": perm.split(".")[-1],
            "category": classify_permission_category(perm),
            "used_reflectively": used,
        }
        if used:
            used_permissions.append(entry)
        else:
            unused_permissions.append(entry)

    summary = {}
    for perm in used_permissions + unused_permissions:
        cat = perm["category"]
        summary.setdefault(cat, {"total": 0, "used_reflectively": 0})
        summary[cat]["total"] += 1
        if perm["used_reflectively"]:
            summary[cat]["used_reflectively"] += 1

    return {
        "total_permissions": len(declared_permissions),
        "used_permissions": used_permissions,
        "unused_permissions": unused_permissions,
        "total_used": len(used_permissions),
        "total_unused": len(unused_permissions),
        "usage_ratio": round(len(used_permissions) / len(declared_permissions), 2) if declared_permissions else 0.0,
        "category_summary": summary,
    }
