"""Single definition of when a C2 record counts as corroborated.

A record is corroborated when it is a full URL seen in code, scored at or above
the threshold, carries an endpoint path, and is not on a known ad/vendor/telemetry
host or a non-public IP (analysis/benign_sdk_hosts.json). "Behavior confirmed" is a
stricter tier: the host is also referenced by code that reads a device identifier. Bare domains (fallback records) never
qualify. A path only counts if its last segment looks like a real endpoint: a
truncated prefix such as "/bot" (from "https://api.telegram.org/bot<token>/...")
or a generic segment such as "/api" does not.

Sanity checks in step 7 and the report model both call this function, so they
cannot disagree about what is corroborated.
"""

import ipaddress
import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

CORROBORATION_MIN_CONFIDENCE = 0.8

BENIGN_SDK_HOSTS_FILE = Path(__file__).with_name("benign_sdk_hosts.json")

# Android calls that read a device identifier. A code file that references a host AND calls one of
# these is a sign the app sends device data there (fixed list, not tuned on the gold set).
DEVICE_ID_APIS = ("getdeviceid", "getsubscriberid", "getline1number", "getsimserialnumber",
                  "android_id", "getmacaddress")
MAX_SMALI_FILES = 60000      # bound the scan on huge apps; beyond this the signal is "unknown"
MAX_SMALI_FILE_BYTES = 2 * 1024 * 1024

# Last path segments too generic to identify an endpoint on their own.
GENERIC_PATH_SEGMENTS = frozenset({"bot", "api", "v1", "v2", "rest", "index", "data", "app"})
MIN_ENDPOINT_SEGMENT_LENGTH = 4


def is_endpoint_path(path: Any) -> bool:
    """True when the path ends in a segment specific enough to name an endpoint."""
    if not path or not isinstance(path, str) or path == "/":
        return False
    segments = [s for s in path.split("/") if s]
    if not segments:
        return False
    last = segments[-1].lower()
    if last in GENERIC_PATH_SEGMENTS:
        return False
    return len(last) >= MIN_ENDPOINT_SEGMENT_LENGTH


@lru_cache(maxsize=1)
def _benign_suffixes() -> frozenset:
    """Suffixes from benign_sdk_hosts.json. A missing or broken file raises: no silent empty list."""
    data = json.loads(BENIGN_SDK_HOSTS_FILE.read_text(encoding="utf-8"))
    return frozenset(s.lower() for key, values in data.items() if isinstance(values, list) for s in values)


def record_host(record: Dict[str, Any]) -> str:
    """Hostname of a C2 record (domain, ip, or the host of raw_url), lowercase, no port."""
    host = record.get("domain") or record.get("ip") or ""
    if not host and record.get("raw_url"):
        host = str(record["raw_url"])
    # A value can hold several hosts ("a.example,b.example") or a bracketed fragment; take the first real one.
    first = re.split(r"[,\s]+", str(host).strip())[0].strip("[]")
    if "//" in first or "/" in first:
        first = urlparse(first if "//" in first else "http://" + first).hostname or ""
    return first.split(":")[0].lower().rstrip(".")


def is_benign_sdk_host(host: str) -> bool:
    """True for a known ad/vendor/telemetry/docs host, or a non-public IP (private, CGNAT, loopback)."""
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    return any(host == s or host.endswith("." + s) for s in _benign_suffixes())


def is_corroborated_endpoint(record: Dict[str, Any],
                             min_confidence: float = CORROBORATION_MIN_CONFIDENCE) -> bool:
    """True when a C2 record is a full URL from code with a real endpoint path on a non-vendor host."""
    if record.get("is_fallback"):
        return False
    if (record.get("confidence") or 0) < min_confidence:
        return False
    if is_benign_sdk_host(record_host(record)):
        return False
    return is_endpoint_path(record.get("path"))


def find_device_data_signal(hosts: Iterable[str], apktool_dir: Optional[str]) -> Dict[str, Optional[bool]]:
    """For each host: True if a code file referencing it also calls a device-ID API,
    False if it appears in code without one, None if it never appears (native/dex-only) or the scan was cut short."""
    hosts = {h.lower() for h in hosts if h}
    result: Dict[str, Optional[bool]] = {h: None for h in hosts}
    base = Path(apktool_dir) if apktool_dir else None
    if not hosts or base is None or not base.is_dir():
        return result
    seen_files = 0
    for path in base.rglob("*.smali"):
        seen_files += 1
        if seen_files > MAX_SMALI_FILES:
            logger.warning("Device-data signal: stopped after %d smali files in %s; remaining hosts stay unknown",
                           MAX_SMALI_FILES, base)
            break
        try:
            if path.stat().st_size > MAX_SMALI_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError as exc:
            logger.warning("Device-data signal: cannot read %s: %s", path, exc)
            continue
        present = [h for h in hosts if h in text]
        if not present:
            continue
        has_device_api = any(api in text for api in DEVICE_ID_APIS)
        for h in present:
            result[h] = True if (has_device_api or result[h]) else False
    return result


def annotate_device_data_signal(records: List[Dict[str, Any]], apktool_dir: Optional[str]) -> None:
    """Set record["device_data_signal"] (True/False/None) on each C2 record, in place."""
    signals = find_device_data_signal((record_host(r) for r in records), apktool_dir)
    for record in records:
        record["device_data_signal"] = signals.get(record_host(record))


def is_behavior_confirmed(record: Dict[str, Any]) -> bool:
    """Corroborated endpoint whose host is also referenced by code that reads a device identifier."""
    return is_corroborated_endpoint(record) and record.get("device_data_signal") is True
