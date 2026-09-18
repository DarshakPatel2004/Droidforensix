import logging
import re
from typing import Dict, List, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?::\d+)?\b')
SOCKET_CALL_RE = re.compile(r'(?:Socket|HttpURLConnection|HttpsURLConnection|OkHttp|Retrofit|Volley)\s*\(')

BENIGN_DOMAINS = {
    "googleapis.com", "google.com", "gstatic.com", "googleadservices.com",
    "googlesyndication.com", "doubleclick.net", "facebook.com", "fbcdn.net",
    "twitter.com", "x.com", "github.com", "stackoverflow.com", "stackoverflow.com",
    "microsoft.com", "live.com", "apple.com", "icloud.com", "amazon.com",
    "amazonaws.com", "cloudfront.net", "amplitude.com", "mixpanel.com",
    "firebaseio.com", "crashlytics.com", "sentry.io", "datadoghq.com",
    "newrelic.com", "segment.io", "adjust.com", "appsflyer.com",
}

C2_PORT_PATTERNS = {8080, 8443, 4444, 1337, 31337, 6666, 6667, 6668, 6669, 9001, 9002}
C2_PATH_PATTERNS = re.compile(r'/(?:gate|cmd|admin|panel|boss|manage|control|shell|upload|fetch|push|sync|report|collect|beacon|ping)\b', re.IGNORECASE)


def extract_endpoints(strings: List[str]) -> List[str]:
    endpoints = []
    for s in strings:
        if not isinstance(s, str):
            continue
        for match in URL_RE.findall(s):
            endpoints.append(match.rstrip("/"))
        for match in IP_RE.findall(s):
            endpoints.append(match)
    return list(set(endpoints))


def classify_endpoint(endpoint: str) -> Dict[str, Any]:
    if endpoint.startswith("http"):
        parsed = urlparse(endpoint)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
    else:
        hostname = endpoint.split(":")[0]
        port_parts = endpoint.split(":")
        port = int(port_parts[1]) if len(port_parts) > 1 and port_parts[1].isdigit() else 80
        path = "/"

    hostname_lower = hostname.lower()
    is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname))

    c2_signals = 0
    if is_ip and not hostname.startswith(("10.", "172.", "192.168.", "127.", "169.254.")):
        c2_signals += 1
    if port in C2_PORT_PATTERNS:
        c2_signals += 1
    if C2_PATH_PATTERNS.search(path):
        c2_signals += 1

    is_benign = any(hostname_lower.endswith("." + bd) or hostname_lower == bd for bd in BENIGN_DOMAINS)
    if is_benign:
        classification = "benign"
        confidence = 0.9
    elif c2_signals >= 2:
        classification = "c2"
        confidence = 0.8 if c2_signals >= 3 else 0.6
    elif c2_signals == 1:
        classification = "suspicious"
        confidence = 0.4
    else:
        classification = "unknown"
        confidence = 0.3

    return {
        "endpoint": endpoint,
        "hostname": hostname,
        "port": port,
        "path": path,
        "is_ip": is_ip,
        "classification": classification,
        "confidence": round(confidence, 2),
        "c2_signals": c2_signals,
    }


def analyze_network_protocols(strings: List[str]) -> Dict[str, Any]:
    endpoints = extract_endpoints(strings)
    classified = [classify_endpoint(ep) for ep in endpoints]
    c2_endpoints = [c for c in classified if c["classification"] == "c2"]
    suspicious = [c for c in classified if c["classification"] == "suspicious"]
    benign = [c for c in classified if c["classification"] == "benign"]

    socket_patterns = [s for s in strings if isinstance(s, str) and SOCKET_CALL_RE.search(s)]

    return {
        "total_endpoints": len(classified),
        "total_c2": len(c2_endpoints),
        "total_suspicious": len(suspicious),
        "total_benign": len(benign),
        "c2_endpoints": c2_endpoints[:50],
        "suspicious_endpoints": suspicious[:50],
        "benign_endpoints": benign[:50],
        "socket_pattern_matches": len(socket_patterns),
    }
