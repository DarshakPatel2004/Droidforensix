"""
Step 16: APK Signing & Certificate Analysis.

Extracts META-INF/MANIFEST.MF + CERT.RSA from APK ZIP.
Parses certificate fields (issuer, subject, validity, fingerprint),
checks against known-bad certificate databases,
flags self-signed vs organization-signed.
"""

import hashlib
import json
import logging
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_CERT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "known_bad_certificates.json"

_cert_cache: Optional[Dict[str, str]] = None

SUSPICIOUS_ISSUERS = [
    "CN=Android Debug",
    "CN=Android Debug Key",
    "CN=Android Debuggable",
]


def load_known_bad_certs(path: Optional[str] = None) -> Dict[str, str]:
    global _cert_cache
    load_path = Path(path) if path else DEFAULT_CERT_DB_PATH
    if not load_path.exists():
        _cert_cache = {}
        logger.warning("Known-bad cert DB not found at %s", load_path)
        return {}
    try:
        with open(load_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        certs = {}
        for entry in data.get("certificates", []):
            fp = entry.get("sha256_fingerprint", "")
            if fp:
                certs[fp] = entry.get("family", "unknown")
        _cert_cache = certs
        logger.info("Loaded %d known-bad certificates from %s", len(certs), load_path)
        return certs
    except Exception as e:
        _cert_cache = {}
        logger.error("Failed to load known-bad cert DB: %s", e)
        return {}


def get_known_bad_certs() -> Dict[str, str]:
    if _cert_cache is None:
        load_known_bad_certs()
    return _cert_cache if _cert_cache is not None else {}


def add_known_bad_cert(fingerprint: str, family: str, source: str = "manual", path: Optional[str] = None) -> None:
    certs = get_known_bad_certs()
    certs[fingerprint] = family
    save_path = Path(path) if path else DEFAULT_CERT_DB_PATH
    if save_path.exists():
        with open(save_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {
            "schema_version": "1.0",
            "description": "Known-bad Android code signing certificates",
            "sources": [source],
            "last_updated": datetime.now().strftime("%Y-%m-%d"),
            "certificates": [],
            "suspicious_issuers": SUSPICIOUS_ISSUERS,
        }
    existing = [c for c in data.get("certificates", []) if c.get("sha256_fingerprint") != fingerprint]
    existing.append({
        "sha256_fingerprint": fingerprint,
        "family": family,
        "source": source,
        "notes": "",
    })
    data["certificates"] = existing
    data["last_updated"] = datetime.now().strftime("%Y-%m-%d")
    if source not in data.get("sources", []):
        data.setdefault("sources", []).append(source)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def parse_certificate_from_apk(apk_path: str) -> Optional[Dict[str, Any]]:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            cert_files = [n for n in zf.namelist()
                          if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]
            if not cert_files:
                return None
            cert_data = zf.read(cert_files[0])
    except Exception:
        return None

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        fingerprint = cert.fingerprint(hashes.SHA256()).hex(":")
        not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)
        not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)

        is_self_signed = subject == issuer
        is_debug = "Android Debug" in subject or "Android Debug" in issuer
        days_valid = (cert.not_valid_after_utc - cert.not_valid_before_utc).days if hasattr(cert, "not_valid_after_utc") else 0

        return {
            "subject": subject,
            "issuer": issuer,
            "sha256_fingerprint": fingerprint,
            "not_before": str(not_before),
            "not_after": str(not_after),
            "is_self_signed": is_self_signed,
            "is_debug": is_debug,
            "days_valid": days_valid,
            "serial_number": str(cert.serial_number),
        }
    except ImportError:
        return None
    except Exception as e:
        logger.debug("Certificate parse failed: %s", e)
        return None


def check_known_bad_certificate(fingerprint: str) -> Dict[str, Any]:
    certs = get_known_bad_certs()
    if fingerprint in certs:
        return {
            "known_bad": True,
            "family": certs[fingerprint],
            "source": "known_malicious_cert_db",
        }
    return {"known_bad": False}


def analyze_certificate(apk_path: str) -> Dict[str, Any]:
    if not apk_path or not Path(apk_path).exists():
        return {"certificate_found": False, "error": "APK path not provided or does not exist"}

    cert_info = parse_certificate_from_apk(apk_path)
    if not cert_info:
        return {"certificate_found": False, "error": "No certificate found in APK"}

    bad_check = check_known_bad_certificate(cert_info.get("sha256_fingerprint", ""))
    suspicious_issuer = any(
        si in cert_info.get("issuer", "") for si in SUSPICIOUS_ISSUERS
    )

    return {
        "certificate_found": True,
        "certificate": cert_info,
        "known_bad": bad_check["known_bad"],
        "known_bad_family": bad_check.get("family"),
        "suspicious_issuer": suspicious_issuer,
        "warnings": [],
    }
