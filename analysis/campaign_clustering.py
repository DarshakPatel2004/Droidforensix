"""
Multi-sample attribution clustering: campaign graph over a malware corpus.

Nodes are samples; link-forming edges are code similarity (step17 MinHash)
and shared non-testkey signing certificates. Shared C2 hosts are kept as
supporting evidence annotated onto campaigns rather than edges: ablation
showed C2 links are net negative for purity (ad-SDK residue, shared infra).

Deliberate scope caps: androguard-only static signals (no apktool, no
pipeline changes — this module is read-only and offline). Corrupt APKs
yield partial features with an error note instead of failing the run.

Enhanced with cached features:
- Native library JNI symbols (step13)
- Obfuscation/packing indicators (step8/step10/step11)
- Certificate issuer profiles (cert_profiles.json)
- String entropy/obfuscation clusters (step11)
"""

import hashlib
import ipaddress
import json
import logging
import math
import re
import zipfile
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Bump when an extractor changes so the batch script re-extracts stale rows.
FEATURE_VERSION = 4

# Cache file paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
GAP_FEATURES_CACHE = PROJECT_ROOT / "analysis" / "gap_features_cache.json"
OBFUSCATION_CACHE = PROJECT_ROOT / "analysis" / "obfuscation_cache.json"
CERT_PROFILES_PATH = PROJECT_ROOT / "analysis" / "cert_profiles.json"

# Public AOSP signing keys carry zero attribution value: anyone can sign
# with them, so unrelated families share them (e.g. one testkey covered
# 49 samples across 10+ families in our corpus). Matched on cert subject.
TESTKEY_SUBJECT_MARKERS = ("CN=Android", "Android Debug")

# Ad/analytics SDK + XML-boilerplate hosts seen co-occurring across
# unrelated families. Suffix-matched (subdomains included).
BOILERPLATE_HOST_SUFFIXES = frozenset({
    "airpush.com",
    "admob.com",
    "umeng.com",
    "umsns.com",
    "adwo.com",
    "alipay.com",
    "w3.org",
})


def is_testkey_cert(subject: Optional[str]) -> bool:
    """True for the public AOSP test/debug keys (no attribution value)."""
    return bool(subject) and any(marker in subject for marker in TESTKEY_SUBJECT_MARKERS)


def is_boilerplate_host(value: str) -> bool:
    """Ad-SDK / XML-namespace hosts shared across unrelated families."""
    host = value.lower().rstrip(".")
    return any(host == suffix or host.endswith("." + suffix) for suffix in BOILERPLATE_HOST_SUFFIXES)


# --- Cache loading -----------------------------------------------------------

@lru_cache(maxsize=1)
def _load_gap_features_cache() -> Dict[str, Any]:
    """Load gap_features_cache.json (lean static features)."""
    if GAP_FEATURES_CACHE.exists():
        try:
            with open(GAP_FEATURES_CACHE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed to load gap_features_cache: %s", exc)
    return {}


@lru_cache(maxsize=1)
def _load_obfuscation_cache() -> Dict[str, Any]:
    """Load obfuscation_cache.json (obfuscation/packing indicators)."""
    if OBFUSCATION_CACHE.exists():
        try:
            with open(OBFUSCATION_CACHE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed to load obfuscation_cache: %s", exc)
    return {}


@lru_cache(maxsize=1)
def _load_cert_profiles() -> Dict[str, Any]:
    """Load cert_profiles.json (certificate issuer profiles by family)."""
    if CERT_PROFILES_PATH.exists():
        try:
            with open(CERT_PROFILES_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("profiles", {})
        except Exception as exc:
            logger.warning("Failed to load cert_profiles: %s", exc)
    return {}


try:
    from analysis.step16_certificate_analysis import parse_certificate_from_apk
except ImportError:  # pragma: no cover - importable in repo layout
    parse_certificate_from_apk = None  # type: ignore

try:
    from analysis.step17_family_clustering import MinHash, jaccard_similarity
except ImportError:  # pragma: no cover - importable in repo layout
    MinHash, jaccard_similarity = None, None  # type: ignore


URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'
)

# --- Native library JNI symbol extraction (from step13) ---------------------

def extract_native_jni_symbols(apk_path: str) -> Set[str]:
    """Extract JNI function symbols from .so files in an APK."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        return set()

    import tempfile

    symbols: Set[str] = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".so"):
                    continue
                data = zf.read(name)
                if len(data) > 10 * 1024 * 1024:
                    continue
                with tempfile.NamedTemporaryFile(delete=False, suffix=".so") as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name
                try:
                    with open(tmp_path, "rb") as f:
                        elf = ELFFile(f)
                        for section in elf.iter_sections():
                            if isinstance(section, SymbolTableSection):
                                for sym in section.iter_symbols():
                                    if sym.name and sym.name.startswith("Java_"):
                                        symbols.add(sym.name)
                except Exception as exc:
                    logger.warning("Suppressed error in extract_native_jni_symbols: %s", exc)
                finally:
                    try:
                        import os
                        os.unlink(tmp_path)
                    except OSError:
                        pass
    except (zipfile.BadZipFile, FileNotFoundError, RuntimeError) as exc:
        logger.warning("Suppressed error reading JNI symbols from %s: %s", apk_path, exc)
    return symbols


def get_jni_family_signature(symbols: Set[str]) -> Optional[str]:
    """Map JNI symbols to known family signatures (from family_id.py NATIVE_API_PATTERNS)."""
    # BaseBridge: libandroidterm.so with fork/ioctl/open/close/dup2
    if any("androidterm" in s for s in symbols) or \
       any(s in symbols for s in ["fork", "ioctl", "open", "close", "dup2"]):
        return "BaseBridge"
    
    # DroidKungFu: libnative.so with Java_uk_co_lilhermit_* getprop/runcmd
    if any("uk_co_lilhermit" in s and ("getprop" in s or "runcmd" in s) for s in symbols):
        return "DroidKungFu"
    
    return None


# --- String entropy clustering (from step11) ---------------------------------

BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{20,}=*$')
HEX_PATTERN = re.compile(r'^[0-9A-Fa-f]{16,}$')


def shannon_entropy_str(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def classify_obfuscation_type(s: str) -> str:
    if BASE64_PATTERN.match(s):
        return "base64"
    if HEX_PATTERN.match(s):
        return "hex"
    high_entropy = shannon_entropy_str(s)
    if high_entropy > 6.5:
        return "encrypted_or_packed"
    contains_binary = any(ord(c) < 32 and ord(c) not in (9, 10, 13) for c in s)
    if contains_binary:
        return "binary"
    return "plaintext"


def string_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    set_a, set_b = set(a), set(b)
    if not set_a or not set_b:
        return 0.0
    j = len(set_a & set_b) / len(set_a | set_b)
    return j


def cluster_high_entropy_strings(
    strings: List[str],
    entropy_threshold: float = 5.5,
    similarity_threshold: float = 0.6,
) -> Dict[str, Any]:
    if not strings:
        return {"clusters": [], "total_clusters": 0, "high_entropy_strings": []}
    if not isinstance(strings, list):
        return {"clusters": [], "total_clusters": 0, "high_entropy_strings": []}

    high_entropy = []
    for s in strings:
        if not isinstance(s, str):
            continue
        ent = shannon_entropy_str(s)
        if ent >= entropy_threshold:
            high_entropy.append({
                "value": s[:200],
                "entropy": round(ent, 2),
                "length": len(s),
                "type": classify_obfuscation_type(s),
            })

    clusters = []
    assigned = set()
    for i, a in enumerate(high_entropy):
        if i in assigned:
            continue
        cluster = [high_entropy[i]]
        assigned.add(i)
        for j, b in enumerate(high_entropy):
            if j in assigned:
                continue
            sim = string_similarity(a["value"], b["value"])
            if sim >= similarity_threshold:
                cluster.append(high_entropy[j])
                assigned.add(j)
        if len(cluster) > 1:
            clusters.append({
                "size": len(cluster),
                "avg_entropy": round(sum(m["entropy"] for m in cluster) / len(cluster), 2),
                "dominant_type": max(set(m["type"] for m in cluster),
                                     key=lambda t: sum(1 for m in cluster if m["type"] == t)),
                "members": [m["value"] for m in cluster],
            })

    clusters.sort(key=lambda c: -c["size"])

    return {
        "high_entropy_strings": high_entropy,
        "clusters": clusters,
        "total_clusters": len(clusters),
        "total_high_entropy": len(high_entropy),
    }


# Edge weights.
WEIGHT_CERT = 3
WEIGHT_SHARED_C2 = 2
WEIGHT_CODE_SIM = 2
WEIGHT_JNI = 3           # JNI symbol family match (strong signal)
WEIGHT_OBFUSCATION = 2   # Shared obfuscation/packing profile
WEIGHT_CERT_ISSUER = 2   # Shared certificate issuer profile (HIGH stability only)
WEIGHT_ENTROPY = 1       # Shared high-entropy string clusters
# Require at least 2 agreeing signals (min weight 4) to form an edge.
# Single signals (cert=3, jni=3, cert_issuer=2, code=2) alone are not enough.
LINK_MIN_WEIGHT = 4
MAX_C2_EDGE_BONUS = 4

# Edge-kind labels for ablation (drop-one / single-signal graph variants).
KIND_CERT = "cert"
KIND_C2 = "c2"
KIND_CODE = "code"
KIND_JNI = "jni"
KIND_OBFUSCATION = "obfuscation"
KIND_CERT_ISSUER = "cert_issuer"
KIND_ENTROPY = "entropy"
ALL_KINDS = frozenset({KIND_CERT, KIND_C2, KIND_CODE, KIND_JNI, KIND_OBFUSCATION, KIND_CERT_ISSUER, KIND_ENTROPY})
# Default links: code + cert + JNI + cert_issuer only.
# Obfuscation and entropy are too generic (many samples share packers) - annotation only.
# C2 is also annotation-only (net negative for purity per ablation).
DEFAULT_KINDS = frozenset({KIND_CERT, KIND_CODE, KIND_JNI, KIND_CERT_ISSUER})
# Strict tier: three-signal agreement (weight >= 5)
STRICT_MIN_WEIGHT = 5

MINHASH_THRESHOLD = 0.3  # same as step17 per-sample matching
# A host seen in more than half the corpus is SDK/boilerplate, not infra.
MAX_HOST_CORPUS_FRACTION = 0.5

try:
    from analysis.labels import CATCH_ALL_LABELS as CATCH_ALL_FAMILIES
    from analysis.labels import is_catch_all as _is_catch_all_label
except ImportError:  # pragma: no cover - importable in repo layout
    CATCH_ALL_FAMILIES = frozenset({"unknown", "androidos", "generickd", "gen", "detected"})

    def _is_catch_all_label(family):
        return (family or "").strip().lower() in CATCH_ALL_FAMILIES


# ---------------------------------------------------------------------------
# Feature extraction (one APK -> flat signal dict)
# ---------------------------------------------------------------------------


def sha256_of_file(apk_path: str) -> str:
    """Hex SHA-256 of the APK bytes; doubles as the GT join key."""
    digest = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


VALID_HOST_RE = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$'
)


def is_routable_ip(value: str) -> bool:
    """True for public IPs; drops RFC1918/loopback/test addresses.

    Emulator defaults (10.0.2.2), localhost, and 0.0.0.0 appear in
    unrelated samples and would otherwise forge campaign links.
    """
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def is_campaign_host(value: str) -> bool:
    """Keep plausible C2 hosts; drop SDK boilerplate and junk literals.

    The latin-1 dex scan that feeds this sees XML namespaces
    (schemas.android.com), string fragments, and non-routable IPs that
    co-occur across unrelated families.
    """
    if not value or len(value) > 253:
        return False
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        return False
    try:
        if is_routable_ip(value):
            return True
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    if not VALID_HOST_RE.match(value):
        return False
    if is_boilerplate_host(value):
        return False
    try:
        from analysis.step5_allowlists import is_tier3

        if is_tier3(value):
            return False
    except Exception as exc:
        logger.warning("Suppressed error in is_campaign_host: %s", exc)
    return True


def extract_hosts_from_dex_bytes(raw: bytes) -> Set[str]:
    """Routable C2-candidate hosts from raw classes.dex bytes."""
    text = raw.decode("latin-1", errors="ignore")
    candidates: Set[str] = set()
    for url in URL_RE.findall(text):
        try:
            host = urlparse(url).hostname
        except Exception as exc:
            logger.warning("Suppressed error in extract_hosts_from_dex_bytes: %s", exc)
            continue
        if host:
            candidates.add(host.lower().rstrip("."))
    for ip in IP_RE.findall(text):
        candidates.add(ip)
    return {host for host in candidates if is_campaign_host(host)}


def read_dex_hosts(apk_path: str) -> Set[str]:
    """All C2-candidate hosts across every classes*.dex entry."""
    hosts: Set[str] = set()
    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            base = name.rsplit("/", 1)[-1]
            if base.startswith("classes") and base.endswith(".dex"):
                try:
                    hosts.update(extract_hosts_from_dex_bytes(zf.read(name)))
                except Exception as exc:
                    logger.debug("dex host scan skipped %s: %s", name, exc)
    return hosts


def read_cert_fp(apk_path: str) -> Optional[str]:
    """Signing-cert SHA-256 hex (normalized, no separators).

    Step16 first; it returns None for the PKCS#7 .RSA blobs jarsigner
    emits, so fall back to androguard, which parses all cert sources.
    """
    if parse_certificate_from_apk is not None:
        try:
            cert = parse_certificate_from_apk(apk_path)
            if cert and cert.get("sha256_fingerprint"):
                return str(cert["sha256_fingerprint"]).replace(":", "").replace(" ", "").lower()
        except Exception as exc:
            logger.debug("step16 cert failed for %s: %s", apk_path, exc)
    try:
        from androguard.core.apk import APK

        certs = APK(apk_path).get_certificates()
        if certs:
            raw_fp = certs[0].sha256_fingerprint
            if isinstance(raw_fp, (bytes, bytearray)):
                return bytes(raw_fp).hex().lower()
            # asn1crypto returns space-separated hex ("8C DB ...")
            return str(raw_fp).replace(" ", "").replace(":", "").lower()
    except Exception as exc:
        logger.debug("androguard cert failed for %s: %s", apk_path, exc)
    return None


def read_cert_subject(apk_path: str) -> Optional[str]:
    """RFC4514 subject of the signing cert (None when unparseable)."""
    try:
        from androguard.core.apk import APK

        certs = APK(apk_path).get_certificates()
        if certs:
            return str(certs[0].subject.rfc4514_string())
    except Exception as exc:
        logger.debug("cert subject failed for %s: %s", apk_path, exc)
    return None


def read_cert_issuer(apk_path: str) -> Optional[str]:
    """Issuer string of the signing cert (None when unparseable)."""
    try:
        from androguard.core.apk import APK

        certs = APK(apk_path).get_certificates()
        if certs:
            return str(certs[0].issuer.human_friendly)
    except Exception as exc:
        logger.debug("cert issuer failed for %s: %s", apk_path, exc)
    return None


def read_permissions(apk_path: str) -> List[str]:
    """Manifest permissions via androguard (manifest parse only)."""
    from androguard.core.apk import APK

    return sorted(set(APK(apk_path).get_permissions()))


def read_method_signatures(apk_path: str) -> List[str]:
    """Class->method+proto strings for MinHash (androguard dex parse)."""
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    signatures = []
    for dex_bytes in APK(apk_path).get_all_dex():
        for cls in DEX(dex_bytes).get_classes():
            for method in cls.get_methods():
                signatures.append(
                    f"{method.get_class_name()}->{method.get_name()}"
                    f"{method.get_descriptor()}"
                )
    return signatures


def method_minhash(signatures: List[str]) -> List[int]:
    """Step17 MinHash over method signatures (empty when unavailable)."""
    if not signatures or MinHash is None:
        return []
    minhash = MinHash()
    for signature in signatures:
        minhash.update(signature)
    return list(minhash.hash_values)


def _load_cached_features(sample_id: str) -> Dict[str, Any]:
    """Load all cached features for a sample."""
    gap_cache = _load_gap_features_cache()
    obf_cache = _load_obfuscation_cache()
    _load_cert_profiles()
    
    cached: Dict[str, Any] = {}
    
    # Gap features: strings, class_count, etc.
    gap_entry = gap_cache.get(sample_id, {})
    if gap_entry:
        cached["gap_strings"] = gap_entry.get("strings", [])
        cached["class_count"] = gap_entry.get("class_count", 0)
        cached["method_count"] = gap_entry.get("method_count", 0)
    
    # Obfuscation features
    obf_entry = obf_cache.get(sample_id, {})
    if obf_entry:
        cached["obfuscation_score"] = obf_entry.get("obfuscation_score", 0)
        cached["obfuscation_level"] = obf_entry.get("obfuscation_level", "none")
        cached["obfuscation_indicators"] = obf_entry.get("indicators", {})
        cached["dex_entropy"] = obf_entry.get("dex_entropy", [])
        cached["asset_analysis"] = obf_entry.get("asset_analysis", {})
        cached["native_library_artifacts"] = obf_entry.get("native_library_artifacts", [])
        cached["total_classes"] = obf_entry.get("total_classes", 0)
        cached["total_methods"] = obf_entry.get("total_methods", 0)
        cached["suspicious_native_libs"] = obf_entry.get("suspicious_native_libs", 0)
    
    return cached


def _get_cert_issuer_family_match(issuer: str) -> Optional[str]:
    """Match certificate issuer to family profile."""
    if not issuer:
        return None
    cert_profiles = _load_cert_profiles()
    for family, profile in cert_profiles.items():
        # Only use HIGH stability profiles for linking
        if profile.get("stability") != "HIGH":
            continue
        for pattern in profile.get("issuer_patterns", []):
            if pattern and pattern.lower() in issuer.lower():
                return family
    return None


def extract_sample_features(apk_path: str) -> Dict[str, Any]:
    """Fast static signals for one APK; partial on corrupt inputs.

    Never raises: corrupt APKs return whatever was recoverable plus an
    ``error`` note so the batch run continues.
    """
    features: Dict[str, Any] = {
        "apk_path": apk_path,
        "sample_id": "",
        "feature_version": FEATURE_VERSION,
        "permissions": [],
        "cert_fp": None,
        "cert_subject": None,
        "cert_issuer": None,
        "c2_hosts": [],
        "minhash_values": [],
        "method_count": 0,
        "jni_symbols": [],
        "jni_family": None,
        "obfuscation_score": 0,
        "obfuscation_level": "none",
        "obfuscation_indicators": {},
        "class_count": 0,
        "entropy_clusters": [],
        "error": None,
    }
    try:
        features["sample_id"] = sha256_of_file(apk_path)
    except OSError as exc:
        features["error"] = f"unreadable: {exc}"
        return features

    sample_id = features["sample_id"]
    
    # Load cached features first
    cached = _load_cached_features(sample_id)
    features.update(cached)
    
    # Cert features
    features["cert_fp"] = read_cert_fp(apk_path)
    features["cert_subject"] = read_cert_subject(apk_path)
    features["cert_issuer"] = read_cert_issuer(apk_path)
    features["cert_issuer_family"] = _get_cert_issuer_family_match(features["cert_issuer"])

    try:
        features["c2_hosts"] = sorted(read_dex_hosts(apk_path))
    except Exception as exc:
        features["error"] = f"zip unreadable: {exc}"
        return features

    try:
        features["permissions"] = read_permissions(apk_path)
    except Exception as exc:
        features["error"] = f"manifest parse failed: {type(exc).__name__}"

    # JNI symbols from native libraries
    try:
        jni_symbols = extract_native_jni_symbols(apk_path)
        features["jni_symbols"] = sorted(jni_symbols)
        features["jni_family"] = get_jni_family_signature(jni_symbols)
    except Exception as exc:
        logger.debug("JNI extraction failed for %s: %s", apk_path, exc)

    # MinHash from method signatures
    try:
        signatures = read_method_signatures(apk_path)
        features["method_count"] = len(signatures)
        features["minhash_values"] = method_minhash(signatures)
    except Exception as exc:
        note = f"dex parse failed: {type(exc).__name__}"
        features["error"] = f"{features['error']}; {note}" if features["error"] else note

    # High-entropy string clusters (from step11) - compute from gap strings
    try:
        gap_strings = features.get("gap_strings", [])
        if gap_strings:
            clusters = cluster_high_entropy_strings(gap_strings)
            features["entropy_clusters"] = clusters.get("clusters", [])
    except Exception as exc:
        logger.debug("entropy clustering failed for %s: %s", apk_path, exc)

    return features


# ---------------------------------------------------------------------------
# Graph: nodes=samples, edges=shared attribution signals
# ---------------------------------------------------------------------------


def campaign_hosts(all_hosts: List[Set[str]]) -> Set[str]:
    """Hosts shared by >=2 samples but not corpus-boilerplate (>50%)."""
    counts = Counter(host for hosts in all_hosts for host in hosts)
    total = len(all_hosts)
    return {
        host
        for host, count in counts.items()
        if count >= 2 and count / total <= MAX_HOST_CORPUS_FRACTION
    }


def _obfuscation_profile_match(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Check if two samples share the same obfuscation/packing profile.
    
    Requires: same obfuscation level + at least 2 shared specific indicators
    across indicator categories (e.g., same dynamic_loading class + same crypto_api).
    """
    # Same obfuscation level
    if left.get("obfuscation_level") != right.get("obfuscation_level"):
        return False
    if left.get("obfuscation_level") == "none":
        return False
    
    left_indicators = left.get("obfuscation_indicators", {})
    right_indicators = right.get("obfuscation_indicators", {})
    
    # Only consider list-type indicators that are hashable (strings, not dicts)
    def get_hashable_items(indicators, cat):
        items = indicators.get(cat, [])
        if not isinstance(items, list):
            return set()
        # Filter to only hashable items (strings, numbers)
        return set(item for item in items if isinstance(item, (str, int, float)))
    
    left_keys = set(k for k, v in left_indicators.items() if isinstance(v, list) and v)
    right_keys = set(k for k, v in right_indicators.items() if isinstance(v, list) and v)
    
    # Shared indicator categories
    shared_cats = left_keys & right_keys
    if not shared_cats:
        return False
    
    # Count total shared specific indicators across all shared categories
    total_shared = 0
    for cat in shared_cats:
        left_items = get_hashable_items(left_indicators, cat)
        right_items = get_hashable_items(right_indicators, cat)
        total_shared += len(left_items & right_items)
    
    # Require at least 2 shared specific indicators
    return total_shared >= 2


def _entropy_cluster_match(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Check if two samples share high-entropy string clusters of same type."""
    left_clusters = left.get("entropy_clusters", [])
    right_clusters = right.get("entropy_clusters", [])
    
    if not left_clusters or not right_clusters:
        return False
    
    left_types = set(c.get("dominant_type") for c in left_clusters)
    right_types = set(c.get("dominant_type") for c in right_clusters)
    
    # Shared obfuscation type (e.g., both have "encrypted_or_packed" clusters)
    shared_types = left_types & right_types
    if not shared_types:
        return False
    
    # A shared cluster type is the whole test. The member-overlap loop it used to have
    # could only return True in the same cases, so it was removed (L20).
    return True


def edge_weight(
    left: Dict[str, Any],
    right: Dict[str, Any],
    kept_hosts: Set[str],
    kinds: frozenset = DEFAULT_KINDS,
) -> tuple:
    """(weight, reasons) between two feature dicts.

    ``kinds`` restricts which signals contribute (ablation variants);
    defaults to DEFAULT_KINDS (the signals the pipeline uses).
    """
    weight = 0
    reasons: List[str] = []

    if KIND_CERT in kinds and left.get("cert_fp") and left["cert_fp"] == right.get("cert_fp"):
        if is_testkey_cert(left.get("cert_subject")) or is_testkey_cert(right.get("cert_subject")):
            reasons.append("shared_testkey_ignored")
        else:
            weight += WEIGHT_CERT
            reasons.append("shared_cert")

    if KIND_C2 in kinds:
        shared = (set(left.get("c2_hosts", [])) & set(right.get("c2_hosts", []))) & kept_hosts
        if shared:
            weight += min(WEIGHT_SHARED_C2, MAX_C2_EDGE_BONUS)
            reasons.append(f"shared_c2:{len(shared)}")

    if KIND_CODE in kinds:
        left_hash, right_hash = left.get("minhash_values", []), right.get("minhash_values", [])
        if left_hash and right_hash and jaccard_similarity is not None:
            similarity = jaccard_similarity(left_hash, right_hash)
            if similarity >= MINHASH_THRESHOLD:
                weight += WEIGHT_CODE_SIM
                reasons.append(f"code_sim:{similarity:.2f}")

    # JNI family match (strong signal - native library behavior)
    if KIND_JNI in kinds:
        left_jni_fam = left.get("jni_family")
        right_jni_fam = right.get("jni_family")
        if left_jni_fam and right_jni_fam and left_jni_fam == right_jni_fam:
            weight += WEIGHT_JNI
            reasons.append(f"jni_family:{left_jni_fam}")

    # Obfuscation/packing profile match
    if KIND_OBFUSCATION in kinds:
        if _obfuscation_profile_match(left, right):
            weight += WEIGHT_OBFUSCATION
            left_level = left.get("obfuscation_level", "none")
            reasons.append(f"obfuscation:{left_level}")

    # Certificate issuer family match
    if KIND_CERT_ISSUER in kinds:
        left_issuer_fam = left.get("cert_issuer_family")
        right_issuer_fam = right.get("cert_issuer_family")
        if left_issuer_fam and right_issuer_fam and left_issuer_fam == right_issuer_fam:
            weight += WEIGHT_CERT_ISSUER
            reasons.append(f"cert_issuer:{left_issuer_fam}")

    # High-entropy string cluster match
    if KIND_ENTROPY in kinds:
        if _entropy_cluster_match(left, right):
            weight += WEIGHT_ENTROPY
            reasons.append("entropy_cluster")

    return weight, reasons


def build_campaign_graph(features: List[Dict[str, Any]], kinds: frozenset = DEFAULT_KINDS):
    """Weighted graph; an edge needs weight >= LINK_MIN_WEIGHT.

    Default links (DEFAULT_KINDS) come from: code similarity (MinHash), non-testkey
    shared certs, JNI family match, cert issuer family match. The obfuscation profile
    is not a default kind. Shared C2 and entropy clusters are annotation-only (see
    campaign_evidence).
    ``kinds`` overrides the contributing signals (ablation variants).
    """
    import networkx as nx

    graph = nx.Graph()
    for entry in features:
        graph.add_node(entry["sample_id"], apk_path=entry.get("apk_path", ""))
    kept = campaign_hosts([set(entry.get("c2_hosts", [])) for entry in features])
    for i in range(len(features)):
        for j in range(i + 1, len(features)):
            weight, reasons = edge_weight(features[i], features[j], kept, kinds)
            if weight >= LINK_MIN_WEIGHT:
                graph.add_edge(
                    features[i]["sample_id"],
                    features[j]["sample_id"],
                    weight=weight,
                    reasons=reasons,
                )
    return graph


def detect_campaigns(graph) -> List[Set[str]]:
    """Communities as campaign candidates (modularity, else components)."""
    import networkx as nx

    if graph.number_of_nodes() == 0:
        return []
    if graph.number_of_edges() == 0:
        return [{node} for node in graph.nodes]
    try:
        from networkx.algorithms.community import greedy_modularity_communities

        return [set(c) for c in greedy_modularity_communities(graph, weight="weight")]
    except Exception as exc:
        logger.debug("modularity failed (%s); using components", exc)
        return [set(c) for c in nx.connected_components(graph)]


def campaign_evidence(
    campaigns: List[Set[str]], features: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Annotate each campaign with supporting (non-link-forming) evidence.

    Shared C2 hosts (seen in >=2 members), shared non-testkey certs,
    shared JNI families, shared obfuscation profiles, shared cert issuers,
    and shared entropy clusters are reported per campaign so analysts keep
    the attribution story without letting noisy overlaps forge clusters.
    """
    by_id = {entry["sample_id"]: entry for entry in features}
    annotated = []
    for campaign in campaigns:
        members = sorted(campaign)
        host_counts = Counter(
            host
            for sample_id in members
            for host in (by_id.get(sample_id) or {}).get("c2_hosts", [])
        )
        shared_hosts = sorted(host for host, count in host_counts.items() if count >= 2)
        cert_counts = Counter(
            (by_id.get(sample_id) or {}).get("cert_fp") for sample_id in members
        )
        cert_counts.pop(None, None)
        shared_certs = sorted(fp for fp, count in cert_counts.items() if count >= 2)
        
        # JNI family
        jni_fams = [(by_id.get(s) or {}).get("jni_family") for s in members]
        shared_jni = sorted(set(f for f in jni_fams if f and jni_fams.count(f) >= 2))
        
        # Obfuscation profile
        obf_levels = [(by_id.get(s) or {}).get("obfuscation_level") for s in members]
        shared_obf = sorted(set(l for l in obf_levels if l != "none" and obf_levels.count(l) >= 2))
        
        # Cert issuer family
        issuer_fams = [(by_id.get(s) or {}).get("cert_issuer_family") for s in members]
        shared_issuer = sorted(set(f for f in issuer_fams if f and issuer_fams.count(f) >= 2))
        
        # Entropy cluster types
        entropy_types = []
        for s in members:
            entry = by_id.get(s) or {}
            for cluster in entry.get("entropy_clusters", []):
                entropy_types.append(cluster.get("dominant_type"))
        shared_entropy = sorted(set(t for t in entropy_types if t and entropy_types.count(t) >= 2))
        
        annotated.append(
            {
                "size": len(members),
                "members": members,
                "shared_c2_hosts": shared_hosts,
                "shared_certs": shared_certs,
                "shared_jni_families": shared_jni,
                "shared_obfuscation_levels": shared_obf,
                "shared_cert_issuer_families": shared_issuer,
                "shared_entropy_cluster_types": shared_entropy,
            }
        )
    return sorted(annotated, key=lambda c: -c["size"])


def campaign_vote(
    sample_id: str,
    campaigns: List[Set[str]],
    gt: Dict[str, Dict[str, str]],
    min_support: int = 2,
    min_fraction: float = 0.5,
    high_confidence_only: bool = False,
) -> Optional[Dict[str, Any]]:
    """Leave-one-out majority-family vote for one sample.

    The sample's own label is excluded (no GT leakage: this is kNN-style
    inference from *other* samples' labels). Catch-all families never win.
    Returns {family, support, fraction, campaign_size} or None.
    """
    for campaign in campaigns:
        if sample_id not in campaign:
            continue
        # Communities are disjoint: at most one campaign contains the sample.
        labels = []
        for member in campaign:
            if member == sample_id:
                continue
            entry = gt.get(member)
            if not entry:
                continue
            if high_confidence_only and not is_high_confidence(entry):
                continue
            family = entry.get("family", "unknown")
            if _is_catch_all_label(family):
                continue
            labels.append(family)
        if len(labels) < min_support:
            return None
        top, top_count = Counter(labels).most_common(1)[0]
        # Strict majority: a tie (e.g. 1-1 at min support) must not decide.
        if top_count * 2 <= len(labels):
            return None
        fraction = top_count / len(labels)
        if fraction < min_fraction:
            return None
        return {
            "family": top,
            "support": len(labels),
            "fraction": round(fraction, 4),
            "campaign_size": len(campaign),
        }
    return None


# ---------------------------------------------------------------------------
# Purity vs ground truth
# ---------------------------------------------------------------------------


def load_ground_truth(gt_csv: str) -> Dict[str, Dict[str, str]]:
    """sha256 -> {family, confidence} for malware rows with a file on disk."""
    import csv

    gt: Dict[str, Dict[str, str]] = {}
    with open(gt_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("is_malware") != "yes":
                continue
            sha = (row.get("sha256") or "").strip().lower()
            if sha:
                gt[sha] = {
                    "family": (row.get("family") or "unknown").strip(),
                    "confidence": (row.get("confidence") or "").strip().lower(),
                }
    return gt


def is_high_confidence(entry: Dict[str, str]) -> bool:
    """High-confidence, non-catch-all label (label noise lives elsewhere)."""
    return (
        entry.get("confidence") == "high"
        and not _is_catch_all_label(entry.get("family", ""))
    )


def cluster_purity(
    campaigns: List[Set[str]],
    gt: Dict[str, Dict[str, str]],
    high_confidence_only: bool = False,
) -> Dict[str, Any]:
    """Purity of campaigns vs GT (majority-family fraction, size-weighted).

    Samples without a GT label are ignored. Singletons are reported
    separately: they are trivially pure and would inflate the headline.
    """
    detail = []
    weighted = 0
    counted = 0
    multi_weighted = 0
    multi_counted = 0
    multi_campaigns = 0
    for campaign in campaigns:
        labels = []
        for sample_id in campaign:
            entry = gt.get(sample_id)
            if not entry:
                continue
            if high_confidence_only and not is_high_confidence(entry):
                continue
            labels.append(entry["family"])
        if not labels:
            continue
        top, top_count = Counter(labels).most_common(1)[0]
        purity = top_count / len(labels)
        detail.append(
            {
                "size": len(campaign),
                "labeled": len(labels),
                "majority_family": top,
                "purity": round(purity, 4),
            }
        )
        weighted += purity * len(labels)
        counted += len(labels)
        if len(campaign) > 1:
            multi_weighted += purity * len(labels)
            multi_counted += len(labels)
            multi_campaigns += 1
    return {
        "purity": round(weighted / counted, 4) if counted else 0.0,
        "non_singleton_purity": round(multi_weighted / multi_counted, 4) if multi_counted else 0.0,
        "labeled_samples": counted,
        "multi_sample_campaigns": multi_campaigns,
        "total_campaigns": len(campaigns),
        "coverage": round(multi_counted / counted, 4) if counted else 0.0,
        "per_cluster": sorted(detail, key=lambda d: -d["size"]),
    }


def summarize(
    features: List[Dict[str, Any]], graph, campaigns: List[Set[str]], gt: Dict[str, Any]
) -> Dict[str, Any]:
    """Headline numbers: purity raw + high-confidence, edges, failures."""
    return {
        "samples": len(features),
        "failed": sum(1 for f in features if f.get("error")),
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "purity_all": cluster_purity(campaigns, gt),
        "purity_high_conf": cluster_purity(campaigns, gt, high_confidence_only=True),
    }


def strict_tier_summary(
    features: List[Dict[str, Any]], gt: Dict[str, Any]
) -> Dict[str, Any]:
    """Precision tier: graph rebuilt keeping only two-signal edges.

    Same features, same GT, stricter bar (weight >= STRICT_MIN_WEIGHT, so
    every edge carries at least two agreeing signals). Reported alongside
    the standard tier with its coverage — never alone.
    """
    import networkx as nx

    full = build_campaign_graph(features)
    strict = nx.Graph()
    strict.add_nodes_from(full.nodes(data=True))
    for left, right, data in full.edges(data=True):
        if data.get("weight", 0) >= STRICT_MIN_WEIGHT:
            strict.add_edge(left, right, **data)
    campaigns = detect_campaigns(strict)
    summary = summarize(features, strict, campaigns, gt)
    summary["min_edge_weight"] = STRICT_MIN_WEIGHT
    return summary
