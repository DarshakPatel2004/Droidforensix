"""
Tier 1/2/3 C2 classification: replace pattern-matching with context tiers.
- Tier 3: legitimate infrastructure (allowlist) -> conf 0.1, c2_flag False
- Tier 1: tracked C2 via VirusTotal/URLhaus -> conf 0.8-1.0, c2_flag True
- Tier 2: hoster reputation via Censys ASN + AbuseIPDB -> conf 0.4-0.65
- Unknown: conf 0.2, c2_flag False (conservative)
See analysis/step5_allowlists.py for Tier 3 lists.
"""
import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Cloud provider ASNs (legitimate hosting -> Tier 3, not C2)
CLOUD_ASNS = {
    16509,   # AWS
    15169,   # Google
    8075,    # Microsoft / Azure
    13335,   # Cloudflare
    20940,   # Akamai
    54113,   # Fastly
    14618,   # Amazon AES
    8987,    # Amazon EU
    16550,   # Amazon
}

# Bulletproof hoster ASNs (mined from data; expand via Censys/VT calibration)
# Start empty; populated as we observe malware C2 ASNs not in CLOUD_ASNS with high abuse scores.
BULLETPROOF_ASNS = set()

CACHE_DIR = Path(r"D:\DroidForensix\evaluation\c2_analysis")
TIER_CACHE = CACHE_DIR / "tier_cache.json"


def _load_tier_cache() -> dict:
    try:
        if TIER_CACHE.exists():
            return json.loads(TIER_CACHE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"vt": {}, "censys": {}, "abuseipdb": {}}


def _save_tier_cache(cache: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        TIER_CACHE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning("tier cache save failed: %s", e)


def check_vt(domain_or_ip: str, itype: str, cache: dict) -> dict:
    """Query VirusTotal (cached, rate-limit aware). Returns {malicious, found}."""
    key = f"{itype}:{domain_or_ip}"
    if key in cache.get("vt", {}):
        return cache["vt"][key]
    # Lazy import to avoid hard dep
    try:
        import requests
        vt_key = os.environ.get("VT_KEY", "")
        if not vt_key:
            # Try .env via backend config
            try:
                from backend.config import settings
                vt_key = getattr(settings, "VT_KEY", "") or os.environ.get("VT_KEY", "")
            except Exception:
                pass
        if not vt_key:
            return {"found": False, "error": "no_vt_key"}
        if itype == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{domain_or_ip}"
        else:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{domain_or_ip}"
        resp = requests.get(url, headers={"x-apikey": vt_key}, timeout=20)
        if resp.status_code == 404:
            result = {"found": False, "malicious": 0}
        elif resp.status_code == 429:
            result = {"found": False, "error": "rate_limited"}
        elif resp.status_code != 200:
            result = {"found": False, "error": f"http_{resp.status_code}"}
        else:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {"found": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
        cache.setdefault("vt", {})[key] = result
        _save_tier_cache(cache)
        # VT free tier: 4/min -> sleep 16s between live queries
        time.sleep(16)
        return result
    except Exception as e:
        return {"found": False, "error": str(e)[:80]}


def get_asn(ip: str, cache: dict) -> dict:
    """Get ASN via Censys (cached). Returns {asn, provider}."""
    if ip in cache.get("censys", {}):
        return cache["censys"][ip]
    try:
        from backend.censys_enrichment import enrich_ip
        data = enrich_ip(ip) or {}
        result = {"asn": data.get("asn"), "provider": data.get("provider", ""), "country": data.get("country", "")}
        cache.setdefault("censys", {})[ip] = result
        _save_tier_cache(cache)
        return result
    except Exception as e:
        return {"asn": None, "error": str(e)[:80]}


def classify_tier(domain: str | None, ip: str | None, context: dict | None = None, cache: dict | None = None, use_live: bool = True) -> dict:
    """
    Returns {tier, confidence, reason, c2_flag}.
    context: {communication_type, source_location}
    use_live=False -> offline only (Tier3 + static rules, no API calls).
    """
    from analysis.step5_allowlists import is_tier3
    context = context or {}
    cache = cache if cache is not None else _load_tier_cache()
    comm = (context.get("communication_type") or "unknown").lower()

    # Tier 3: allowlist
    if domain and is_tier3(domain):
        return {"tier": 3, "confidence": 0.1, "reason": "legitimate_infrastructure", "c2_flag": False}

    # Tier 1: VT tracker (live only)
    if use_live:
        if domain:
            vt = check_vt(domain, "domain", cache)
            if vt.get("found") and vt.get("malicious", 0) >= 10:
                return {"tier": 1, "confidence": 0.9, "reason": f"vt_malicious_{vt['malicious']}", "c2_flag": True}
        if ip:
            vt = check_vt(ip, "ip", cache)
            if vt.get("found") and vt.get("malicious", 0) >= 10:
                return {"tier": 1, "confidence": 0.9, "reason": f"vt_ip_malicious_{vt['malicious']}", "c2_flag": True}

    # Tier 2: hoster reputation via Censys ASN (live only)
    if use_live and ip:
        asn_info = get_asn(ip, cache)
        asn = asn_info.get("asn")
        if asn in CLOUD_ASNS:
            return {"tier": 3, "confidence": 0.2, "reason": f"cloud_asn_{asn}", "c2_flag": False}
        if asn in BULLETPROOF_ASNS:
            if comm in ("socket", "tcp", "udp"):
                return {"tier": 2, "confidence": 0.65, "reason": f"bulletproof_asn_{asn}_socket", "c2_flag": True}
            return {"tier": 2, "confidence": 0.4, "reason": f"bulletproof_asn_{asn}_string", "c2_flag": False}

    # Default: unknown, conservative
    return {"tier": "unknown", "confidence": 0.2, "reason": "no_signals", "c2_flag": False}
