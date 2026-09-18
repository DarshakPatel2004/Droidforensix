"""
Censys Platform API v3 enrichment for DroidForensix.

Bearer-token auth against `/v3/global/asset/host/{ip}`. Returns ASN,
provider (whois org), geolocation, service ports, DNS reverse names,
and current TLS certificate data per service.

Two entry points:
  enrich_ip(ip)           — single IP, synchronous (for the live pipeline)
  batch_enrich(ips)       — many IPs, async with global rate throttle (for backfill)

Results are cached locally so the live pipeline never re-queries the same IP.
"""

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from dotenv import load_dotenv

_load_dotenv_path = Path(__file__).resolve().parent.parent / ".env"
if _load_dotenv_path.exists():
    load_dotenv(_load_dotenv_path)

from backend.config import settings

logger = logging.getLogger(__name__)

CENSYS_TOKEN = os.environ.get("CENSYS_TOKEN", "")
CENSYS_API_BASE = os.environ.get("CENSYS_API_BASE", "https://api.platform.censys.io/v3")
CENSYS_ORG_ID = os.environ.get("CENSYS_ORG_ID", "")

CACHE_PATH = settings.WORK_DIR / "censys_cache.json"
MAX_CONCURRENT = 3
REQUEST_TIMEOUT = 20
RATE_LIMIT_DELAY = 0.6  # seconds between requests to stay under rate cap


def _load_cache() -> Dict[str, Any]:
    if CACHE_PATH.exists():
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            logger.debug("Failed to load Censys cache")
    return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception as exc:
        logger.warning("Failed to write Censys cache: %s", exc)


def _headers() -> Dict[str, str]:
    hdrs = {
        "Authorization": f"Bearer {CENSYS_TOKEN}",
        "Accept": "application/json",
    }
    if CENSYS_ORG_ID:
        hdrs["X-Organization-ID"] = CENSYS_ORG_ID
    return hdrs


def _extract(ip: str, data: dict) -> dict:
    resource = data.get("result", {}).get("resource", {})
    asys = resource.get("autonomous_system") or {}
    loc = resource.get("location") or {}
    coords = loc.get("coordinates") or {}
    whois_org = resource.get("whois", {}).get("organization") or {}
    services_raw = resource.get("services") or []
    dns_data = resource.get("dns") or {}
    dns_names = dns_data.get("names") or []

    services = []
    certs = []
    for s in services_raw:
        svc = {
            "port": s.get("port"),
            "protocol": s.get("protocol"),
            "transport": s.get("transport_protocol"),
        }
        services.append(svc)
        if "cert" in s:
            c = s["cert"]
            parsed = c.get("parsed") or {}
            vp = parsed.get("validity_period") or {}
            certs.append({
                "port": s.get("port"),
                "fingerprint_sha256": c.get("fingerprint_sha256"),
                "subject_dn": parsed.get("subject_dn"),
                "issuer_dn": parsed.get("issuer_dn"),
                "not_before": vp.get("not_before"),
                "not_after": vp.get("not_after"),
                "names": c.get("names") or [],
                "validation_level": c.get("validation_level"),
            })

    return {
        "ip": ip,
        "asn": asys.get("asn"),
        "asn_description": asys.get("description", ""),
        "asn_name": asys.get("name", ""),
        "asn_country_code": asys.get("country_code", ""),
        "provider": whois_org.get("name", ""),
        "country": loc.get("country", ""),
        "country_code": loc.get("country_code", ""),
        "city": loc.get("city", ""),
        "province": loc.get("province", ""),
        "latitude": coords.get("latitude"),
        "longitude": coords.get("longitude"),
        "services": services,
        "dns_names": dns_names,
        "certs": certs,
        "_enriched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _is_retryable(status: int) -> bool:
    """429 (rate-limit) and 5xx are retryable.  4xx (except 429) are not."""
    return status == 429 or status >= 500


def _error_result(ip: str, msg: str) -> dict:
    return {
        "ip": ip,
        "_error": str(msg)[:120],
        "_enriched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def enrich_ip(ip: str) -> Optional[Dict[str, Any]]:
    """Synchronous single-IP enrichment with retry+backoff.  Uses cache if available."""
    cache = _load_cache()
    if ip in cache:
        return cache[ip]

    import requests
    url = f"{CENSYS_API_BASE}/global/asset/host/{ip}"
    last_exc = None
    for attempt in range(4):
        try:
            resp = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
            if resp.status_code == 404:
                result = _error_result(ip, "not_found")
                cache[ip] = result
                _save_cache(cache)
                return result
            if _is_retryable(resp.status_code) and attempt < 3:
                wait = 2.0 ** attempt
                logger.info("Retryable %d on %s, retry %d in %.1fs", resp.status_code, ip, attempt + 1, wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            data = resp.json()
            result = _extract(ip, data)
            cache[ip] = result
            _save_cache(cache)
            return result
        except Exception as exc:
            last_exc = exc
            if not hasattr(exc, 'response') or _is_retryable(getattr(exc.response, 'status_code', 0)):
                if attempt < 3:
                    wait = 2.0 ** attempt
                    time.sleep(wait)
                    continue
            break

    logger.warning("Censys enrich_ip(%s) failed: %s", ip, last_exc)
    result = _error_result(ip, last_exc)
    cache[ip] = result
    _save_cache(cache)
    return result


async def _query_one(session: aiohttp.ClientSession, sem: asyncio.Semaphore,
                     ip: str, cache: dict) -> dict:
    if ip in cache:
        return cache[ip]

    async with sem:
        url = f"{CENSYS_API_BASE}/global/asset/host/{ip}"
        last_exc = None
        for attempt in range(4):
            try:
                async with session.get(url, headers=_headers(),
                                       timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as resp:
                    if resp.status == 404:
                        result = _error_result(ip, "not_found")
                        cache[ip] = result
                        return result
                    if _is_retryable(resp.status) and attempt < 3:
                        wait = 2.0 ** attempt
                        logger.info("Retryable %d on %s, retry %d in %.1fs", resp.status, ip, attempt + 1, wait)
                        await asyncio.sleep(wait)
                        continue
                    resp.raise_for_status()
                    data = await resp.json()
                    result = _extract(ip, data)
                    cache[ip] = result
                    return result
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_exc = exc
                resp_obj = getattr(exc, 'status', None) or getattr(exc, 'code', None)
                is_retry = _is_retryable(resp_obj) if resp_obj else attempt < 3
                if is_retry and attempt < 3:
                    wait = 2.0 ** attempt
                    await asyncio.sleep(wait)
                    continue
                break

        logger.warning("Censys _query_one(%s) failed: %s", ip, last_exc)
        result = _error_result(ip, last_exc)
        cache[ip] = result
        return result


async def _batch(ips: List[str]) -> Dict[str, Any]:
    cache = _load_cache()
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT + 5)

    async def _rate_limited_query(ip: str) -> dict:
        await asyncio.sleep(RATE_LIMIT_DELAY)
        return await _query_one(session, sem, ip, cache)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_rate_limited_query(ip) for ip in ips]
        results = await asyncio.gather(*tasks)
    _save_cache(cache)
    return {r["ip"]: r for r in results}


def batch_enrich(ips: List[str]) -> Dict[str, Any]:
    """Enrich many IPs concurrently with rate limiting. Returns {ip: result}."""
    return asyncio.run(_batch(ips))
