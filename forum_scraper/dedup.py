"""Deduplication and normalization for scraped C2-to-forum links.

A link is identified by (content hash of the post, canonical indicator).
Optionally, domain links are collapsed against IP links for the same post
when the domain resolves to that IP (bounded DNS lookups).
"""

import hashlib
import ipaddress
import re
import socket
import threading
from typing import Dict, List, Optional, Tuple

from .linker import C2Indicator, canonicalize_domain

WHITESPACE_RE = re.compile(r"\s+")


def canonical_indicator(indicator: C2Indicator) -> str:
    """Canonical key for an indicator: root domain or compressed IP."""
    if indicator.kind == "domain":
        return canonicalize_domain(indicator.value)
    try:
        return ipaddress.ip_address(indicator.value).compressed
    except ValueError:
        return indicator.value


def content_hash(text: str) -> str:
    """sha256 of whitespace-normalized text — same post content, same key."""
    normalized = WHITESPACE_RE.sub(" ", text).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def resolve_hostname(domain: str, timeout: float = 2.0) -> Optional[str]:
    """Best-effort DNS resolution with a hard timeout (dead C2s must not stall)."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
    return None


def deduplicate(
    links: List[Dict],
    resolve_ips: bool = True,
) -> List[Dict]:
    """Drop duplicate (post content, indicator) pairs, keeping first occurrence.

    Each link dict needs: c2_indicator, snippet (or raw body), username,
    source. Extra keys pass through unchanged.
    """
    seen_keys: Dict[Tuple[str, str], bool] = {}
    deduped: List[Dict] = []

    for link in links:
        body = link.get("snippet") or link.get("body") or ""
        key_indicator = canonical_indicator(
            C2Indicator(
                value=link["c2_indicator"],
                kind="ip" if _is_ip(link["c2_indicator"]) else "domain",
            )
        )
        key = (content_hash(body), key_indicator)
        if key in seen_keys:
            continue

        if resolve_ips and _is_domain(link["c2_indicator"]):
            resolved = resolve_hostname(key_indicator)
            if resolved:
                ip_key = (key[0], ipaddress.ip_address(resolved).compressed)
                if ip_key in seen_keys:
                    continue
                seen_keys[ip_key] = True

        seen_keys[key] = True
        deduped.append(link)

    return deduped


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_domain(value: str) -> bool:
    return not _is_ip(value)
