"""Community intelligence: search online forums/communities for "gossip" about an
APK package or its malware family.

Uses free, no-API-key sources:
  - Hacker News (Algolia search API)
  - Reddit (public search JSON endpoint)
  - DuckDuckGo HTML search (scraped, best-effort)

Every source is wrapped in a timeout and its own try/except so a blocked or
unreachable source degrades gracefully instead of failing the endpoint.
"""

import html
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 5
MAX_POSTS_PER_SOURCE = 8
MAX_TOTAL_POSTS = 30
CACHE_TTL_SECONDS = 600  # community data changes slowly; cache per sample

_CACHE: Dict[str, tuple] = {}  # sample_id -> (timestamp, payload)
_CACHE_LOCK = threading.Lock()

_HEADERS = {
    "User-Agent": "DroidForensix/1.0 (malware analysis research; contact: droidforensix@local)",
}


def _build_queries(package_name: str, family: str) -> List[str]:
    queries = []
    if package_name:
        queries.append(f'"{package_name}" malware')
        queries.append(f'"{package_name}" virus')
    if family and family.lower() not in ("unknown", "none", "n/a"):
        queries.append(f'"{family}" android malware')
        queries.append(f'"{family}" apk trojan')
    if not queries:
        queries = ["android malware apk forum"]
    return queries


def _search_hacker_news(query: str) -> List[Dict]:
    """Search Hacker News via the Algolia API (no auth required)."""
    url = "https://hn.algolia.com/api/v1/search"
    params = {"query": query, "tags": "story", "hitsPerPage": MAX_POSTS_PER_SOURCE}
    resp = requests.get(url, params=params, headers=_HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    hits = resp.json().get("hits", [])
    posts = []
    for hit in hits:
        title = hit.get("title") or hit.get("story_title") or ""
        url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}"
        if not title:
            continue
        posts.append({
            "source": "Hacker News",
            "title": title,
            "url": url,
            "snippet": (hit.get("story_text") or "")[:300],
            "author": hit.get("author") or "",
            "score": hit.get("points") or 0,
            "published_at": hit.get("created_at") or "",
        })
    return posts


def _search_reddit(query: str) -> List[Dict]:
    """Search Reddit via its public search JSON endpoint."""
    url = "https://www.reddit.com/search.json"
    params = {"q": query, "limit": MAX_POSTS_PER_SOURCE, "sort": "relevance"}
    resp = requests.get(url, params=params, headers=_HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    children = resp.json().get("data", {}).get("children", [])
    posts = []
    for child in children:
        data = child.get("data", {})
        title = data.get("title") or ""
        permalink = data.get("permalink") or ""
        if not title or not permalink:
            continue
        posts.append({
            "source": "Reddit",
            "title": title,
            "url": f"https://www.reddit.com{permalink}",
            "snippet": (data.get("selftext") or "")[:300],
            "author": data.get("author") or "",
            "score": data.get("score") or 0,
            "published_at": datetime.utcfromtimestamp(data.get("created_utc") or 0).isoformat() if data.get("created_utc") else "",
            "subreddit": data.get("subreddit") or "",
        })
    return posts


def _search_duckduckgo(query: str) -> List[Dict]:
    """Scrape DuckDuckGo HTML results (best-effort; no API key needed)."""
    url = "https://html.duckduckgo.com/html/"
    params = {"q": query}
    resp = requests.get(url, params=params, headers=_HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    posts = []
    for block in re.findall(r'<div class="result[^"]*">(.*?)</div>\s*</div>', resp.text, re.DOTALL):
        title_match = re.search(r'class="result__a"[^>]*>(.*?)</a>', block, re.DOTALL)
        link_match = re.search(r'class="result__a"[^>]*href="([^"]+)"', block)
        snippet_match = re.search(r'class="result__snippet"[^>]*>(.*?)</(?:a|span|div)>', block, re.DOTALL)
        if not title_match:
            continue
        title = html.unescape(re.sub(r"<[^>]+>", "", title_match.group(1))).strip()
        link = link_match.group(1) if link_match else ""
        if link.startswith("//"):
            link = f"https:{link}"
        snippet = html.unescape(re.sub(r"<[^>]+>", "", snippet_match.group(1))).strip() if snippet_match else ""
        posts.append({
            "source": "DuckDuckGo",
            "title": title,
            "url": link,
            "snippet": snippet[:300],
            "author": "",
            "score": 0,
            "published_at": "",
        })
    return posts


_SOURCES = {
    "reddit": _search_reddit,
    "hacker_news": _search_hacker_news,
    "duckduckgo": _search_duckduckgo,
}


def search_community_intel(package_name: str, family: str) -> Dict:
    """Search all configured community sources for gossip about the app/family."""
    queries = _build_queries(package_name, family)
    posts: List[Dict] = []
    sources_failed: List[str] = []

    with ThreadPoolExecutor(max_workers=min(len(_SOURCES) * len(queries), 8)) as executor:
        futures = {
            executor.submit(fn, q): (source_name, q)
            for source_name, fn in _SOURCES.items()
            for q in queries
        }
        for future in as_completed(futures):
            source_name, q = futures[future]
            try:
                posts.extend(future.result())
            except Exception as exc:  # noqa: BLE001 - degraded behavior is intentional
                logger.debug("Community source %s failed for query %r: %s", source_name, q, exc)
                sources_failed.append(source_name)

    # Dedupe by URL, keep the highest-scored entry.
    by_url: Dict[str, Dict] = {}
    for post in posts:
        url = post["url"]
        if not url:
            continue
        existing = by_url.get(url)
        if existing is None or (post.get("score") or 0) > (existing.get("score") or 0):
            by_url[url] = post

    ranked = sorted(by_url.values(), key=lambda p: -(p.get("score") or 0))
    return {
        "package_name": package_name or "",
        "family": family or "unknown",
        "queried_at": datetime.utcnow().isoformat(),
        "total_posts": len(ranked[:MAX_TOTAL_POSTS]),
        "posts": ranked[:MAX_TOTAL_POSTS],
        "sources_failed": sorted(set(sources_failed)),
    }


def get_cached_community_intel(sample_id: str, package_name: str, family: str) -> Dict:
    """Return cached community intel for a sample, refreshing if stale."""
    with _CACHE_LOCK:
        cached = _CACHE.get(sample_id)
        if cached and (time.time() - cached[0]) < CACHE_TTL_SECONDS:
            return cached[1]
    payload = search_community_intel(package_name, family)
    with _CACHE_LOCK:
        _CACHE[sample_id] = (time.time(), payload)
    return payload
