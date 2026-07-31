"""Match C2 indicators (domains/IPs) against forum text with confidence scoring.

Pure logic module — no network I/O — so it is fully unit-testable.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set

import tldextract

CONF_EXACT = 1.0
CONF_IP = 0.9
CONF_SUBDOMAIN = 0.8
CONF_TYPOSQUAT = 0.5  # Risky: always flagged for human review

SNIPPET_RADIUS = 80

DOMAIN_RE = re.compile(
    r"(?<![a-zA-Z0-9.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![a-zA-Z0-9-])"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Well-known infrastructure that has no attribution value (configurable).
DEFAULT_EXCLUDE_DOMAINS: Set[str] = {
    "github.com",
    "reddit.com",
    "stackoverflow.com",
    "pastebin.com",
    "imgur.com",
    "google.com",
    "youtube.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
}

# Reddit auto-moderation / bot accounts that never carry attribution signal.
BOT_USERNAMES: Set[str] = {"automoderator", "autoadmin", "moderator"}

BOT_BODY_MARKERS = re.compile(
    r"\b(i am a bot|auto.?moderator|automod)\b", re.IGNORECASE
)

# URLs/IRIs/host:port patterns are handled by the domain regex; email-style
# hostnames (foo.bar.com) match too, which is acceptable for C2 attribution.


@dataclass
class MatchDetail:
    """A single indicator-to-text match with its confidence score."""

    match_type: str  # exact | subdomain | ip | typosquat
    confidence: float
    match_start: int
    match_end: int
    needs_review: bool = False
    matched_text: str = field(default="")


@dataclass
class C2Indicator:
    """A parsed C2 indicator from the DroidForensix pipeline."""

    value: str
    kind: str  # "domain" | "ip"
    confidence: float = 1.0
    source_sample: str = ""


def classify_indicator(raw: str) -> Optional[C2Indicator]:
    """Classify a raw indicator string as a domain or IP."""
    cleaned = raw.strip().lower().rstrip(".")
    if not cleaned:
        return None
    ip = _normalize_ipv4(cleaned)
    if ip is not None:
        return C2Indicator(value=ip, kind="ip")
    if re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,63}", cleaned):
        return C2Indicator(value=cleaned, kind="domain")
    return None


def _normalize_ipv4(raw: str) -> Optional[str]:
    """Validate an IPv4 string, accepting leading-zero octets from APKs."""
    octets = raw.split(".")
    if len(octets) != 4:
        return None
    try:
        numeric = [int(octet) for octet in octets]
    except ValueError:
        return None
    if any(octet < 0 or octet > 255 for octet in numeric):
        return None
    return ipaddress.ip_address(".".join(str(o) for o in numeric)).compressed


def registered_domain(domain: str) -> str:
    """Reduce a domain to its registrable root (no www/subdomain prefixes)."""
    extracted = tldextract.extract(domain)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return domain.lower()


def canonicalize_domain(domain: str) -> str:
    """Normalize a domain for exact matching: strip www. and trailing dot."""
    root = registered_domain(domain)
    return root


def normalize_indicator(indicator: C2Indicator) -> C2Indicator:
    """Return a copy of the indicator in canonical form."""
    if indicator.kind == "domain":
        return C2Indicator(
            value=canonicalize_domain(indicator.value),
            kind="domain",
            confidence=indicator.confidence,
            source_sample=indicator.source_sample,
        )
    return indicator


def extract_domains(text: str) -> List[str]:
    """Extract all domain-like tokens from text (lowercase, deduplicated)."""
    found: Set[str] = set()
    for match in DOMAIN_RE.finditer(text.lower()):
        found.add(match.group(0))
    return sorted(found)


def extract_ips(text: str) -> List[str]:
    """Extract all IPv4 strings from text (deduplicated)."""
    found: Set[str] = set()
    for match in IP_RE.finditer(text):
        candidate = match.group(0)
        try:
            found.add(ipaddress.ip_address(candidate).compressed)
        except ValueError:
            continue
    return sorted(found)


def levenshtein(a: str, b: str) -> int:
    """Levenshtein distance — used for typosquatting detection."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (char_a != char_b),
                )
            )
        previous = current
    return previous[-1]


def match_indicator(
    indicator: C2Indicator,
    text: str,
    exclude_domains: Optional[Sequence[str]] = None,
) -> Optional[MatchDetail]:
    """Find the best match of an indicator inside text.

    Priority: exact domain > IP > subdomain > typosquat.
    Returns None when nothing matches or the match is noise.
    """
    excludes = set(exclude_domains or DEFAULT_EXCLUDE_DOMAINS)
    text_lower = text.lower()

    if indicator.kind == "domain":
        domain = indicator.value.lower().rstrip(".")
        if domain.startswith("www."):
            domain = domain[4:]
        # Exclusion lists are checked at the registered-root level so
        # "cdn.github.com" and "github.com" are both treated as noise.
        if registered_domain(domain) in excludes:
            return None

        hosts = extract_domains(text)

        # Exact match: the C2 host itself (or its bare www. alias) appears.
        for host in hosts:
            if host == domain or host == f"www.{domain}":
                position = text_lower.find(host)
                return MatchDetail(
                    match_type="exact",
                    confidence=CONF_EXACT,
                    match_start=position if position >= 0 else 0,
                    match_end=position + len(host) if position >= 0 else len(host),
                    matched_text=host,
                )

        # Subdomain match: a host that is a strict subdomain of the C2 host
        # (covers both "cdn.c2.com" for c2.com and "cdn.c2.example.com" for
        # c2.example.com — but NOT a mention of the parent domain alone).
        for host in hosts:
            if host.endswith(f".{domain}"):
                position = text_lower.find(host)
                return MatchDetail(
                    match_type="subdomain",
                    confidence=CONF_SUBDOMAIN,
                    match_start=position if position >= 0 else 0,
                    match_end=position + len(host) if position >= 0 else len(host),
                    matched_text=host,
                )

        # Typosquatting: within edit distance 1 of the C2 host (risky).
        for host in hosts:
            if len(host) < len(domain) - 1:
                continue
            if levenshtein(host, domain) <= 1:
                position = text_lower.find(host)
                return MatchDetail(
                    match_type="typosquat",
                    confidence=CONF_TYPOSQUAT,
                    match_start=position if position >= 0 else 0,
                    match_end=position + len(host) if position >= 0 else len(host),
                    needs_review=True,
                    matched_text=host,
                )
        return None

    # IP match: exact string equality against extracted IPv4 tokens.
    for candidate in extract_ips(text):
        if candidate == indicator.value:
            position = text_lower.find(indicator.value)
            return MatchDetail(
                match_type="ip",
                confidence=CONF_IP,
                match_start=position if position >= 0 else 0,
                match_end=position + len(indicator.value) if position >= 0 else len(indicator.value),
                matched_text=indicator.value,
            )
    return None


def make_snippet(text: str, match_start: int, match_end: int, radius: int = SNIPPET_RADIUS) -> str:
    """Return ~2*radius characters of context around a match."""
    snippet_start = max(0, match_start - radius)
    snippet_end = min(len(text), match_end + radius)
    snippet = text[snippet_start:snippet_end].replace("\n", " ").strip()
    if snippet_start > 0:
        snippet = f"...{snippet}"
    if snippet_end < len(text):
        snippet = f"{snippet}..."
    return snippet


def is_bot_content(username: str, body: str) -> bool:
    """Heuristic: auto-moderation or bot replies carry no attribution signal.

    An empty username (e.g. GitHub code-search records) is NOT bot content;
    only explicit bot markers disqualify a record.
    """
    if not body:
        return True
    if username and username.lower().strip() in BOT_USERNAMES:
        return True
    if username and "bot" in username.lower() and BOT_BODY_MARKERS.search(body):
        return True
    return bool(BOT_BODY_MARKERS.search(body))


def find_matches(
    indicator: C2Indicator,
    text: str,
    username: str = "",
    exclude_domains: Optional[Sequence[str]] = None,
) -> List[MatchDetail]:
    """Return all match details for an indicator within text (usually one)."""
    match = match_indicator(indicator, text, exclude_domains)
    if match is None:
        return []
    return [match]


def score_filter(match: MatchDetail, min_confidence: float = 0.7) -> bool:
    """Keep only links at or above the confidence threshold."""
    return match.confidence >= min_confidence
