"""
Tier 3 Allowlist: Legitimate infrastructure that should not be scored as C2.
Populated from FP analysis (evaluation/c2_analysis/fp_domains.csv) + known OAuth/CDN/library docs.
See analysis/step5_c2_extraction.py for usage.
"""

import logging

logger = logging.getLogger(__name__)

# OAuth / SaaS identity providers - legitimate API endpoints often embedded in apps
OAUTH_DOMAINS = {
    # Google / Firebase
    "accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com",
    "firebaseio.com", "firebaseapp.com", "firebasestorage.googleapis.com",
    # Facebook
    "graph.facebook.com", "connect.facebook.net", "www.facebook.com",
    # Snapchat (the FP case)
    "accounts.snapchat.com", "app.snapchat.com", "snapchat.com",
    # Twitter/X
    "api.twitter.com", "accounts.twitter.com", "t.co",
    # Apple / Microsoft / Spotify
    "appleid.apple.com", "login.microsoftonline.com", "accounts.spotify.com",
    "accounts.microsoft.com", "graph.microsoft.com",
    # GitHub
    "github.com", "api.github.com",
}

# CDN / cloud providers - legitimate hosting
CDN_PROVIDERS = {
    # Cloudflare
    "cloudflare.com", "cloudflare.net",
    # AWS
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "cloudfront.amazonaws.com",
    # GCP
    "googleapis.com", "storage.googleapis.com", "appspot.com",
    # Azure
    "azureedge.net", "blob.core.windows.net", "azure.com",
    # Akamai / Fastly / CDN
    "akamai.net", "akamaihd.net", "akamaiedge.net", "fastly.net", "fastly-edge.com",
    "jsdelivr.net", "cdn.jsdelivr.net",
    # Map / tile CDNs observed in FP
    "openstreetmap.org", "overlay.openstreetmap.nl", "basemap.nationalmap.gov",
    "openhab.org", "tile.openstreetmap.org",
}

# Library documentation / developer portals - never C2
LIBRARY_DOCS = {
    # From FP top 20
    "logback.qos.ch", "www.qos.ch", "qos.ch",
    "jabber.org", "www.jabber.org",
    "tasks.org", "www.tasks.org",
    "ankiweb.net", "docs.ankiweb.net", "docs.ankidroid.org", "ankidroid.org",
    "wms.chartbundle.com", "chartbundle.com",
    "bandcamp.com", "www.bandcamp.com",
    "ccil.org", "www.ccil.org",
    "soundcloud.com", "api-v2.soundcloud.com",
    "gmail.com", "www.gmail.com",
    "newpipe.net", "www.newpipe.net",
    "media.ccc.de", "ccc.de",
    "json.schemastore.org", "schemastore.org",
    "ktor.io", "www.ktor.io",
    "eightbitwonders.gitlab.io", "gitlab.io",
    # General docs
    "maven.org", "repo.maven.apache.org", "docs.gradle.org", "gradle.org",
    "square.github.io", "kotlinlang.org", "developer.android.com",
    "w3.org", "www.w3.org", "schemas.android.com",
    "feederapp.nononsenseapps.com", "nononsenseapps.com",
    # Round 2 FP (retest 446: top benign C2 domains, all library/docs/donation/tiles)
    "link.adtidy.org", "adtidy.org",
    "liberapay.com", "www.liberapay.com",
    "www.aelf.org", "aelf.org",
    "linphone.org", "www.linphone.org",
    "a.tile.opentopomap.org", "b.tile.opentopomap.org", "c.tile.opentopomap.org",
    "opentopomap.org",
    "opencollective.com", "www.opencollective.com",
    "auroraoss.com", "www.auroraoss.com",
    "json-schema.org", "www.json-schema.org",
    "codedead.com", "www.codedead.com",
    "addismaptransit.com", "www.addismaptransit.com",
    "addy.io", "www.addy.io",
    "opds-spec.org", "www.opds-spec.org",
    "dropbox.com", "www.dropbox.com",
}

# Union for quick check
TIER3_ALLOWLIST = OAUTH_DOMAINS | CDN_PROVIDERS | LIBRARY_DOCS

# Shared hosting: any tenant can create <name>.<parent>, so only the exact parent host is
# allowlisted, never its subdomains (audit A1-03). Malware C2 is hosted on these platforms.
TENANT_HOSTING_PARENTS = frozenset({
    "firebaseio.com", "appspot.com", "githubusercontent.com", "github.com", "github.io",
    "gitlab.io", "amazonaws.com", "cloudfront.net", "azureedge.net", "windows.net",
    "byethost3.com", "dropbox.com", "t.me", "telegram.me", "mail.ru", "qq.com",
    "dropboxusercontent.com", "herokuapp.com", "ngrok.io", "pages.dev", "workers.dev",
    "s3.amazonaws.com", "cloudfront.amazonaws.com", "storage.googleapis.com",
    "blob.core.windows.net", "cdn.jsdelivr.net",
})


def suffix_allowed(hostname: str, allowed) -> bool:
    """True if hostname, or one of its parent domains, is in `allowed`.

    A tenant-hosting parent matches only the exact host, so an attacker subdomain
    under a shared platform is not allowlisted by its parent.
    """
    parts = hostname.lower().split(".")
    for i in range(len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in allowed and (i == 0 or suffix not in TENANT_HOSTING_PARENTS):
            return True
    return False


# Also include all BENIGN_DOMAINS from step5 as Tier 3 (568 entries) - import at runtime to avoid circular
def is_tier3(domain: str) -> bool:
    """Check if domain is Tier 3 legitimate infrastructure."""
    if not domain:
        return False
    d = domain.lower().removeprefix("www.")
    # Subdomain match: e.g. api.ktor.io -> ktor.io
    if suffix_allowed(d, TIER3_ALLOWLIST):
        return True
    # Also check against step5 BENIGN_DOMAINS (568) at runtime
    try:
        from analysis.step5_c2_extraction import BENIGN_DOMAINS
        if suffix_allowed(d, BENIGN_DOMAINS):
            return True
    except Exception as exc:
        logger.warning("BENIGN_DOMAINS unavailable, using Tier 3 allowlist only: %s", exc)
    return False
