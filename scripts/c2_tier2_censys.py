#!/usr/bin/env python3
"""C2 Tier 2: Censys ASN reputation for malware C2 IPs + retiering.

Enriches the malware C2 IP list (`evaluation/c2_analysis/malware_ips.csv`) via
`backend.censys_enrichment`, classifies each IP's ASN into a hosting-reputation
bucket (bulletproof / cloud / residential / other), and re-tiers per-sample
`kept_c2` counts from `evaluation/c2_analysis/retier_counts.csv`.

Usage:
    python scripts/c2_tier2_censys.py            # enrich (network, once)
    python scripts/c2_tier2_censys.py --offline  # reuse analysis/work/censys_cache.json only

Outputs: reports/c2_tier2_report.csv, reports/c2_tier2_summary.json,
         reports/c2_retiering_v2.csv
"""

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

IPS_PATH = PROJECT_ROOT / "evaluation" / "c2_analysis" / "malware_ips.csv"
RETIER_PATH = PROJECT_ROOT / "evaluation" / "c2_analysis" / "retier_counts.csv"
CACHE_PATH = PROJECT_ROOT / "analysis" / "work" / "censys_cache.json"
REPORT_PATH = PROJECT_ROOT / "reports" / "c2_tier2_report.csv"
SUMMARY_PATH = PROJECT_ROOT / "reports" / "c2_tier2_summary.json"
RETIER_OUT = PROJECT_ROOT / "reports" / "c2_retiering_v2.csv"

BP_ORGS = (
    "flokinet", "njabl", "mirhosting", "alexhost", "belcloud", "m247",
    "creanova", "estnoc", "abo host", "datawagon", "serveroffer",
    "interserver", "east bytes", "long live", "quantil", "dc hosting",
    "hostecho", "bfont", "fast horizon", "globalserv", "gigacloud",
    "mini heptagon", "newartical", "petersburg internet", "velia",
    "triolan", "cc lethal", "dobrolin",
    # abuse-tolerant/cheap VPS found in the 172-IP sweep (2026-09-12):
    "sondercloud", "pfcloud", "virtual systems", "tyna host",
)
CLOUD_ORGS = (
    "cloudflare", "akamai", "fastly", "amazon", "aws", "amazon technologies",
    "google", "google cloud", "microsoft", "azure", "microsoft corporation",
    "alibaba", "tencent", "tencent cloud", "huawei", "digitalocean", "linode",
    "vultr", "ovh", "hetzner", "contabo", "namecheap", "scaleway",
    "oracle", "zenlayer", "level 3", "netease", "west263",
)
ISP_ORGS = (
    "telecom", "unist", "cable", "broadband", "wireless", "mobile", " isp",
    "telekom", "telefonica", "internet services", "pccw", "china unicom",
    "china telecom", "chinanet", "unicom", "china mobile", "beijing baidu",
    "jintong data", "orange s.a.", "cell c", "sify", "at&t", "att-internet4",
    "communications international", "verizon", "vodafone", "rogers", "comcast",
)
TELEGRAM_ORGS = ("telegram messenger", "telegram - telegram", "telegram,")


def load_ips() -> list[str]:
    ips: list[str] = []
    with IPS_PATH.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            ip = (row.get("ip") or "").strip()
            if ip and ip not in ips:
                ips.append(ip)
    return ips


def load_retier() -> list[dict]:
    if not RETIER_PATH.exists():
        return []
    with RETIER_PATH.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def classify(entry: dict) -> tuple[str, str]:
    def haystack() -> str:
        parts = [
            entry.get("asn_description", ""),
            entry.get("asn_name", ""),
            entry.get("provider", ""),
        ]
        return " ".join(p for p in parts if p).lower()

    text = haystack()
    if any(t in text for t in TELEGRAM_ORGS) and not any(b in text for b in BP_ORGS):
        return "telegram", "Telegram Messenger bot-API block (abused as C2/messaging)"
    if any(b in text for b in BP_ORGS):
        return "bulletproof", "ASN org on bulletproof-hosting list"
    if any(c in text for c in CLOUD_ORGS):
        return "cloud", "public cloud/CDN ASN (weak signal)"
    if any(i in text for i in ISP_ORGS):
        return "residential", "telecom/ISP ASN (likely infected host)"
    if entry.get("_error"):
        return "unresolved", entry["_error"][:80]
    return "other", "hosting-adjacent or unclear ASN"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="use existing cache only")
    args = parser.parse_args()

    ips = load_ips()
    cache: dict = {}
    if CACHE_PATH.exists():
        cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))

    missing = [ip for ip in ips if ip not in cache]
    if missing and not args.offline:
        from backend.censys_enrichment import batch_enrich

        print(f"Enriching {len(missing)} IPs via Censys (cached {len(cache)})...", flush=True)
        fresh = batch_enrich(missing)
        cache = {**cache, **fresh}
        CACHE_PATH.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    elif missing:
        print(f"[offline] {len(missing)} IPs missing from cache -- marked unresolved", file=sys.stderr)

    rows = []
    category: Counter = Counter()
    unresolved = []
    for ip in ips:
        entry = cache.get(ip, {"ip": ip, "_error": "not cached"})
        cat, reason = classify(entry)
        entry["_category"] = cat
        entry["_reason"] = reason
        rows.append(entry)
        category[cat] += 1
        asn = entry.get("asn")
        if cat != "unresolved" and not asn:
            unresolved.append(ip)

    with REPORT_PATH.open("w", newline="", encoding="utf-8") as fh:
        cols = ["ip", "asn", "asn_name", "asn_description", "provider",
                "country_code", "_category", "_reason"]
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in sorted(rows, key=lambda x: (x.get("_category", ""), x.get("ip", ""))):
            w.writerow(r)

    # Retiering: drop bulletproof-hosted IPs from per-sample kept_c2.  Map back to
    # samples via the sha10 prefix in malware_ips.csv.
    ip_category = {r["ip"]: r.get("_category", "other") for r in rows}
    bp_ips = {ip for ip, c in ip_category.items() if c == "bulletproof"}
    sha10_to_ips: dict[str, set[str]] = {}
    with IPS_PATH.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            s10 = (row.get("sha10") or "").strip()
            ip = (row.get("ip") or "").strip()
            if s10 and ip:
                sha10_to_ips.setdefault(s10, set()).add(ip)

    retier = load_retier()
    retier_removed: Counter = Counter()
    if retier:
        with RETIER_OUT.open("w", newline="", encoding="utf-8") as fh:
            cols = ["sha", "orig_c2", "tier3_filtered", "kept_c2",
                    "tier2_removed", "kept_c2_tier2"]
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for row in retier:
                kept = int(row.get("kept_c2", "0") or "0")
                s10 = (row.get("sha") or "")[:10]
                ips_for_sample = sha10_to_ips.get(s10, set())
                tier2_removed = sum(1 for ip in ips_for_sample if ip in bp_ips)
                w.writerow({**row, "tier2_removed": tier2_removed,
                            "kept_c2_tier2": max(0, kept - tier2_removed)})
                retier_removed[tier2_removed] += 1
    else:
        retier = []

    import time
    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "unique_ips": len(ips),
        "enriched": len([r for r in rows if r.get("_category") not in ("unresolved",)]),
        "unresolved": len(unresolved),
        "category_counts": dict(category),
        "bulletproof_ips": sorted(bp_ips),
        "samples_retiered": len(retier),
        "samples_with_tier2_removal": int(sum(v for k, v in retier_removed.items() if k > 0)),
        "tier2_removal_distribution": dict(sorted(retier_removed.items())),
    }
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"unique IPs: {len(ips)} | categories: {dict(category)}")
    print(f"bulletproof IPs ({len(bp_ips)}): {', '.join(sorted(bp_ips)) or '(none)'}")
    print(f"report -> {REPORT_PATH}")
    if retier:
        print(f"retiering -> {RETIER_OUT}")
    print(f"summary -> {SUMMARY_PATH}")


if __name__ == "__main__":
    main()