"""
Aggregator Comparison Script for DroidForensix.

Cross-checks extracted C2 indicators (IPs, domains) against VirusTotal,
AlienVault OTX, and Shodan to measure what percentage are already known
to public threat intelligence feeds.

***** RESEARCH TOOL CAVEAT *****
This script queries LIVE threat intelligence feeds. The results reflect
what those feeds contain TODAY, not at the time the samples were analyzed.
Indicators that appear "unknown" may have been registered in feeds after
the analysis date, or may never have been seen by those particular feeds.
Conversely, indicators detected today may not have been detectable at the
time of original analysis.

Do NOT draw timeline conclusions from this data. This is a cross-sectional
snapshot for research purposes only.
*****

Usage:
    python scripts/compare_aggregators.py
    python scripts/compare_aggregators.py --cached-only
    python scripts/compare_aggregators.py --export-csv evaluation/aggregator_comparison.csv
    python scripts/compare_aggregators.py --limit 10
    python scripts/compare_aggregators.py --type ip
    python scripts/compare_aggregators.py --vt-key XXX --otx-key YYY --shodan-key ZZZ
"""

import argparse
import csv
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import settings


CACHE_PATH = ROOT / "evaluation" / "aggregator_comparison_cache.json"
RESULTS_PATH = ROOT / "evaluation" / "aggregator_comparison_results.json"
SUMMARY_PATH = ROOT / "evaluation" / "aggregator_comparison_summary.json"

VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"
SHODAN_BASE = "https://api.shodan.io"

VT_LINK = "https://www.virustotal.com/gui"
OTX_LINK = "https://otx.alienvault.com/indicator"


def load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_cache(cache: dict):
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(
        json.dumps(cache, indent=2, default=str), encoding="utf-8"
    )


def is_public_ip(ip: str) -> bool:
    if ":" in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return False
    if o[0] == 10:
        return False
    if o[0] == 172 and 16 <= o[1] <= 31:
        return False
    if o[0] == 192 and o[1] == 168:
        return False
    if o[0] == 127:
        return False
    if o[0] == 169 and o[1] == 254:
        return False
    if o[0] == 0:
        return False
    return True


def extract_domain(value: str) -> str | None:
    if not value:
        return None
    value = value.strip()
    if value.startswith(("http://", "https://")):
        try:
            host = urlparse(value).hostname
        except Exception:
            host = None
    else:
        host = value.split("/")[0].split(":")[0]
    if not host:
        return None
    host = host.lower()
    if "%" in host or host.count(".") == 0:
        return None
    if any(c in host for c in ("=", "(", ")", "\\", "|", "{", "}", "\n", "\r", "*", " ")):
        return None
    if all(c == "." for c in host):
        return None
    host = host.rstrip(".")
    if host.count(".") == 0:
        return None
    return host


def load_indicators(work_dir: Path, limit: int | None = None, filter_type: str | None = None):
    """Walk pipeline results and collect all unique C2 indicators."""
    indicators: dict[str, dict] = {}
    sample_files = sorted(work_dir.glob("*/pipeline_result.json"))

    for result_path in sample_files:
        sample_id = result_path.parent.name
        try:
            data = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        family = "unknown"
        family_path = result_path.parent / "family.json"
        if family_path.exists():
            try:
                fdata = json.loads(family_path.read_text(encoding="utf-8"))
                family = fdata.get("family", "unknown")
            except Exception:
                pass
        elif "family" in data:
            family = data.get("family", "unknown")

        for c2 in data.get("c2_infrastructure", []):
            raw_ip = c2.get("ip")
            if raw_ip and is_public_ip(raw_ip):
                if filter_type and filter_type != "ip":
                    pass
                else:
                    if raw_ip not in indicators:
                        indicators[raw_ip] = {
                            "value": raw_ip,
                            "type": "ip",
                            "sample_count": 0,
                            "samples": set(),
                            "families": set(),
                            "url_references": [],
                        }
                    indicators[raw_ip]["sample_count"] += 1
                    indicators[raw_ip]["samples"].add(sample_id)
                    indicators[raw_ip]["families"].add(family)

            raw_val = c2.get("raw_url") or c2.get("value") or c2.get("domain") or ""
            domain = extract_domain(raw_val)
            if domain and not raw_ip:
                if filter_type and filter_type != "domain":
                    pass
                else:
                    key = f"domain:{domain}"
                    if key not in indicators:
                        indicators[key] = {
                            "value": domain,
                            "type": "domain",
                            "sample_count": 0,
                            "samples": set(),
                            "families": set(),
                            "url_references": [],
                        }
                    indicators[key]["sample_count"] += 1
                    indicators[key]["samples"].add(sample_id)
                    indicators[key]["families"].add(family)

    result = []
    for key, ind in indicators.items():
        ind["samples"] = sorted(ind["samples"])
        ind["families"] = sorted(ind["families"])
        result.append(ind)

    result.sort(key=lambda x: x["value"])

    if limit and limit < len(result):
        result = result[:limit]

    return result


def make_cache_key(value: str, indicator_type: str, source: str) -> str:
    return f"{indicator_type}:{value}:{source}"


class RateLimiter:
    def __init__(self, requests_per_sec: float):
        self.min_interval = 1.0 / requests_per_sec
        self.last_call = 0.0

    def wait(self):
        now = time.monotonic()
        elapsed = now - self.last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_call = time.monotonic()


def query_virustotal(ip_or_domain: str, indicator_type: str, api_key: str, session: requests.Session) -> dict:
    if indicator_type == "ip":
        endpoint = f"{VT_BASE}/ip_addresses/{ip_or_domain}"
    else:
        endpoint = f"{VT_BASE}/domains/{ip_or_domain}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        resp = session.get(endpoint, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {"detected": False, "error": "not_found"}
        if resp.status_code == 401:
            return {"detected": False, "error": "unauthorized"}
        if resp.status_code == 429:
            return {"detected": False, "error": "rate_limited"}
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected
        reputation = attrs.get("reputation", 0)
        detected = malicious > 0 or suspicious > 0

        link = f"{VT_LINK}/{indicator_type == 'ip' and 'ip-address' or 'domain'}/{ip_or_domain}"

        return {
            "detected": detected,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_engines": total_engines,
            "reputation": reputation,
            "link": link,
        }
    except requests.RequestException as e:
        return {"detected": False, "error": str(e)[:200]}


def query_otx(ip_or_domain: str, indicator_type: str, api_key: str, session: requests.Session) -> dict:
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
    path_part = "IPv4" if indicator_type == "ip" else "domain"
    url = f"{OTX_BASE}/indicators/{path_part}/{ip_or_domain}/general"
    try:
        resp = session.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {"found": False, "error": "not_found"}
        if resp.status_code == 401:
            return {"found": False, "error": "unauthorized"}
        if resp.status_code == 429:
            return {"found": False, "error": "rate_limited"}
        resp.raise_for_status()
        data = resp.json()
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", []) if pulse_info else []
        pulses_count = len(pulses)
        validation = data.get("validation", [])
        validated = any(v.get("source", "").lower() != "false" for v in validation) if validation else False
        false_positive = data.get("false_positive", [])
        return {
            "found": pulses_count > 0 or validated,
            "pulses_count": pulses_count,
            "validated": validated,
            "false_positive": len(false_positive) > 0,
            "pulse_names": [p.get("name", "") for p in pulses[:10]],
            "link": f"{OTX_LINK}/{path_part}/{ip_or_domain}",
        }
    except requests.RequestException as e:
        return {"found": False, "error": str(e)[:200]}


def query_shodan(ip: str, api_key: str, session: requests.Session) -> dict:
    url = f"{SHODAN_BASE}/shodan/host/{ip}"
    params = {"key": api_key}
    try:
        resp = session.get(url, params=params, timeout=15)
        if resp.status_code == 404:
            return {"found": False, "error": "not_found"}
        if resp.status_code == 401:
            return {"found": False, "error": "unauthorized"}
        if resp.status_code == 429:
            return {"found": False, "error": "rate_limited"}
        resp.raise_for_status()
        data = resp.json()
        ports = data.get("ports", [])
        services = []
        for svc_data in data.get("data", []):
            svc_name = svc_data.get("_shodan", {}).get("module", "") or svc_data.get("product", "")
            if svc_name and svc_name not in services:
                services.append(svc_name)
        tags = data.get("tags", [])
        last_update = data.get("last_update", "")
        suspicious_tags = [t for t in tags if t.lower() in ("malware", "c2", "botnet", "phishing", "malicious", "attacker")]
        return {
            "found": True,
            "ports": sorted(ports),
            "services": services[:20],
            "tags": tags,
            "suspicious_tags": suspicious_tags,
            "last_update": last_update,
            "link": f"https://www.shodan.io/host/{ip}",
        }
    except requests.RequestException as e:
        return {"found": False, "error": str(e)[:200]}


def print_progress(label: str, done: int, total: int, start_time: float):
    if total == 0:
        return
    pct = done / total * 100
    elapsed = time.monotonic() - start_time
    rate = done / elapsed if elapsed > 0 else 0
    remaining = (total - done) / rate if rate > 0 else 0
    eta_min = remaining / 60
    print(
        f"\r[{label}] {done}/{total} ({pct:.0f}%) - "
        f"ETA: {eta_min:.1f} min{' ' * 10}",
        end="",
        flush=True,
    )


def run_queries(
    indicators: list[dict],
    vt_key: str | None,
    otx_key: str | None,
    shodan_key: str | None,
    cached_only: bool = False,
) -> list[dict]:
    cache = load_cache()
    session = requests.Session()
    session.headers.update({"User-Agent": "DroidForensix/1.0"})

    vt_limiter = RateLimiter(4.0)
    otx_limiter = RateLimiter(1.0)
    shodan_limiter = RateLimiter(1.0)

    results = []
    ip_only = [ind for ind in indicators if ind["type"] == "ip"]

    for ind in indicators:
        val = ind["value"]
        typ = ind["type"]

        result_entry = {
            "value": val,
            "type": typ,
            "sample_count": ind["sample_count"],
            "samples": ind["samples"],
            "families": ind["families"],
            "vt": None,
            "otx": None,
            "shodan": None,
            "any_detected": False,
        }

        # VirusTotal
        if vt_key:
            ck = make_cache_key(val, typ, "vt")
            if ck in cache and not cached_only:
                vt_result = cache[ck]
            elif cached_only:
                vt_result = cache.get(ck, {"detected": False, "error": "cached_only"})
            else:
                vt_limiter.wait()
                vt_result = query_virustotal(val, typ, vt_key, session)
                cache[ck] = vt_result
            result_entry["vt"] = vt_result
            if vt_result.get("detected"):
                result_entry["any_detected"] = True

        # AlienVault OTX
        if otx_key:
            ck = make_cache_key(val, typ, "otx")
            if ck in cache and not cached_only:
                otx_result = cache[ck]
            elif cached_only:
                otx_result = cache.get(ck, {"found": False, "error": "cached_only"})
            else:
                otx_limiter.wait()
                otx_result = query_otx(val, typ, otx_key, session)
                cache[ck] = otx_result
            result_entry["otx"] = otx_result
            if otx_result.get("found") or otx_result.get("pulses_count", 0) > 0:
                result_entry["any_detected"] = True

        # Shodan (IPs only)
        if shodan_key and typ == "ip":
            ck = make_cache_key(val, "ip", "shodan")
            if ck in cache and not cached_only:
                shodan_result = cache[ck]
            elif cached_only:
                shodan_result = cache.get(ck, {"found": False, "error": "cached_only"})
            else:
                shodan_limiter.wait()
                shodan_result = query_shodan(val, shodan_key, session)
                cache[ck] = shodan_result
            result_entry["shodan"] = shodan_result
            if shodan_result.get("found"):
                result_entry["any_detected"] = True

        results.append(result_entry)

    save_cache(cache)
    return results


def compute_summary(results: list[dict]) -> dict:
    total = len(results)
    ips = [r for r in results if r["type"] == "ip"]
    domains = [r for r in results if r["type"] == "domain"]

    def count_found(items, source_key, condition_fn):
        if not items:
            return 0, 0
        found = sum(1 for r in items if condition_fn(r.get(source_key)))
        return found, len(items)

    vt_found_ip, vt_total_ip = count_found(ips, "vt", lambda v: v and v.get("detected"))
    vt_found_dom, vt_total_dom = count_found(domains, "vt", lambda v: v and v.get("detected"))
    vt_found = vt_found_ip + vt_found_dom
    vt_total = vt_total_ip + vt_total_dom

    otx_found_ip, otx_total_ip = count_found(ips, "otx", lambda v: v and (v.get("found") or v.get("pulses_count", 0) > 0))
    otx_found_dom, otx_total_dom = count_found(domains, "otx", lambda v: v and (v.get("found") or v.get("pulses_count", 0) > 0))
    otx_found = otx_found_ip + otx_found_dom
    otx_total = otx_total_ip + otx_total_dom

    shodan_found_ip, shodan_total_ip = count_found(ips, "shodan", lambda v: v and v.get("found"))

    any_detected = sum(1 for r in results if r["any_detected"])

    all_detected = 0
    none_detected = 0
    for r in results:
        active_sources = 0
        detected_sources = 0
        if r.get("vt") is not None:
            active_sources += 1
            if r["vt"].get("detected"):
                detected_sources += 1
        if r.get("otx") is not None:
            active_sources += 1
            if r["otx"].get("found") or r["otx"].get("pulses_count", 0) > 0:
                detected_sources += 1
        if r.get("shodan") is not None:
            active_sources += 1
            if r["shodan"].get("found"):
                detected_sources += 1
        if active_sources > 0 and detected_sources == active_sources:
            all_detected += 1
        if active_sources > 0 and detected_sources == 0:
            none_detected += 1

    # Detection rates
    vt_malicious_ct = sum(1 for r in results if r.get("vt") and r["vt"].get("detected"))
    vt_malicious_total = sum(1 for r in results if r.get("vt") and r["vt"].get("error") is None)
    otx_with_pulses = sum(1 for r in results if r.get("otx") and r["otx"].get("pulses_count", 0) > 0)
    otx_pulse_total = sum(1 for r in results if r.get("otx"))
    shodan_tagged = sum(1 for r in ips if r.get("shodan") and r["shodan"].get("suspicious_tags"))
    shodan_tag_total = sum(1 for r in ips if r.get("shodan"))

    # Top detected
    scored = []
    for r in results:
        score = 0
        parts = []
        if r.get("vt") and r["vt"].get("detected"):
            mc = r["vt"].get("malicious_count", 0)
            te = r["vt"].get("total_engines", 1) or 1
            score += mc / te * 100
            parts.append(f"VT: {mc}/{te}")
        if r.get("otx") and r["otx"].get("pulses_count", 0) > 0:
            pc = r["otx"]["pulses_count"]
            score += pc * 10
            parts.append(f"OTX: {pc} pulses")
        if r.get("shodan") and r["shodan"].get("found"):
            ports = r["shodan"].get("ports", [])
            parts.append(f"Shodan: {ports[:5]}")
        if score > 0:
            scored.append((score, r["value"], parts))
    scored.sort(reverse=True, key=lambda x: x[0])
    top_detected = [
        {
            "value": s[1],
            "details": ", ".join(s[2]),
        }
        for s in scored[:10]
    ]

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_indicators": total,
        "total_ips": len(ips),
        "total_domains": len(domains),
        "coverage": {
            "virustotal": {
                "pct": round(vt_found / vt_total * 100, 1) if vt_total else 0,
                "found": vt_found,
                "total": vt_total,
            },
            "alienvault_otx": {
                "pct": round(otx_found / otx_total * 100, 1) if otx_total else 0,
                "found": otx_found,
                "total": otx_total,
            },
            "shodan": {
                "pct": round(shodan_found_ip / shodan_total_ip * 100, 1) if shodan_total_ip else 0,
                "found": shodan_found_ip,
                "total": shodan_total_ip,
            },
            "any_source": {
                "pct": round(any_detected / total * 100, 1) if total else 0,
                "found": any_detected,
                "total": total,
            },
            "all_sources": {
                "pct": round(all_detected / total * 100, 1) if total else 0,
                "found": all_detected,
                "total": total,
            },
            "no_source": {
                "pct": round(none_detected / total * 100, 1) if total else 0,
                "found": none_detected,
                "total": total,
            },
        },
        "detection_rates": {
            "vt_malicious": {
                "pct": round(vt_malicious_ct / vt_malicious_total * 100, 1) if vt_malicious_total else 0,
                "found": vt_malicious_ct,
                "total": vt_malicious_total,
            },
            "otx_pulses": {
                "pct": round(otx_with_pulses / otx_pulse_total * 100, 1) if otx_pulse_total else 0,
                "found": otx_with_pulses,
                "total": otx_pulse_total,
            },
            "shodan_tagged": {
                "pct": round(shodan_tagged / shodan_tag_total * 100, 1) if shodan_tag_total else 0,
                "found": shodan_tagged,
                "total": shodan_tag_total,
            },
        },
        "top_detected_indicators": top_detected,
    }


def print_report(summary: dict, results: list[dict], skipped_sources: list[str]):
    print()
    print("=" * 60)
    print(" Aggregator Comparison Report")
    print("=" * 60)
    print(f"Generated: {summary['generated_at'][:10]}")
    print(f"Indicators checked: {summary['total_ips']} IPs, {summary['total_domains']} domains")
    print(f"Total unique indicators: {summary['total_indicators']}")
    print()
    print("*" * 60)
    print("*** CAVEAT: Live queries reflect current feed state, not ***")
    print("*** analysis-time baselines. Do NOT draw timeline       ***")
    print("*** conclusions from this data.                         ***")
    print("*" * 60)
    print()

    if skipped_sources:
        print(f"Skipped sources (no API key): {', '.join(skipped_sources)}")
        print()

    cov = summary["coverage"]
    det = summary["detection_rates"]
    print("Coverage:")
    print(f"  VirusTotal:     {cov['virustotal']['pct']}% ({cov['virustotal']['found']}/{cov['virustotal']['total']} found)")
    print(f"  AlienVault OTX: {cov['alienvault_otx']['pct']}% ({cov['alienvault_otx']['found']}/{cov['alienvault_otx']['total']} found)")
    print(f"  Shodan:         {cov['shodan']['pct']}% ({cov['shodan']['found']}/{cov['shodan']['total']} found)")
    print()
    print(f"  Any source:     {cov['any_source']['pct']}% ({cov['any_source']['found']}/{cov['any_source']['total']} found in at least one feed)")
    print(f"  All sources:    {cov['all_sources']['pct']}% ({cov['all_sources']['found']}/{cov['all_sources']['total']} found in all feeds)")
    print(f"  No source:      {cov['no_source']['pct']}% ({cov['no_source']['found']}/{cov['no_source']['total']} found in NO feed)")
    print()
    print("Detection rates:")
    print(f"  VT malicious:   {det['vt_malicious']['pct']}% ({det['vt_malicious']['found']}/{det['vt_malicious']['total']} flagged malicious)")
    print(f"  OTX pulses:     {det['otx_pulses']['pct']}% ({det['otx_pulses']['found']}/{det['otx_pulses']['total']} with pulse info)")
    print(f"  Shodan tagged:  {det['shodan_tagged']['pct']}% ({det['shodan_tagged']['found']}/{det['shodan_tagged']['total']} with suspicious tags)")
    print()
    print("Top detected indicators:")
    for i, entry in enumerate(summary.get("top_detected_indicators", []), 1):
        print(f"  {i}. {entry['value']} - {entry['details']}")


def export_csv(results: list[dict], path: Path):
    fieldnames = [
        "value",
        "type",
        "sample_count",
        "families",
        "any_detected",
        "vt_detected",
        "vt_malicious",
        "vt_total_engines",
        "vt_link",
        "otx_found",
        "otx_pulses_count",
        "otx_validated",
        "otx_link",
        "shodan_found",
        "shodan_ports",
        "shodan_tags",
        "shodan_link",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            vt = r.get("vt") or {}
            otx = r.get("otx") or {}
            shodan = r.get("shodan") or {}
            writer.writerow({
                "value": r["value"],
                "type": r["type"],
                "sample_count": r["sample_count"],
                "families": ";".join(r.get("families", [])),
                "any_detected": r["any_detected"],
                "vt_detected": vt.get("detected", False),
                "vt_malicious": vt.get("malicious_count", 0),
                "vt_total_engines": vt.get("total_engines", 0),
                "vt_link": vt.get("link", ""),
                "otx_found": otx.get("found", False),
                "otx_pulses_count": otx.get("pulses_count", 0),
                "otx_validated": otx.get("validated", False),
                "otx_link": otx.get("link", ""),
                "shodan_found": shodan.get("found", False),
                "shodan_ports": ",".join(str(p) for p in shodan.get("ports", [])),
                "shodan_tags": ",".join(shodan.get("tags", [])),
                "shodan_link": shodan.get("link", ""),
            })
    print(f"\nCSV exported to: {path}")


def main():
    parser = argparse.ArgumentParser(description="Cross-check C2 indicators against threat intel feeds")
    parser.add_argument("--cached-only", action="store_true", help="Use cached results only (no API calls)")
    parser.add_argument("--export-csv", type=str, help="Export results as CSV to path")
    parser.add_argument("--limit", type=int, default=None, help="Limit to first N indicators")
    parser.add_argument("--type", type=str, choices=["ip", "domain"], help="Filter by indicator type")
    parser.add_argument("--vt-key", type=str, default=None, help="VirusTotal API key")
    parser.add_argument("--otx-key", type=str, default=None, help="AlienVault OTX API key")
    parser.add_argument("--shodan-key", type=str, default=None, help="Shodan API key")
    args = parser.parse_args()

    vt_key = args.vt_key or os.environ.get("VT_API_KEY") or os.environ.get("VT_KEY") or ""
    otx_key = args.otx_key or os.environ.get("OTX_API_KEY") or os.environ.get("OTX_KEY") or ""
    shodan_key = args.shodan_key or os.environ.get("SHODAN_API_KEY") or os.environ.get("SHODAN_KEY") or ""

    if not vt_key:
        vt_key = None
    if not otx_key:
        otx_key = None
    if not shodan_key:
        shodan_key = None

    skipped = []
    if not vt_key:
        skipped.append("VirusTotal")
    if not otx_key:
        skipped.append("AlienVault OTX")
    if not shodan_key:
        skipped.append("Shodan")

    if args.cached_only:
        print("Running in --cached-only mode: no new API queries will be made.")

    work_dir = settings.WORK_DIR
    print(f"Loading C2 indicators from {work_dir} ...")
    indicators = load_indicators(work_dir, limit=args.limit, filter_type=args.type)

    if not indicators:
        print("No indicators found. Exiting.")
        return

    ip_count = sum(1 for i in indicators if i["type"] == "ip")
    domain_count = sum(1 for i in indicators if i["type"] == "domain")
    print(f"Loaded {len(indicators)} indicators ({ip_count} IPs, {domain_count} domains)")

    print("Querying threat intel feeds...")
    t0 = time.monotonic()
    results = run_queries(indicators, vt_key, otx_key, shodan_key, cached_only=args.cached_only)
    elapsed = time.monotonic() - t0
    print(f"\nQueries completed in {elapsed:.1f}s")

    summary = compute_summary(results)

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"Results written to: {RESULTS_PATH}")
    print(f"Summary written to: {SUMMARY_PATH}")

    if args.export_csv:
        export_csv(results, Path(args.export_csv))

    print_report(summary, results, skipped)


if __name__ == "__main__":
    main()