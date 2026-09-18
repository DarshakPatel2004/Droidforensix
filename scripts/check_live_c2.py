"""
Check which extracted C2 domains from analyzed samples currently resolve to IPs.

Usage:
    python scripts/check_live_c2.py

This performs DNS resolution only by default (safe, read-only).  Direct HTTP/HTTPS
connectivity checks are optional and disabled by default because touching live
malicious infrastructure can expose your IP address and trigger alerts.

Output:
    reports/live_c2_summary.csv
    reports/live_c2_details.csv
"""

import argparse
import csv
import json
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict

from backend.config import settings


def extract_domain(value: str) -> str | None:
    """Pull a clean domain out of a URL or bare domain string."""
    if not value:
        return None
    value = value.strip()
    if value.startswith(("http://", "https://")):
        try:
            parsed = urlparse(value)
            host = parsed.hostname
        except Exception:
            host = None
    else:
        host = value.split("/")[0].split(":")[0]
    if not host:
        return None
    # Discard wildcard/format strings like %sdlsdk.%s
    if "%" in host or host.count(".") == 0:
        return None
    return host.lower()


def is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 / loopback IPs."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return True
    if o[0] == 127:
        return True
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    return False


def resolve_domain(domain: str, timeout: float = 3.0) -> list[str]:
    """Resolve a domain to IPv4 addresses."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        info = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = sorted({rec[4][0] for rec in info})
        return [ip for ip in ips if not is_private_ip(ip)]
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(old_timeout)


def check_http_reachable(url: str, timeout: float = 5.0) -> dict:
    """Attempt a HEAD request.  Requires urllib."""
    import urllib.request
    result = {"reachable": False, "status": None, "error": None}
    try:
        req = urllib.request.Request(url, method="HEAD", headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result["reachable"] = True
            result["status"] = resp.status
    except Exception as e:
        result["error"] = str(e)
    return result


def load_c2_indicators(work_dir: Path):
    """Walk analyzed results and collect C2 indicators per sample."""
    samples = defaultdict(lambda: {"domains": set(), "ips": set(), "urls": set()})
    for result_path in work_dir.glob("*/pipeline_result.json"):
        sample_id = result_path.parent.name
        try:
            data = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for c2 in data.get("c2_infrastructure", []):
            raw = c2.get("raw_url") or c2.get("value") or c2.get("domain") or ""
            domain = extract_domain(raw)
            if domain:
                samples[sample_id]["domains"].add(domain)
                samples[sample_id]["urls"].add(raw)
            ip = c2.get("ip")
            if ip:
                samples[sample_id]["ips"].add(ip)
    return samples


def main():
    parser = argparse.ArgumentParser(description="Check live C2 indicators from analyzed samples")
    parser.add_argument(
        "--http",
        action="store_true",
        help="Also perform HTTP/HTTPS reachability checks (WARNING: touches live C2 servers)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="DNS resolution timeout in seconds (default: 3.0)",
    )
    args = parser.parse_args()

    if args.http:
        print("WARNING: --http will connect directly to live C2 endpoints.")
        print("Only run this from an isolated sandbox/VPN, and only if you have permission.")
        confirm = input("Type 'yes' to continue: ")
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            sys.exit(0)

    work_dir = settings.WORK_DIR
    reports_dir = settings.REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading C2 indicators from {work_dir} ...")
    samples = load_c2_indicators(work_dir)
    print(f"Found {len(samples)} samples with C2 indicators.")

    all_domains = sorted({d for s in samples.values() for d in s["domains"]})
    print(f"Unique domains to resolve: {len(all_domains)}")

    domain_to_ips = {}
    for domain in all_domains:
        ips = resolve_domain(domain, timeout=args.timeout)
        domain_to_ips[domain] = ips
        if ips:
            print(f"  {domain} -> {', '.join(ips)}")

    # Build per-sample summary
    summary_rows = []
    detail_rows = []
    for sample_id, indicators in samples.items():
        live_domains = [d for d in indicators["domains"] if domain_to_ips.get(d)]
        live_ips = sorted({ip for d in live_domains for ip in domain_to_ips[d]})
        static_ips = sorted(indicators["ips"])

        summary_rows.append({
            "sample_id": sample_id,
            "total_domains": len(indicators["domains"]),
            "live_domains": len(live_domains),
            "resolved_ips": len(live_ips),
            "static_ips": len(static_ips),
            "live_domain_list": ";".join(live_domains),
            "resolved_ip_list": ";".join(live_ips),
            "static_ip_list": ";".join(static_ips),
        })

        for domain in live_domains:
            for ip in domain_to_ips[domain]:
                row = {
                    "sample_id": sample_id,
                    "domain": domain,
                    "ip": ip,
                    "source": "dns_resolution",
                    "http_reachable": "",
                    "http_status": "",
                    "http_error": "",
                }
                if args.http:
                    urls = [u for u in indicators["urls"] if domain in u]
                    url = urls[0] if urls else f"http://{domain}"
                    http_result = check_http_reachable(url)
                    row["http_reachable"] = str(http_result["reachable"])
                    row["http_status"] = str(http_result["status"] or "")
                    row["http_error"] = str(http_result["error"] or "")
                detail_rows.append(row)

    summary_path = reports_dir / "live_c2_summary.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "sample_id", "total_domains", "live_domains", "resolved_ips",
            "static_ips", "live_domain_list", "resolved_ip_list", "static_ip_list"
        ])
        writer.writeheader()
        writer.writerows(summary_rows)

    detail_path = reports_dir / "live_c2_details.csv"
    with open(detail_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "sample_id", "domain", "ip", "source", "http_reachable", "http_status", "http_error"
        ])
        writer.writeheader()
        writer.writerows(detail_rows)

    print()
    print(f"Samples with at least one live-resolved domain: {sum(1 for r in summary_rows if r['live_domains'] > 0)}")
    print(f"Summary written to: {summary_path}")
    print(f"Details written to: {detail_path}")


if __name__ == "__main__":
    main()
