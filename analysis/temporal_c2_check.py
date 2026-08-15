#!/usr/bin/env python3
"""
Temporal C2 analysis: URLhaus + VirusTotal lookups for all domains.
Uses free APIs (no key for URLhaus, optional key for VT).
"""
import json
import time
import requests
from pathlib import Path

CLASSIFICATION = Path("D:/DroidForensix/analysis/c2_domain_classification.json")
OUTPUT = Path("D:/DroidForensix/analysis/temporal_c2_results.json")

VT_API_KEY = ""  # User fills this in

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
VT_API = "https://www.virustotal.com/api/v3"


def check_urlhaus(domain: str) -> dict:
    """Check domain against URLhaus (free, no key needed)."""
    try:
        resp = requests.post(
            f"{URLHAUS_API}host/",
            data={"host": domain},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "no_results":
                return {"listed": False, "urls_online": 0, "urls_total": 0}
            urls_online = data.get("urls_online", 0)
            urls_total = data.get("urls_total", 0)
            # Get first few URL entries
            urls = data.get("urls", [])[:3]
            url_details = []
            for u in urls:
                url_details.append({
                    "url": u.get("url", ""),
                    "status": u.get("url_status", ""),
                    "threat": u.get("threat", ""),
                    "date_added": u.get("date_added", ""),
                })
            return {
                "listed": urls_total > 0,
                "urls_online": urls_online,
                "urls_total": urls_total,
                "details": url_details,
            }
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_virustotal(domain: str, api_key: str) -> dict:
    """Check domain against VirusTotal (needs API key)."""
    if not api_key:
        return {"skipped": True, "reason": "no API key"}

    try:
        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"{VT_API}/domains/{domain}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "categories": data.get("categories", {}),
                "registrar": data.get("registrar", ""),
                "creation_date": data.get("creation_date", ""),
            }
        elif resp.status_code == 404:
            return {"listed": False, "reason": "not found in VT"}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_whois(domain: str) -> dict:
    """Basic whois lookup."""
    try:
        import socket
        # Simple RDAP/WHOIS via socket
        # For now, just check if domain resolves
        answers = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list(set(a[4][0] for a in answers))
        return {"resolves": True, "ips": ips[:3]}
    except socket.gaierror:
        return {"resolves": False}
    except Exception as e:
        return {"error": str(e)}


def main():
    with open(CLASSIFICATION) as f:
        classifications = json.load(f)

    domains = list(classifications["classifications"].keys())
    print(f"Checking {len(domains)} domains...")

    results = {}
    for i, domain in enumerate(domains):
        print(f"  [{i+1}/{len(domains)}] {domain}...", end=" ", flush=True)

        # DNS check
        dns_result = check_whois(domain)

        # URLhaus check
        urlhaus = check_urlhaus(domain)
        time.sleep(0.5)  # Rate limit

        # VT check
        vt = check_virustotal(domain, VT_API_KEY)
        time.sleep(4)  # VT rate limit (4 req/min for free tier)

        # Determine overall verdict
        verdict = "UNKNOWN"
        if urlhaus.get("listed"):
            verdict = "MALICIOUS"
        elif vt.get("malicious", 0) >= 3:
            verdict = "MALICIOUS"
        elif vt.get("malicious", 0) >= 1:
            verdict = "SUSPICIOUS"
        elif urlhaus.get("listed") is False and vt.get("harmless", 0) > 0:
            verdict = "BENIGN"
        elif not dns_result.get("resolves"):
            verdict = "DEAD"

        results[domain] = {
            "dns": dns_result,
            "urlhaus": urlhaus,
            "virustotal": vt,
            "verdict": verdict,
        }

        status = f"verdict={verdict}"
        if urlhaus.get("listed"):
            status += f" urlhaus={urlhaus.get('urls_total', 0)} urls"
        if vt.get("malicious", 0) > 0:
            status += f" vt_mal={vt['malicious']}"
        print(status)

        # Save intermediate every 10 domains
        if (i + 1) % 10 == 0:
            with open(OUTPUT, "w") as f:
                json.dump(results, f, indent=2)

    # Final save
    with open(OUTPUT, "w") as f:
        json.dump(results, f, indent=2)

    # Summary
    verdicts = {}
    for d, r in results.items():
        v = r.get("verdict", "UNKNOWN")
        verdicts[v] = verdicts.get(v, 0) + 1

    print(f"\nFinal results ({len(results)} domains):")
    for v, c in sorted(verdicts.items(), key=lambda x: -x[1]):
        print(f"  {v:15s}: {c}")

    print(f"\nSaved to {OUTPUT}")


if __name__ == "__main__":
    main()
