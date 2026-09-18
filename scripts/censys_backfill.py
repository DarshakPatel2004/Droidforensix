"""
Historical Censys v3 backfill for the DroidForensix paper.

Reads ALL IPs from every pipeline_result.json across all samples,
enriches them via Censys Platform API v3 (concurrent, 25 slots),
and writes results to reports/censys_enrichment_2026-07-20.json.

Usage:
    cd DroidForensix
    python -m scripts.censys_backfill

Requires:
    CENSYS_TOKEN in .env (already set)
"""

import glob
import json
import os
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.censys_enrichment import batch_enrich


def collect_all_ips() -> set:
    """Gather every public IP from all pipeline results."""
    ips = set()
    pattern = str(ROOT / "analysis" / "work" / "*" / "pipeline_result.json")
    for path in glob.glob(pattern):
        try:
            with open(path, "r", encoding="utf-8") as f:
                result = json.load(f)
        except Exception:
            continue
        for c2 in result.get("c2_infrastructure", []) or []:
            if c2.get("ip"):
                ips.add(c2["ip"])
            for r_ip in (c2.get("live_dns") or {}).get("ips", []) or []:
                ips.add(r_ip)

    # Filter to public IPs only (ipaddress handles CGNAT 100.64.0.0/10,
    # which the old string-prefix filter missed)
    import ipaddress
    public = set()
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version == 4 and addr.is_global:
            public.add(ip)
    return public


def main():
    print("=" * 60)
    print("Censys v3 Historical Backfill")
    print("=" * 60)

    ips = collect_all_ips()
    print(f"\nCollected {len(ips)} unique public IPs from pipeline results.")

    if not ips:
        print("Nothing to backfill. Exiting.")
        return

    ip_list = sorted(ips)
    t0 = time.time()

    results = batch_enrich(ip_list)

    elapsed = time.time() - t0
    enriched = sum(1 for v in results.values() if not v.get("_error"))
    errors = sum(1 for v in results.values() if v.get("_error"))
    cached = sum(1 for v in results.values() if v.get("_error") == "not_found")

    print(f"\nDone in {elapsed:.1f}s")
    print(f"  Enriched:  {enriched}")
    print(f"  Not found: {cached}")
    print(f"  Errors:    {errors}")
    print(f"  Total:     {len(results)}")

    # Write report
    report = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_ips_queried": len(ip_list),
            "total_enriched": enriched,
            "total_not_found": cached,
            "total_errors": errors,
            "elapsed_seconds": round(elapsed, 1),
            "source": "Censys Platform API v3 (/global/asset/host/{ip})",
            "documentation": "Enriched via Censys Platform API on 2026-07-20",
        },
        "results": results,
    }

    out_dir = ROOT / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"censys_enrichment_{time.strftime('%Y-%m-%d')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport written to {out_path}")


if __name__ == "__main__":
    main()
