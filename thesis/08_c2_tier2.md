# C2 Tier 2 — Censys ASN Reputation (design + results)

> Status: first draft (2026-09-12). Tier 3 (allowlist, `analysis/step5_allowlists.py`)
> is implemented. Tier 2 is the stage below it: *hosting-infrastructure reputation*,
> applied to IP-direct C2 indicators before they reach the allowlist.
> Tooling: `scripts/c2_tier2_censys.py`; outputs: `reports/c2_tier2_report.csv`,
> `reports/c2_tier2_summary.json`, `reports/c2_retiering_v2.csv`.

## 1. Why a Tier 2, and where it sits

The C2 signal currently resolves to three buckets (`backend/threat_intel.classify_c2`):

| Tier | Rule | State |
|---|---|---|
| Tier 3 | `is_tier3(domain)` -- comprehensive legitimate infra allowlist | done |
| Tier 1 | domain/port/path/pDNS heuristics (SUSPICIOUS_TLDS, ports, NXDOMAIN...) | done |
| Tier 2 | **hosting reputation** (bulletproof vs cloud vs residential) | **this** |

Dominant unresolved class in the corpus: **IP-direct C2** (`10. IP-direct C2 (no
domain)` reason, `classify_c2` line 467) and IPs under weakly-signalled domains.
An attacker host on a bulletproof provider and a victim's residential IP are
currently indistinguishable at this stage. Tier 2 resolves that: it is a
*prior on hosting* applied to the IP side of an indicator.

## 2. Data

- 328 C2 IP rows for malware, `evaluation/c2_analysis/malware_ips.csv`
  (deduplicated ~250 unique IPs; includes private IPs such as `10.0.0.172`).
- Censys Platform v3 host lookup per IP (`backend/censys_enrichment.py`):
  ASN, ASN org name, whois provider, services, DNS names, TLS certs.
  Local cache: `analysis/work/censys_cache.json` (7/328 pre-computed).

## 3. Classification rules (v0)

Per IP, from `asn_description` + `asn_name` + `provider` (lowercased):

1. **bulletproof** -- org on the known-BP list (seeded from
   `scripts/check_legitimacy.py:SUSPICIOUS_HOSTING`): `flokinet`, `njabl`,
   `mirhosting`, `alexhost`, `belcloud`, `m247`, `estnoc`, `datawagon`,
   `serveroffer`, `interserver`, `east bytes`, `creanova`, `abo host`,
   plus top-BP ASNs named (`quantil`, `dc hosting`, `hostecho`, `bfont`, ...).
   Signal: **raise** (malicious prior).
2. **cloud** -- `cloudflare, akamai, fastly, amazon, aws, google, microsoft,
   azure, alibaba, tencent, digitalocean, linode, vultr, ovh, hetzner, contabo`.
   Signal: **weak** (public Iaas/edge -- commonly abused, but the ASN is public
   infrastructure, so the *provider* carries no malice).
3. **residential/ISP** -- telecom/ISP orgs (`telecom`, `unist`, `cable`, `broadband`,
   `wireless`, `mobile`, `isp`): signal **weak-negative** (victim-corp infected boxes).
4. **other** -- unclassified hosting/hosting-adjacent.

This v0 deliberately uses ASN org naming, not IP-block lists -- it is reproducible
off the Censys JSON cache with zero network at re-run.

## 4. Expected magnitude (honest)

C2 across the batch scores ~0.041 discriminator importance. Even a perfect Tier 2
only moves the *IP-direct C2* slice. Based on prior C2 analysis
(`evaluation/c2_analysis/fp_domains.csv`, `retier_counts.csv`: most samples have
`<2` kept C2 after Tier 3), the realistic gain is a cleaner per-sample "kept C2*
count rather than a headline accuracy jump. This is reported in
`reports/c2_tier2_summary.json` as **evidence of bounded value**, matching the
thesis position that C2 is a weak-but-clean feature.

## 5. Run

```
python scripts/c2_tier2_censys.py            # enrich+classify (network, once)
python scripts/c2_tier2_censys.py --offline  # re-run from cache only
```

Writes `reports/c2_tier2_report.csv` (per-IP), `reports/c2_tier2_summary.json`,
`reports/c2_retiering_v2.csv` (per-sample `kept_c2` after Tier-2 re-tiering).