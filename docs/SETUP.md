# DroidForensix — Setup & Data Dependencies

A fresh `git clone` succeeds, but a few runtime datasets are **not** committed
(size / third-party licensing). This file restores a complete, reproducible
environment and explains which data files are tracked and which are not.

For general usage see [USAGE.md](USAGE.md); for how the pieces fit together see
[ARCHITECTURE.md](ARCHITECTURE.md).

---

## 1. Quick install

```powershell
# from the repo root
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # Windows (or `source .venv/bin/activate` on Linux/macOS)
pip install -r requirements.txt      # latest  -- or --  pip install -r requirements-lock.txt
Copy-Item .env.example .env          # then add any API keys
```

Optional runtime (used only if present): Ollama for LLM threat assessment
(`ollama serve`, default model `mistral:3b`).

---

## 2. Data files and where they come from

`data/` is git-ignored except for four first-party files (see §3). Everything
below is data that the pipeline reads but that is **not** part of the commit:

| File | Approx. size | Git status | Needed by | Source |
|------|-------------|------------|-----------|--------|
| `GeoLite2-City.mmdb` | 63 MB | ignored | `backend/threat_intel.py` (optional), `scripts/check_legitimacy.py` (required) | MaxMind GeoLite2 |
| `drebin_sha256_family.csv` | 0.4 MB | ignored | `scripts/download_samples.py`, `scripts/download_drebin_androzoo.py` | Drebin dataset (Arp et al.) |
| `known_bad_certificates.json` | small | ignored | `analysis/step16_certificate_analysis.py` | Abuse.ch SSLBL + curated campaign entries — regenerable |

### 2a. GeoLite2-City.mmdb

Used for IP→geo enrichment in threat-intel views. The backend degrades
gracefully if it is absent; `scripts/check_legitimacy.py` fails without it.

```powershell
# 1. Create a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
# 2. Download from the MaxMind portal: GeoLite2 City databases → GeoLite2-City.mmdb
#    (or, with a downloaded license key, the direct URL from the "Download Files" page)
# 3. Place the file at data\GeoLite2-City.mmdb
```

Notes:
- The `.mmdb` is a 63 MB binary; committing it permanently bloats the repository
  and the MaxMind GeoLite2 EULA restricts redistribution, so it stays out of git.
- Do not store your MaxMind license key in `.env`; the current code has no
  auto-download step and reads the file directly.

### 2b. drebin_sha256_family.csv

`sha256,family` mapping of malware in the Drebin dataset (Arp et al., NDSS 2014,
`https://wwwsec.tu-bs.de/~danarp/drebin/`). It is consumed by the sample
downloaders when pulling APKs from AndroZoo; it is a static research artifact,
so there is no in-repo generator.

```powershell
# Obtain the mapping (Drebin dataset archive), then place it at:
#   data\drebin_sha256_family.csv
# It is then consumed automatically, e.g.:
python scripts/download_drebin_androzoo.py data/drebin_sha256_family.csv 50   # needs $env:ANDROZOO_API_KEY
```

### 2c. known_bad_certificates.json

Known-bad Android code-signing certificate fingerprints used by the certificate
analysis step (step 16). A regenerable base exists via the feed downloader
(Abuse.ch SSL Blacklist); campaign-attribution entries are local curation that
the downloader preserves and merges into.

```powershell
python scripts/download_cert_feeds.py            # refreshes data\known_bad_certificates.json
python scripts/download_cert_feeds.py -v         # verbose
```

---

## 3. Tracked files under `data/`

These are first-party configuration/rule files that ARE committed and require
no download step:

| File | Purpose |
|------|---------|
| `packer_markers.json` | Data-driven packer-brand markers (9 brands) — see [PACKERS.md](PACKERS.md) |
| `engine_allowlist.json` | Enumeration engine allowlist |
| `engine_apps_manifest.csv` | Enumeration engine manifest CSV |
| `triage_locklist_m0.csv` | Triage lock list for tier-0 families |

### The `.gitignore` rule

`data/` is ignored in `.gitignore`, with the four files above force-added
(`git add -f`). Any new third-party dataset you drop into `data/` will not show
up in `git status` — that is deliberate (size + licensing). To add a new
first-party data file, force-add it explicitly:

```powershell
git add -f data/your_new_first_party_file.json
```

---

## 4. License / redistribution notes

| Dataset | Terms to respect |
|---------|------------------|
| MaxMind GeoLite2 | Free for the documented use cases under the GeoLite2 EULA; check current redistribution terms before re-hosting the `.mmdb` |
| Drebin dataset | Published for research; keep attribution to Arp et al., NDSS 2014 |
| AndroZoo | Per-researcher API key; sample downloads are rate-limited and logged via `sample_metadata.csv` |

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Threat-intel geo fields empty | `data/GeoLite2-City.mmdb` missing — follow §2a |
| `check_legitimacy.py` errors on GeoIP import | Required (not optional) here — follow §2a |
| Sample downloader no-ops | `ANDROZOO_API_KEY` (and/or `KOODOUS_API_KEY`) not set — see `scripts/download_samples.py` |
| `ModuleNotFoundError` from a subfolder | Run from the repo root |