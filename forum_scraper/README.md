# DroidForensix Forum Scraper

Cross-references C2 indicators extracted by the DroidForensix pipeline
(~1,700 indicators across 277 samples) with public discussion mentions on
Reddit and GitHub, producing high-confidence C2-to-forum links for
attribution context.

**Legal/ethical note:** this tool uses only official, ToS-compliant APIs
(PRAW for Reddit, GitHub REST + GraphQL). No scraping of unauthorized
sources (Discord, Telegram, web-scraping HTML) is performed.

## Installation

```bash
pip install -r requirements.txt
```

Credentials are read from environment variables (never commit them):

| Variable | Purpose |
| --- | --- |
| `REDDIT_CLIENT_ID` | Reddit app (script) client ID |
| `REDDIT_CLIENT_SECRET` | Reddit app (script) client secret |
| `REDDIT_USER_AGENT` | e.g. `droidforensix-malware-research/0.1 (contact@example.com)` |
| `GITHUB_TOKEN` | GitHub personal access token (repo scope recommended) |

Create a Reddit script app at https://www.reddit.com/prefs/apps and a
GitHub PAT at https://github.com/settings/tokens.

## Usage

```bash
python -m forum_scraper.main \
  --c2-file analysis/work/c2s.json \
  --output c2_forum_links.csv \
  --source reddit,github \
  --limit 100
```

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--c2-file` | (required) | JSON/CSV export of C2 indicators (see below) |
| `--output` | `c2_forum_links.csv` | Output CSV path |
| `--source` | `reddit,github` | Comma-separated sources |
| `--limit` | `0` (all) | Max indicators to process |
| `--config` | package `config.yaml` | Alternate config path |
| `--min-confidence` | config value (0.7) | Link confidence floor |
| `--c2-min-confidence` | `0.0` (all) | Skip pipeline C2s below this confidence |
| `--no-dedup` | off | Skip deduplication |

### C2 file formats

Any of:

- **Directory (pipeline native):** point `--c2-file` at a directory of
  per-sample `pipeline_result.json` files (e.g. `analysis/work/`). All
  `c2_infrastructure` records are aggregated and deduplicated by indicator
  value, keeping the highest confidence per indicator.
- **JSON (single file):** a list of records with `domain`/`ip`/`raw_url`
  and optional `confidence` keys, or an object with a
  `c2_infrastructure`/`indicators`/`results` list.
- **CSV:** columns `domain,ip,confidence` (matching the pipeline's
  validation exports).
- **Plain text:** one indicator per line, optionally `indicator,confidence`.

Use `--c2-min-confidence 0.8` to skip low-confidence indicators from the
pipeline (the export includes ad-network domains and private IPs that are
not worth querying).

### Output CSV

`c2_indicator, forum_url, date, username, snippet, confidence, source`

- `confidence` is the match confidence: 1.0 exact domain, 0.9 IP,
  0.8 subdomain; typosquat candidates score 0.5 and are excluded unless
  `--min-confidence` is lowered (review them manually — they are flagged
  via the `needs_review` field in the SQLite store).
- `date` is ISO-8601 UTC.

## How it works

```
main.py ──> reddit_scraper (PRAW, official API)
        ──> github_scraper (GraphQL issues + REST code search)
        ──> linker.py      (pure matching + confidence scoring)
        ──> dedup.py       (content-hash + indicator normalization)
        ──> storage.py     (SQLite cache + results)
```

- **Reddit:** searches each configured subreddit for the indicator, then
  scans the comments of matching submissions (Reddit's search API covers
  submissions only). Posts older than `max_age_days`, deleted posts, and
  bot/auto-mod content are skipped.
- **GitHub:** issues via GraphQL search; code/README mentions via the REST
  code search (code search is not exposed in GraphQL). Only repos whose
  name/description/topics match `malware|c2|indicator|ioc` pass the
  keyword gate. Code search is throttled to ~10 req/min.
- **Caching:** every API response is stored in SQLite (`forum_scraper.db`),
  so re-runs take minutes, not hours. Delete the cache rows to force a
  fresh scrape.
- **Dedup:** links are keyed by (whitespace-normalized content hash,
  canonical indicator). www/subdomain prefixes collapse to the registered
  domain; IPs are canonicalized. When both a domain link and an IP link
  point to the same post and the domain resolves to that IP, the duplicate
  is dropped (resolution is best-effort with a 2s timeout so dead C2s
  cannot stall the run).

## Configuration

See `config.yaml`: subreddit list, `min_score`, `max_age_days`, GitHub
keywords/`min_stars`, link confidence floor, and noise `exclude_domains`.

## Status / limitations

- Blog/RSS sources (KrebsOnSecurity, Talos, Unit42) are deferred — the
  spec marks them optional.
- GitHub Discussions search is not exposed by any official API; issue
  search covers the attribution use case.
- Sentiment (sinkholed vs active) and actor aliasing are not implemented.
