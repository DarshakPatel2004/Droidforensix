"""CLI entry point for the DroidForensix forum scraper.

Usage:
    python -m forum_scraper.main --c2-file c2s.json --output links.csv \
        --source reddit,github --limit 100

Credentials come from environment variables (never commit them):
    REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USER_AGENT, GITHUB_TOKEN
"""

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from urllib.parse import urlparse

import yaml

from .dedup import deduplicate
from .github_scraper import GitHubScraper
from .linker import (
    C2Indicator,
    classify_indicator,
    find_matches,
    is_bot_content,
    make_snippet,
    score_filter,
)
from .reddit_scraper import RedditScraper, utc_iso
from .storage import Storage

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = Path(__file__).resolve().parent / "config.yaml"

CSV_HEADERS = [
    "c2_indicator",
    "forum_url",
    "date",
    "username",
    "snippet",
    "confidence",
    "source",
]


def load_config(config_path: Optional[str]) -> Dict[str, Any]:
    path = Path(config_path or DEFAULT_CONFIG)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_c2_indicators(c2_file: str, min_confidence: float = 0.0) -> List[C2Indicator]:
    """Parse the DroidForensix C2 export into indicators.

    Accepts a single JSON/CSV/text file, or a DIRECTORY of per-sample
    pipeline_result.json files (the pipeline's native output layout),
    which are aggregated and deduplicated by indicator value.
    """
    path = Path(c2_file)
    if not path.exists():
        raise FileNotFoundError(f"C2 file not found: {path}")

    records: List[Dict[str, Any]] = []
    if path.is_dir():
        records = _aggregate_pipeline_results(path)
    elif path.suffix.lower() == ".json":
        # utf-8-sig: Windows tooling (PowerShell, Excel) emits UTF-8 BOMs
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(payload, dict):
            for key in ("c2_infrastructure", "indicators", "results", "c2s"):
                if isinstance(payload.get(key), list):
                    records = payload[key]
                    break
            else:
                raise ValueError(
                    "JSON C2 file must be a list or contain a "
                    "'c2_infrastructure'/'indicators'/'results' list"
                )
        elif isinstance(payload, list):
            records = payload
        else:
            raise ValueError("Unsupported JSON shape in C2 file")
    elif path.suffix.lower() == ".csv":
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                records.append(row)
    else:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            records.append({"value": parts[0], "confidence": parts[1] if len(parts) > 1 else "1.0"})

    indicators: List[C2Indicator] = []
    for record in records:
        if isinstance(record, str):
            value, confidence = record, 1.0
        else:
            value = (
                record.get("value")
                or record.get("domain")
                or record.get("ip")
                or record.get("indicator")
                or record.get("raw_url")
            )
            confidence = float(record.get("confidence", 1.0) or 1.0)
        if not value:
            continue
        parsed = classify_indicator(str(value))
        if parsed is None:
            logger.debug("Skipping unparseable indicator: %s", value)
            continue
        if confidence < min_confidence:
            continue
        parsed.confidence = confidence
        parsed.source_sample = str(record.get("sample_sha256", "")) if isinstance(record, dict) else ""
        indicators.append(parsed)

    return _dedupe_indicators(indicators)


def _aggregate_pipeline_results(directory: Path) -> List[Dict[str, Any]]:
    """Merge every pipeline_result.json under a directory into C2 records."""
    records: List[Dict[str, Any]] = []
    for result_path in directory.rglob("pipeline_result.json"):
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping unreadable result %s: %s", result_path, exc)
            continue
        c2_records = payload.get("c2_infrastructure") or []
        if not isinstance(c2_records, list):
            continue
        sample_id = str(payload.get("sample_id", result_path.parent.name))
        for c2 in c2_records:
            if isinstance(c2, dict):
                records.append({**c2, "sample_sha256": sample_id})
    if not records:
        logger.warning(
            "No c2_infrastructure records found under %s", directory
        )
    return records


def _dedupe_indicators(indicators: List[C2Indicator]) -> List[C2Indicator]:
    """Collapse the same indicator found in multiple samples, keep max confidence."""
    best: Dict[str, C2Indicator] = {}
    for indicator in indicators:
        key = f"{indicator.kind}:{indicator.value}"
        existing = best.get(key)
        if existing is None or indicator.confidence > existing.confidence:
            best[key] = indicator
    return sorted(best.values(), key=lambda i: i.value)


def build_links(
    indicators: List[C2Indicator],
    raw_records: List[Dict[str, Any]],
    config: Dict[str, Any],
    min_confidence: float,
    source: str,
) -> List[Dict[str, Any]]:
    """Score every raw record against every indicator; keep passable links."""
    linking = config.get("linking", {})
    exclude_domains = linking.get("exclude_domains", [])
    links: List[Dict[str, Any]] = []
    for indicator in indicators:
        for record in raw_records:
            body = record.get("body", "")
            if not body:
                continue
            if is_bot_content(record.get("username", ""), body):
                continue
            matches = find_matches(indicator, body, exclude_domains=exclude_domains)
            for match in matches:
                if not score_filter(match, min_confidence):
                    continue
                links.append(
                    {
                        "c2_indicator": indicator.value,
                        "forum_url": record.get("url", ""),
                        "date": _record_date(record),
                        "username": record.get("username", ""),
                        "snippet": make_snippet(body, match.match_start, match.match_end),
                        "confidence": round(match.confidence, 2),
                        "source": source,
                    }
                )
    return links


def _record_date(record: Dict[str, Any]) -> str:
    if record.get("created_utc"):
        return utc_iso(float(record["created_utc"]))
    return record.get("date") or record.get("created") or ""


def repo_of(url: str) -> Optional[str]:
    """Extract 'owner/repo' from a GitHub URL; None for non-GitHub links."""
    parts = urlparse(url)
    if parts.netloc != "github.com":
        return None
    segments = [s for s in parts.path.split("/") if s]
    return "/".join(segments[:2]) if len(segments) >= 2 else None


def cap_links_per_repo(links: List[Dict[str, Any]], max_per_repo: int = 0) -> List[Dict[str, Any]]:
    """Limit how many links a single repo can contribute (0 = unlimited).

    Two passes: (1) enforce the per-repo cap, (2) rescue any C2 indicator
    that would otherwise lose ALL of its links — coverage beats diversity.
    Reddit links are unaffected.
    """
    if max_per_repo <= 0:
        return links
    counts: Dict[str, int] = {}
    kept: List[Dict[str, Any]] = []
    for link in links:
        repo = repo_of(link["forum_url"])
        if repo is None:
            kept.append(link)
            continue
        count = counts.get(repo, 0)
        if count >= max_per_repo:
            continue
        counts[repo] = count + 1
        kept.append(link)

    # Rescue: C2s whose only links were dropped by the cap keep their first.
    kept_c2s = {link.get("c2_indicator") for link in kept}
    for link in links:
        c2 = link.get("c2_indicator")
        if c2 and c2 not in kept_c2s:
            kept_c2s.add(c2)
            kept.append(link)
    return kept


def export_csv(links: List[Dict[str, Any]], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_HEADERS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(links)
    logger.info("Exported %d links to %s", len(links), path)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cross-reference C2 indicators with forum mentions (official APIs only)."
    )
    parser.add_argument("--c2-file", required=True, help="CSV/JSON export of C2 indicators")
    parser.add_argument("--output", default="c2_forum_links.csv", help="Output CSV path")
    parser.add_argument(
        "--source",
        default="reddit,github",
        help="Comma-separated sources: reddit, github",
    )
    parser.add_argument("--limit", type=int, default=0, help="Max indicators to process (0 = all)")
    parser.add_argument("--config", default=None, help="Path to config.yaml (default: package config)")
    parser.add_argument("--min-confidence", type=float, default=None, help="Override link confidence floor")
    parser.add_argument(
        "--c2-min-confidence",
        type=float,
        default=0.0,
        help="Skip pipeline C2 indicators below this confidence (default: 0.0 = all)",
    )
    parser.add_argument(
        "--max-links-per-repo",
        type=int,
        default=None,
        help="Cap GitHub links per repo (default: config linking.max_links_per_repo, 0 = unlimited)",
    )
    parser.add_argument("--no-dedup", action="store_true", help="Skip deduplication step")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argument_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    config = load_config(args.config)
    storage = Storage(config.get("storage", {}).get("db_path", "forum_scraper.db"))
    indicators = load_c2_indicators(args.c2_file, min_confidence=args.c2_min_confidence)
    if args.limit > 0:
        indicators = indicators[: args.limit]
    logger.info("Loaded %d C2 indicators", len(indicators))

    min_confidence = (
        args.min_confidence
        if args.min_confidence is not None
        else config.get("linking", {}).get("min_confidence", 0.7)
    )
    sources = [s.strip() for s in args.source.split(",") if s.strip()]

    all_raw: Dict[str, List[Dict[str, Any]]] = {}
    if "reddit" in sources:
        reddit_cfg = config.get("reddit", {})
        scraper = RedditScraper(
            client_id=os.environ.get("REDDIT_CLIENT_ID", ""),
            client_secret=os.environ.get("REDDIT_CLIENT_SECRET", ""),
            user_agent=os.environ.get("REDDIT_USER_AGENT", ""),
            storage=storage,
            subreddits=reddit_cfg.get("subreddits", []),
            min_score=reddit_cfg.get("min_score", 1),
            max_age_days=reddit_cfg.get("max_age_days", 180),
        )
        raw_by_source = []
        for indicator in indicators:
            raw_by_source.extend(scraper.scrape_indicator(indicator.value))
        all_raw["reddit"] = raw_by_source

    if "github" in sources:
        github_cfg = config.get("github", {})
        scraper = GitHubScraper(
            token=os.environ.get("GITHUB_TOKEN", ""),
            storage=storage,
            keywords=github_cfg.get("keywords", []),
            min_stars=github_cfg.get("min_stars", 0),
        )
        raw_by_source = []
        for indicator in indicators:
            raw_by_source.extend(scraper.scrape_indicator(indicator.value))
        all_raw["github"] = raw_by_source

    links: List[Dict[str, Any]] = []
    for source, raw_records in all_raw.items():
        links.extend(build_links(indicators, raw_records, config, min_confidence, source))
    logger.info("Raw links before dedup: %d", len(links))

    if not args.no_dedup:
        links = deduplicate(links)

    max_per_repo = (
        args.max_links_per_repo
        if args.max_links_per_repo is not None
        else config.get("linking", {}).get("max_links_per_repo", 0)
    )
    links = cap_links_per_repo(links, max_per_repo)

    storage.store_results(links)
    export_csv(links, args.output)
    logger.info(
        "Done: %d unique C2-to-forum links (confidence >= %.2f)",
        len(links),
        min_confidence,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
