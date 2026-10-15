#!/usr/bin/env python3
"""Batch front end for the master key breaker.

Runs the KDF/cipher search engine over one APK or a directory of APKs, writes the
honesty-preserving outputs (hit.json / coverage.json per APK, summary.csv for the
batch), and prints a single JSON line of counts. Misses are typed, never silent.

Static only: this script reads APK bytes, derives candidate keys, decrypts and
validates structure. It never executes a sample.

Usage:  .venv\\Scripts\\python.exe scripts/breaker.py --input <apk|dir> --out <dir> [options]
"""
import argparse
import csv
import hashlib
import json
import pathlib
import sys
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, ".")

from packers.breaker.engine import break_apk  # noqa: E402

SUMMARY_COLUMNS = (
    "apk_path",
    "sha256",
    "ciphertext_members",
    "recovered",
    "attempts_total",
    "truncated",
    "wall_s",
    "outcome",
)


def discover(input_path: pathlib.Path) -> list[pathlib.Path]:
    """Every APK to attack: a single file, or a recursive directory scan."""
    if input_path.is_file():
        return [input_path]
    return sorted(
        path for path in input_path.rglob("*.apk") if not path.name.startswith("._")
    )


def dedupe(paths: list[pathlib.Path]) -> list[pathlib.Path]:
    """Same bytes = same work: keep the first path per sha256, in input order."""
    unique: list[pathlib.Path] = []
    seen: set[str] = set()
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        unique.append(path)
    return unique


def attack(job: tuple) -> dict:
    """One APK, one summary row. Module level so ProcessPoolExecutor can pickle it."""
    apk_path, out_dir, attempts_cap, budget_s, depth, seeds_extra, max_strings = job
    result = break_apk(
        apk_path,
        out_dir,
        attempts_cap=attempts_cap,
        budget_s=budget_s,
        depth=depth,
        seeds_extra=seeds_extra,
        max_strings=max_strings,
    )
    return {
        "apk_path": result.apk,
        "sha256": result.sha256,
        "ciphertext_members": result.ciphertext_members,
        "recovered": 1 if result.hits else 0,
        "attempts_total": result.attempts_total,
        "truncated": result.truncated,
        "wall_s": round(result.wall_s, 3),
        "outcome": result.outcome,
    }


def write_summary(path: pathlib.Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", required=True, help="APK file or directory to scan")
    parser.add_argument("--out", required=True, help="directory for hit/coverage/summary outputs")
    parser.add_argument("--attempts-cap", type=int, default=200_000)
    parser.add_argument("--budget-s", type=float, default=300.0)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--seeds-extra", default=None, help="optional JSON/text file of extra seeds")
    parser.add_argument("--max-strings", type=int, default=2000)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args(argv)
    if not pathlib.Path(args.input).exists():
        parser.error(f"input does not exist: {args.input}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates = discover(pathlib.Path(args.input))
    unique = dedupe(candidates)
    jobs = [
        (str(path), str(out_dir), args.attempts_cap, args.budget_s, args.depth,
         args.seeds_extra, args.max_strings)
        for path in unique
    ]
    if args.jobs > 1 and len(jobs) > 1:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(attack, jobs))
    else:
        rows = [attack(job) for job in jobs]
    write_summary(out_dir / "summary.csv", rows)
    # Counts only: key material belongs in the local hit.json files, never on stdout.
    print(json.dumps({
        "apks_input": len(candidates),
        "apks_deduped": len(unique),
        "recovered": sum(row["recovered"] for row in rows),
        "miss": sum(1 for row in rows if not row["recovered"] and row["truncated"] == "none"),
        "budget": sum(1 for row in rows if not row["recovered"] and row["truncated"] != "none"),
        "out": str(out_dir),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
