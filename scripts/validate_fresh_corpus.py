"""Validate a fresh APK corpus manifest without scoring its samples."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import string
from pathlib import Path
from typing import Iterable

REQUIRED_COLUMNS = (
    "sha256",
    "path",
    "label",
    "role",
    "source",
    "source_url",
    "license",
    "collected_at",
    "notes",
)
PROVENANCE_COLUMNS = ("source", "source_url", "license", "collected_at")
HEX_DIGITS = frozenset(string.hexdigits)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_excluded_hashes(paths: Iterable[Path]) -> set[str]:
    excluded: set[str] = set()
    for path in paths:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or "sha256" not in reader.fieldnames:
                raise ValueError(f"exclusion file has no sha256 column: {path}")
            excluded.update(
                row["sha256"].strip().lower()
                for row in reader
                if row.get("sha256", "").strip()
            )
    return excluded


def validate_manifest(
    manifest: Path,
    root: Path,
    exclusion_files: Iterable[Path],
    allow_empty: bool = False,
) -> dict:
    errors: list[str] = []
    with manifest.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        columns = tuple(reader.fieldnames or ())
        rows = list(reader)

    missing_columns = [column for column in REQUIRED_COLUMNS if column not in columns]
    if missing_columns:
        errors.append(f"missing columns: {', '.join(missing_columns)}")

    excluded = load_excluded_hashes(exclusion_files) if not missing_columns else set()
    seen_hashes: set[str] = set()
    seen_paths: set[str] = set()
    valid_rows = 0

    for line_number, row in enumerate(rows, start=2):
        prefix = f"row {line_number}"
        sha = (row.get("sha256") or "").strip().lower()
        relative_path = (row.get("path") or "").strip()
        if len(sha) != 64 or any(char not in HEX_DIGITS for char in sha):
            errors.append(f"{prefix}: invalid sha256")
        if sha in seen_hashes:
            errors.append(f"{prefix}: duplicate sha256")
        seen_hashes.add(sha)
        if relative_path in seen_paths:
            errors.append(f"{prefix}: duplicate path")
        seen_paths.add(relative_path)
        if row.get("label") not in {"malware", "benign"}:
            errors.append(f"{prefix}: label must be malware or benign")
        if row.get("role") not in {"holdout", "development"}:
            errors.append(f"{prefix}: role must be holdout or development")
        for column in PROVENANCE_COLUMNS:
            if not (row.get(column) or "").strip():
                errors.append(f"{prefix}: missing {column}")
        if not relative_path:
            errors.append(f"{prefix}: missing path")
        else:
            apk_path = Path(relative_path)
            if not apk_path.is_absolute():
                apk_path = root / apk_path
            if not apk_path.is_file():
                errors.append(f"{prefix}: APK path does not exist")
            elif len(sha) == 64 and file_sha256(apk_path) != sha:
                errors.append(f"{prefix}: sha256 does not match APK bytes")
        if sha and sha in excluded:
            errors.append(f"{prefix}: sha256 overlaps an exclusion manifest")
        if not any(error.startswith(prefix) for error in errors):
            valid_rows += 1

    if not rows and not allow_empty:
        errors.append("manifest is empty; add rows before freezing")

    return {
        "manifest": str(manifest),
        "manifest_sha256": file_sha256(manifest),
        "rows": len(rows),
        "valid_rows": valid_rows,
        "excluded_hashes": len(excluded),
        "errors": errors,
        "ready_for_freeze": bool(rows) and not errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--exclude", type=Path, action="append", default=[])
    parser.add_argument("--report", type=Path)
    parser.add_argument("--allow-empty", action="store_true")
    args = parser.parse_args()

    report = validate_manifest(
        args.manifest,
        args.root,
        args.exclude,
        allow_empty=args.allow_empty,
    )
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not report["ready_for_freeze"] and not args.allow_empty:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
