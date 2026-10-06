"""Tests for the fresh-corpus manifest validator."""

import csv
import hashlib

from scripts.validate_fresh_corpus import validate_manifest


def _write_csv(path, fieldnames, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_valid_manifest_is_ready(tmp_path):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk bytes")
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    exclusion = tmp_path / "exclude.csv"
    _write_csv(exclusion, ["sha256"], [{"sha256": "0" * 64}])
    manifest = tmp_path / "manifest.csv"
    _write_csv(
        manifest,
        [
            "sha256",
            "path",
            "label",
            "role",
            "source",
            "source_url",
            "license",
            "collected_at",
            "notes",
        ],
        [
            {
                "sha256": sha,
                "path": "sample.apk",
                "label": "benign",
                "role": "holdout",
                "source": "fixture",
                "source_url": "https://example.invalid/sample.apk",
                "license": "fixture-license",
                "collected_at": "2026-09-24",
                "notes": "",
            }
        ],
    )

    report = validate_manifest(manifest, tmp_path, [exclusion])

    assert report["ready_for_freeze"] is True
    assert report["rows"] == 1
    assert report["valid_rows"] == 1
    assert report["errors"] == []


def test_overlap_and_hash_mismatch_fail_validation(tmp_path):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk bytes")
    other_apk = tmp_path / "other.apk"
    other_apk.write_bytes(b"other bytes")
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    exclusion = tmp_path / "exclude.csv"
    _write_csv(exclusion, ["sha256"], [{"sha256": sha}])
    manifest = tmp_path / "manifest.csv"
    _write_csv(
        manifest,
        [
            "sha256",
            "path",
            "label",
            "role",
            "source",
            "source_url",
            "license",
            "collected_at",
            "notes",
        ],
        [
            {
                "sha256": sha,
                "path": "sample.apk",
                "label": "malware",
                "role": "development",
                "source": "fixture",
                "source_url": "https://example.invalid/sample.apk",
                "license": "fixture-license",
                "collected_at": "2026-09-24",
                "notes": "",
            },
            {
                "sha256": "1" * 64,
                "path": "other.apk",
                "label": "malware",
                "role": "development",
                "source": "fixture",
                "source_url": "https://example.invalid/other.apk",
                "license": "fixture-license",
                "collected_at": "2026-09-24",
                "notes": "",
            },
        ],
    )

    report = validate_manifest(manifest, tmp_path, [exclusion])

    assert report["ready_for_freeze"] is False
    assert any("sha256 does not match" in error for error in report["errors"])
    assert any("overlaps" in error for error in report["errors"])
