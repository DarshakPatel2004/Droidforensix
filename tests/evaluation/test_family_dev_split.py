"""Tests for the frozen family dev/holdout boundary."""

import csv
from pathlib import Path

import pytest

from evaluation import run_validation_359

ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH = ROOT / "ground_truth_all.csv"
SPLIT_FILE = ROOT / "evaluation" / "holdout_split_v1.csv"

# Pinned 2026-10-18 against the 323-row manifest, for the anchor documented in
# evaluation/DEV_BASELINE.md. The 6-Oct corpus offload (ff4b752) dropped 54
# modern_eval rows that holdout_split_v1.csv still lists, and filter_by_split
# intersects the two silently - so the effective dev set fell from 264 to 228
# with no signal anywhere. If this fails, split and corpus have diverged again:
# update the pins together with the anchor doc, and say why in the commit.
EFFECTIVE_DEV_ROWS = 228
EFFECTIVE_HOLDOUT_ROWS = 95
OFFLOADED_SPLIT_ROWS = 54


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def test_effective_split_membership_matches_the_frozen_anchor():
    """Pin dev/holdout ∩ manifest so corpus drift fails loudly, not silently.

    ``filter_by_split`` intersects membership with the manifest with no warning,
    so a manifest edit quietly changes the evaluation denominator. Every A/B
    delta is stated against these counts.
    """
    manifest = {row["sha256"].lower() for row in _read_rows(GROUND_TRUTH)}
    membership = _read_rows(SPLIT_FILE)
    dev = {row["sha256"].lower() for row in membership if row["split"] == "dev"}
    holdout = {row["sha256"].lower() for row in membership if row["split"] == "holdout"}
    offloaded = len(membership) - len(dev & manifest) - len(holdout & manifest)

    assert (len(dev & manifest), len(holdout & manifest)) == (
        EFFECTIVE_DEV_ROWS,
        EFFECTIVE_HOLDOUT_ROWS,
    ), (
        "Frozen split membership no longer matches the manifest: effective "
        f"dev/holdout = {len(dev & manifest)}/{len(holdout & manifest)}, pinned "
        f"{EFFECTIVE_DEV_ROWS}/{EFFECTIVE_HOLDOUT_ROWS}. Update the pins and "
        "evaluation/DEV_BASELINE.md deliberately."
    )
    assert offloaded == OFFLOADED_SPLIT_ROWS, (
        f"{offloaded} split rows are absent from the manifest, pinned "
        f"{OFFLOADED_SPLIT_ROWS} - the split file and the corpus have diverged."
    )


def _write_membership(root, rows):
    evaluation_dir = root / "evaluation"
    evaluation_dir.mkdir()
    with (evaluation_dir / "holdout_split_v1.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=["sha256", "source", "split"])
        writer.writeheader()
        writer.writerows(rows)


def test_filter_by_split_returns_only_requested_membership(tmp_path, monkeypatch):
    _write_membership(
        tmp_path,
        [
            {"sha256": "dev-sha", "source": "fixture", "split": "dev"},
            {"sha256": "holdout-sha", "source": "fixture", "split": "holdout"},
        ],
    )
    monkeypatch.setattr(run_validation_359, "PROJECT_ROOT", tmp_path)

    rows = [
        {"sha256": "DEV-SHA", "family": "Example"},
        {"sha256": "holdout-sha", "family": "Hidden"},
    ]

    assert run_validation_359.filter_by_split(rows, "dev") == [rows[0]]


def test_filter_by_split_fails_loudly_without_membership_file(tmp_path, monkeypatch):
    monkeypatch.setattr(run_validation_359, "PROJECT_ROOT", tmp_path)

    with pytest.raises(FileNotFoundError):
        run_validation_359.filter_by_split([{"sha256": "dev-sha"}], "dev")
