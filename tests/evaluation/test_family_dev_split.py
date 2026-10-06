"""Tests for the frozen family dev/holdout boundary."""

import csv

import pytest

from evaluation import run_validation_359


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
