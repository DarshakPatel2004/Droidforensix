"""Tests for the dev-only scorer cache builder."""

import csv
import json

from scripts.build_dev_scorer_cache import build_cache


def _write_csv(path, fieldnames, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_build_cache_excludes_holdout_and_catch_all_rows(tmp_path):
    ground_truth = tmp_path / "ground_truth.csv"
    split_file = tmp_path / "split.csv"
    base_cache = tmp_path / "base.json"
    pipeline_dir = tmp_path / "pipeline"

    _write_csv(
        ground_truth,
        ["sha256", "family"],
        [
            {"sha256": "dev-base", "family": "KnownFamily"},
            {"sha256": "dev-fill", "family": "OtherFamily"},
            {"sha256": "dev-catchall", "family": "AndroidOS"},
            {"sha256": "holdout", "family": "SecretFamily"},
        ],
    )
    _write_csv(
        split_file,
        ["sha256", "source", "split"],
        [
            {"sha256": "dev-base", "source": "fixture", "split": "dev"},
            {"sha256": "dev-fill", "source": "fixture", "split": "dev"},
            {"sha256": "dev-catchall", "source": "fixture", "split": "dev"},
            {"sha256": "holdout", "source": "fixture", "split": "holdout"},
        ],
    )
    base_cache.write_text(
        json.dumps(
            {
                "dev-base": {"strings": ["base-token"], "domains": []},
                "holdout": {"strings": ["must-not-be-read"], "domains": []},
            }
        ),
        encoding="utf-8",
    )
    pipeline_result = pipeline_dir / "dev-fill" / "pipeline_result.json"
    pipeline_result.parent.mkdir(parents=True)
    pipeline_result.write_text(
        json.dumps(
            {
                "extraction": {
                    "string_literals": [{"value": "filled-token"}],
                    "decompiled_classes": 3,
                    "native_libs_found": [],
                },
                "manifest": {"uses_permissions": []},
                "c2_infrastructure": [],
            }
        ),
        encoding="utf-8",
    )

    cache, report = build_cache(ground_truth, split_file, pipeline_dir, base_cache)

    assert set(cache) == {"dev-base", "dev-fill"}
    assert "holdout" not in cache
    assert "dev-catchall" not in cache
    assert report["dev_scorable_rows"] == 2
    assert report["cache_rows"] == 2
    assert report["filled_from_dev_pipeline"] == 1
    assert report["missing_after_fill"] == 0
