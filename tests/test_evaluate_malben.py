"""Tests for scripts/evaluate_malben.py: input validation and metric math."""

import csv
import hashlib
import json
from pathlib import Path

import pytest

from scripts import evaluate_malben as em


def _write_apk(root, name: bytes) -> tuple[str, str]:
    rel = f"apks/{name.decode()}.apk"
    (root / "apks").mkdir(exist_ok=True)
    (root / rel).write_bytes(name)
    return rel, hashlib.sha256(name).hexdigest()


def _manifest(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sha256", "path", "label", "source"])
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_wilson_interval_matches_reference_value():
    lo, hi = em.wilson_interval(11, 20)
    assert lo == pytest.approx(0.3419, abs=1e-3)
    assert hi == pytest.approx(0.7419, abs=1e-3)


def test_wilson_interval_empty_is_full_range():
    assert em.wilson_interval(0, 0) == (0.0, 1.0)


def test_load_manifest_accepts_valid_rows(tmp_path):
    rel, sha = _write_apk(tmp_path, b"alpha")
    manifest = _manifest(tmp_path / "m.csv", [{"sha256": sha, "path": rel, "label": "malware", "source": "x"}])
    samples = em.load_manifest(manifest, root=tmp_path)
    assert [s.sha256 for s in samples] == [sha]


def test_load_manifest_reports_every_problem(tmp_path):
    rel, sha = _write_apk(tmp_path, b"beta")
    manifest = _manifest(
        tmp_path / "m.csv",
        [
            {"sha256": sha, "path": rel, "label": "malware", "source": "x"},
            {"sha256": sha, "path": rel, "label": "benign", "source": "x"},  # duplicate
            {"sha256": "ab", "path": rel, "label": "benign", "source": "x"},  # bad hash
            {"sha256": "c" * 64, "path": "apks/none.apk", "label": "benign", "source": "x"},  # missing file
        ],
    )
    with pytest.raises(em.ManifestError) as info:
        em.load_manifest(manifest, root=tmp_path)
    text = " ".join(info.value.problems)
    assert "duplicate" in text and "invalid sha256" in text and "missing file" in text


def test_load_manifest_rejects_tampered_file(tmp_path):
    rel, sha = _write_apk(tmp_path, b"gamma")
    (tmp_path / rel).write_bytes(b"changed after hashing")
    manifest = _manifest(tmp_path / "m.csv", [{"sha256": sha, "path": rel, "label": "benign", "source": "x"}])
    with pytest.raises(em.ManifestError, match="sha256 is"):
        em.load_manifest(manifest, root=tmp_path)


def test_load_manifest_rejects_unknown_label(tmp_path):
    rel, sha = _write_apk(tmp_path, b"delta")
    manifest = _manifest(tmp_path / "m.csv", [{"sha256": sha, "path": rel, "label": "adware", "source": "x"}])
    with pytest.raises(em.ManifestError, match="label must be"):
        em.load_manifest(manifest, root=tmp_path)


def test_training_overlap_is_rejected(tmp_path):
    sample = em.Sample(sha256="d" * 64, path="p", label="malware", source="x")
    train_map = tmp_path / "train.json"
    train_map.write_text(json.dumps({"d" * 64: "samples/x.apk"}), encoding="utf-8")
    with pytest.raises(em.ManifestError, match="training set"):
        em.check_no_training_overlap([sample], train_map)


def test_compute_metrics_counts_errors_as_wrong():
    rows = [
        {"label": "malware", "status": "ok", "predicted_malware": True},
        {"label": "malware", "status": "error", "predicted_malware": None},
        {"label": "benign", "status": "ok", "predicted_malware": False},
        {"label": "benign", "status": "ok", "predicted_malware": True},
    ]
    m = em.compute_metrics(rows)
    assert m["confusion"] == {"tp": 1, "fn": 1, "tn": 1, "fp": 1}
    assert m["accuracy"]["numerator"] == 2 and m["accuracy"]["denominator"] == 4
    assert m["malware_recall"]["value"] == 0.5
    assert m["benign_specificity"]["value"] == 0.5
    assert m["errors"] == 1


def test_display_path_handles_relative_and_outside_paths(tmp_path, monkeypatch):
    # Regression: a relative --manifest used to crash relative_to(ROOT) after all samples ran.
    monkeypatch.chdir(em.ROOT)
    assert em._display_path(Path("evaluation") / "FRESH_CORPUS_MANIFEST.csv") == str(Path("evaluation") / "FRESH_CORPUS_MANIFEST.csv")
    assert em._display_path(em.ROOT / "evaluation" / "FRESH_CORPUS_MANIFEST.csv") == str(Path("evaluation") / "FRESH_CORPUS_MANIFEST.csv")
    outside = tmp_path / "m.csv"
    assert em._display_path(outside) == str(outside.resolve())


def test_load_done_restores_types_and_skips_errors(tmp_path):
    # Regression: CSV "False" is truthy as a string; resumed rows must be real booleans.
    path = tmp_path / "predictions.csv"
    em._write_predictions(
        path,
        [
            {"sha256": "a" * 64, "path": "p", "label": "benign", "source": "x", "status": "ok",
             "predicted_malware": False, "confidence": 12.5, "correct": True, "error": "",
             "model_sha256": "m" * 8, "threshold": 0.5},
            {"sha256": "b" * 64, "path": "p", "label": "malware", "source": "x", "status": "error",
             "predicted_malware": None, "confidence": None, "correct": False, "error": "boom",
             "model_sha256": "m" * 8, "threshold": 0.5},
        ],
    )
    done = em._load_done(path, "m" * 8, 0.5)
    assert set(done) == {"a" * 64}
    assert done["a" * 64]["predicted_malware"] is False
    assert done["a" * 64]["confidence"] == 12.5
    assert done["a" * 64]["correct"] is True


def test_errors_count_against_class_rates():
    # Regression: an errored benign sample used to be dropped from specificity's denominator.
    rows = [
        {"label": "benign", "status": "ok", "predicted_malware": False},
        {"label": "benign", "status": "error", "predicted_malware": None},
        {"label": "malware", "status": "ok", "predicted_malware": True},
    ]
    m = em.compute_metrics(rows)
    assert m["benign_specificity"]["denominator"] == 2
    assert m["benign_specificity"]["value"] == 0.5
    assert m["malware_recall"]["denominator"] == 1


def test_hard_cap_turns_a_hung_sample_into_an_error_row(tmp_path, monkeypatch):
    # Regression: a stuck sample used to block the run forever; the parent must kill it at the cap.
    import subprocess

    work = tmp_path / "hung_sample_dir"
    work.mkdir()

    def hang(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr(em.subprocess, "run", hang)
    row = em._classify_in_subprocess("apk", 10, str(work), False)
    assert row["status"] == "error" and "hard cap" in row["error"]
    assert not work.exists()
