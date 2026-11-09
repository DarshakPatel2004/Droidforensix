"""Reproducible malware-vs-benign evaluation of the deployed model.

Anyone can re-run this on the same frozen manifest and get the same numbers:

    .venv/Scripts/python.exe scripts/evaluate_malben.py --validate-only   # check inputs only
    .venv/Scripts/python.exe scripts/evaluate_malben.py                   # full run

The script refuses to run (exit 2) unless every input checks out:
  * every APK named in the manifest exists and matches its manifest SHA-256;
  * the model file matches the pinned SHA-256 below;
  * no manifest sample appears in the training map (no leakage).

Errors during analysis count as wrong predictions in every headline number,
so a failing sample can never raise the score. Network enrichment (CIRCL,
URLhaus) is disabled unless --allow-network is given, because it changes
between runs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_MANIFEST = ROOT / "evaluation" / "malben_eval" / "manifest.csv"
DEFAULT_OUT_DIR = ROOT / "evaluation" / "malben_eval"
TRAIN_MAP = ROOT / "evaluation" / "classifier_eval_2026-10-23" / "train_apk_map.json"
MODEL_PATH = ROOT / "evaluation" / "classifier_data" / "malben_rf.pkl"
# Pinned: any change to the model file changes this hash and fails the run.
MODEL_SHA256 = "e19c1e82b909aef6adeaba21d82b10c3372a777614cabe82e53362555318774c"
VALID_LABELS = {"malware", "benign"}
Z_95 = 1.959963984540054


class ManifestError(ValueError):
    """Raised when inputs fail validation; carries every problem found."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class Sample:
    sha256: str
    path: str
    label: str
    source: str


PREDICTION_FIELDS = ["sha256", "path", "label", "source", "status", "predicted_malware", "confidence", "correct", "error"]


def _write_predictions(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PREDICTION_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _load_done(path: Path) -> dict[str, dict]:
    """Successful earlier results keyed by sha256. CSV strings are parsed back to types."""
    if not path.exists():
        return {}
    done: dict[str, dict] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["status"] != "ok":
                continue
            row["predicted_malware"] = row["predicted_malware"] == "True"
            row["confidence"] = float(row["confidence"])
            row["correct"] = row["correct"] == "True"
            done[row["sha256"]] = row
    return done


def _display_path(path: Path) -> str:
    """Repo-relative path when inside the repo, absolute otherwise."""
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wilson_interval(successes: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """95% Wilson score interval for a proportion. Returns (0, 1) when n == 0."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def load_manifest(manifest: Path, root: Path = ROOT) -> list[Sample]:
    """Parse and verify the manifest. Collects every problem before failing."""
    problems: list[str] = []
    samples: list[Sample] = []
    seen: set[str] = set()
    with manifest.open(newline="", encoding="utf-8-sig") as handle:
        for line_no, row in enumerate(csv.DictReader(handle), start=2):
            sha = (row.get("sha256") or "").strip().lower()
            label = (row.get("label") or "").strip()
            path = (row.get("path") or "").strip()
            where = f"line {line_no}"
            if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                problems.append(f"{where}: invalid sha256 {sha!r}")
                continue
            if sha in seen:
                problems.append(f"{where}: duplicate sha256 {sha}")
                continue
            seen.add(sha)
            if label not in VALID_LABELS:
                problems.append(f"{where}: label must be malware or benign, got {label!r}")
                continue
            apk = root / path
            if not apk.is_file():
                problems.append(f"{where}: missing file {path}")
                continue
            actual = file_sha256(apk)
            if actual != sha:
                problems.append(f"{where}: {path} sha256 is {actual}, manifest says {sha}")
                continue
            samples.append(Sample(sha, path, label, (row.get("source") or "").strip()))
    if not samples and not problems:
        problems.append("manifest contains no samples")
    if problems:
        raise ManifestError(problems)
    return samples


def check_no_training_overlap(samples: list[Sample], train_map: Path) -> None:
    trained = set(json.loads(train_map.read_text(encoding="utf-8")))
    overlap = sorted(s.sha256 for s in samples if s.sha256 in trained)
    if overlap:
        raise ManifestError([f"{len(overlap)} manifest samples are in the training set, e.g. {overlap[0]}"])


def check_model(model_path: Path = MODEL_PATH) -> str:
    actual = file_sha256(model_path)
    if actual != MODEL_SHA256:
        raise ManifestError([f"model sha256 is {actual}, pinned value is {MODEL_SHA256}"])
    return actual


def compute_metrics(rows: list[dict]) -> dict:
    """rows: dicts with label ('malware'|'benign'), status ('ok'|'error'), predicted_malware (bool|None)."""
    tp = sum(r["label"] == "malware" and r["status"] == "ok" and r["predicted_malware"] for r in rows)
    fn = sum(r["label"] == "malware" and not (r["status"] == "ok" and r["predicted_malware"]) for r in rows)
    tn = sum(r["label"] == "benign" and r["status"] == "ok" and not r["predicted_malware"] for r in rows)
    fp = sum(r["label"] == "benign" and r["status"] == "ok" and r["predicted_malware"] for r in rows)
    n = len(rows)
    # Denominators are whole classes, so an error counts against recall/specificity too.
    n_mal = sum(r["label"] == "malware" for r in rows)
    n_ben = sum(r["label"] == "benign" for r in rows)
    correct = tp + tn
    errors = sum(r["status"] == "error" for r in rows)

    def stat(k: int, d: int) -> dict:
        lo, hi = wilson_interval(k, d)
        return {"value": round(k / d, 4) if d else None, "ci95": [round(lo, 4), round(hi, 4)], "numerator": k, "denominator": d}

    return {
        "n": n,
        "errors": errors,
        "accuracy": stat(correct, n),
        "malware_recall": stat(tp, n_mal),
        "benign_specificity": stat(tn, n_ben),
        "confusion": {"tp": tp, "fn": fn, "tn": tn, "fp": fp},
    }


def _disable_network_enrichment() -> None:
    """Make step 5 deterministic: skip CIRCL and URLhaus lookups."""
    import analysis.step5_c2_extraction as step5

    step5.enrich_with_circl = lambda records: records
    step5.enrich_with_reputation = lambda records, work_dir: records


def _classify_one(apk: str, timeout: int, work_dir: str, allow_network: bool) -> dict:
    """Runs in a child process (see _classify_in_subprocess). Failures become error rows."""
    from analysis.classify_fast import classify_malware_fast

    if not allow_network:
        _disable_network_enrichment()
    try:
        is_malware, confidence = classify_malware_fast(apk, pipeline_timeout=timeout, work_dir=work_dir)
        return {"status": "ok", "predicted_malware": bool(is_malware), "confidence": float(confidence), "error": ""}
    except Exception as exc:
        return {"status": "error", "predicted_malware": None, "confidence": None, "error": f"{type(exc).__name__}: {exc}"}


def _classify_in_subprocess(apk: str, timeout: int, work_dir: str, allow_network: bool) -> dict:
    """Parent side. The pipeline's own timeout cannot stop a stuck step, so each sample runs in
    a child process that the parent kills at a hard wall-clock cap."""
    cap = timeout + 60
    cmd = [sys.executable, str(Path(__file__).resolve()), "--classify-one", apk, work_dir, str(timeout), "1" if allow_network else "0"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=cap, cwd=ROOT)
        lines = proc.stdout.strip().splitlines()
        if proc.returncode == 0 and lines:
            return json.loads(lines[-1])
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
        return {"status": "error", "predicted_malware": None, "confidence": None, "error": f"child exit {proc.returncode}: {tail[0]}"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "predicted_malware": None, "confidence": None, "error": f"TimeoutError: hard cap {cap}s exceeded"}
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)  # keep only the report and predictions


def _child_main(argv: list[str]) -> int:
    apk, work_dir, timeout, allow_network = argv[0], argv[1], int(argv[2]), argv[3] == "1"
    row = _classify_one(apk, timeout, work_dir, allow_network)
    print(json.dumps(row), flush=True)
    return 0


def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _sklearn_version() -> str:
    try:
        import sklearn

        return sklearn.__version__
    except ImportError:
        return "not installed"


def run(args: argparse.Namespace) -> int:
    try:
        samples = load_manifest(args.manifest)
        check_no_training_overlap(samples, TRAIN_MAP)
        model_sha = check_model()
    except ManifestError as exc:
        for problem in exc.problems:
            print(f"INPUT ERROR: {problem}", file=sys.stderr)
        return 2

    manifest_sha = file_sha256(args.manifest)
    print(f"inputs OK: {len(samples)} samples, model {model_sha[:12]}, manifest {manifest_sha[:12]}")
    if args.validate_only:
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = args.out_dir / "predictions.csv"
    done = _load_done(predictions_path)  # successful earlier results; errors are retried
    work_root = args.out_dir / "work"
    results: dict[str, dict] = dict(done)
    pending = [s for s in samples if s.sha256 not in done]
    print(f"{len(done)} resumed, {len(pending)} to run, {args.workers} worker(s)", flush=True)

    finished = len(done)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(_classify_in_subprocess, str(ROOT / s.path), args.timeout, str(work_root / s.sha256), args.allow_network): s
            for s in pending
        }
        for future in as_completed(futures):
            sample = futures[future]
            try:
                row = future.result()
            except Exception as exc:  # a crashed worker is scored as a wrong prediction too
                row = {"status": "error", "predicted_malware": None, "confidence": None, "error": f"{type(exc).__name__}: {exc}"}
            row.update(sha256=sample.sha256, path=sample.path, label=sample.label, source=sample.source)
            results[sample.sha256] = row
            finished += 1
            _write_predictions(predictions_path, [results[s.sha256] for s in samples if s.sha256 in results])
            print(f"[{finished}/{len(samples)}] {sample.label} {row['status']}", flush=True)
    shutil.rmtree(work_root, ignore_errors=True)

    rows = [results[s.sha256] for s in samples]
    for row in rows:
        row["correct"] = row["status"] == "ok" and row["predicted_malware"] == (row["label"] == "malware")
    _write_predictions(predictions_path, rows)

    metrics = compute_metrics(rows)
    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": _git_commit(),
        "manifest": _display_path(args.manifest),
        "manifest_sha256": manifest_sha,
        "model": _display_path(MODEL_PATH),
        "model_sha256": model_sha,
        "python": platform.python_version(),
        "sklearn": _sklearn_version(),
        "network_enrichment": "enabled" if args.allow_network else "disabled",
        "pipeline": "classify_malware_fast (steps 1-6, no LLM)",
        "label_counts": dict(Counter(s.label for s in samples)),
        "metrics": metrics,
    }
    (args.out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    acc = metrics["accuracy"]
    print(f"accuracy {acc['value']:.4f} (95% CI {acc['ci95'][0]:.4f}-{acc['ci95'][1]:.4f}), n={metrics['n']}, errors={metrics['errors']}")
    print(f"report: {args.out_dir / 'report.json'}")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--classify-one":  # internal: one sample in a child process
        return _child_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--timeout", type=int, default=600, help="per-sample pipeline timeout in seconds")
    parser.add_argument("--validate-only", action="store_true", help="check inputs and stop")
    parser.add_argument("--workers", type=int, default=4, help="samples analysed in parallel")
    parser.add_argument("--allow-network", action="store_true", help="keep CIRCL/URLhaus enrichment on (not reproducible)")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
