"""Run leakage-free family validation on ground_truth_all.csv."""

import argparse
import csv
import json
import logging
import os
import subprocess
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analysis import pipeline as pipeline_module
from backend import family_id
from backend.config import settings

GROUND_TRUTH = PROJECT_ROOT / "ground_truth_all.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "evaluation" / "validation_359"

# Vendor naming aliases: a prediction is semantically correct when it matches an
# alias of the ground truth (Kaspersky's Andr/NGate-G vs our NGate, etc).
ALIASES = {
    "KungFu": "DroidKungFu",
    "Andr/NGate-G": "NGate",
    "Andr/Banker-HDY": "BankBot",
}


def load_ground_truth() -> list[dict[str, str]]:
    with GROUND_TRUTH.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def disable_ground_truth_lookup() -> None:
    """Prevent exact-label leakage while leaving production code unchanged."""
    family_id.GROUND_TRUTH_FILES = []
    family_id._ground_truth_map.cache_clear()


def start_ollama() -> subprocess.Popen:
    """Start an isolated Ollama server owned by this validation run."""
    ollama = os.environ.get(
        "OLLAMA_EXE",
        r"C:\Users\darsh\AppData\Local\Programs\Ollama\ollama.exe",
    )
    host = "127.0.0.1:11435"
    environment = os.environ.copy()
    environment["OLLAMA_HOST"] = host
    process = subprocess.Popen(
        [ollama, "serve"],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://{host}/api/tags", timeout=2):
                os.environ["OLLAMA_HOST"] = f"http://{host}"
                os.environ["LLM_PROVIDER"] = "ollama"
                settings.OLLAMA_HOST = f"http://{host}"
                settings.LLM_PROVIDER = "ollama"
                return process
        except Exception:
            if process.poll() is not None:
                raise RuntimeError("Ollama server exited before becoming ready")
            time.sleep(1)
    stop_ollama(process)
    raise TimeoutError("Ollama server did not become ready within 60 seconds")


def stop_ollama(process: subprocess.Popen) -> None:
    """Stop only the Ollama server started by this run."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _init_worker():
    """Per-worker init: disable leakage, install accuracy mode, set timeouts."""
    import os
    os.environ.setdefault("LLM_PROVIDER", "ollama")
    os.environ.setdefault("OLLAMA_HOST", "http://127.0.0.1:11435")

    from backend import family_id
    family_id.GROUND_TRUTH_FILES = []
    family_id._ground_truth_map.cache_clear()

    import analysis.pipeline as pipeline_module
    original_run_step = pipeline_module._run_step

    def run_step_with_downstream_skip(step_num, sample_id, apk_size,
                                       global_start, emitter, work_dir,
                                       func, *args, **kwargs):
        if 10 <= step_num <= 18:
            return ({}, 0.0)
        return original_run_step(step_num, sample_id, apk_size, global_start,
                                 emitter, work_dir, func, *args, **kwargs)
    pipeline_module._run_step = run_step_with_downstream_skip

    class NoOpDissector:
        def __init__(self, *args, **kwargs): pass
        def dissect(self): return {}
    pipeline_module.APKDissector = NoOpDissector

    pipeline_module.STEP_TIMEOUTS[5] = 300
    pipeline_module.STEP_TIMEOUTS[6] = 180
    pipeline_module.STEP_TIMEOUTS[7] = 180
    pipeline_module.STEP_TIMEOUTS[8] = 300
    pipeline_module.STEP_TIMEOUTS[9] = 180


def _worker_run_one(row: dict, output_dir_str: str) -> dict:
    """Run one sample in a worker process (pickle-safe top-level function)."""
    from pathlib import Path
    from backend.config import settings
    settings.WORK_DIR = Path(output_dir_str)
    return run_one(row, Path(output_dir_str))


def install_accuracy_mode() -> None:
    """Keep Steps 1-9 while skipping downstream stages irrelevant to family ID."""
    original_run_step = pipeline_module._run_step

    def run_step_with_downstream_skip(
        step_num, sample_id, apk_size, global_start, emitter, work_dir, func, *args, **kwargs
    ):
        if 10 <= step_num <= 18:
            logging.info("Skipping Step %s for family-identification validation", step_num)
            return ({}, 0.0)
        return original_run_step(
            step_num, sample_id, apk_size, global_start, emitter, work_dir,
            func, *args, **kwargs
        )

    class NoOpDissector:
        def __init__(self, *args, **kwargs):
            pass

        def dissect(self):
            return {}

    pipeline_module._run_step = run_step_with_downstream_skip
    pipeline_module.APKDissector = NoOpDissector


def resolve_apk_path(row: dict[str, str]) -> str:
    """Resolve the sample's apk_path against PROJECT_ROOT when it is relative."""
    apk_path = row.get("apk_path", "")
    if not apk_path:
        return apk_path
    path = Path(apk_path)
    return str(path) if path.is_absolute() else str(PROJECT_ROOT / path)


def run_one(row: dict[str, str], output_dir: Path) -> dict:
    sha256 = row["sha256"].lower()
    try:
        result = pipeline_module.run_pipeline(
            resolve_apk_path(row), work_dir=str(output_dir), event_emitter=None
        )
        family = result.get("family_identification") or {}
        assessment = result.get("llm_assessment") or {}
        return {
            "sha256": sha256,
            "source": row["source"],
            "ground_truth": row["family"],
            "prediction": family.get("family", "unknown"),
            "confidence": family.get("confidence", 0.0),
            "method": family.get("method", "none"),
            "reasoning": family.get("reasoning", ""),
            "candidates": family.get("candidates", [])[:5],
            "risk_score": assessment.get("risk_score", 0),
            "severity": assessment.get("severity", "unknown"),
            "status": "success",
        }
    except Exception as exc:
        logging.exception("Validation failed for %s", sha256)
        return {
            "sha256": sha256,
            "source": row["source"],
            "ground_truth": row["family"],
            "prediction": "error",
            "confidence": 0.0,
            "method": "error",
            "reasoning": f"{type(exc).__name__}: {exc}",
            "candidates": [],
            "risk_score": None,
            "severity": "error",
            "status": "error",
        }


def result_from_saved_pipeline(row: dict[str, str], output_dir: Path) -> dict | None:
    """Recover a completed sample after an interrupted validation run."""
    result_path = output_dir / row["sha256"].lower() / "pipeline_result.json"
    if not result_path.exists():
        return None
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
        family = result.get("family_identification") or {}
        assessment = result.get("llm_assessment") or {}
        return {
            "sha256": row["sha256"].lower(),
            "source": row["source"],
            "ground_truth": row["family"],
            "prediction": family.get("family", "unknown"),
            "confidence": family.get("confidence", 0.0),
            "method": family.get("method", "none"),
            "reasoning": family.get("reasoning", ""),
            "candidates": family.get("candidates", [])[:5],
            "risk_score": assessment.get("risk_score", 0),
            "severity": assessment.get("severity", "unknown"),
            "status": "success",
        }
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        logging.warning("Could not recover %s: %s", row["sha256"], exc)
        return None


def save_checkpoint(output_dir: Path, results: list[dict]) -> None:
    """Persist results after each sample so interruption is recoverable."""
    predictions_path = output_dir / "predictions.json"
    temporary_path = output_dir / "predictions.json.tmp"
    temporary_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    temporary_path.replace(predictions_path)
    report = build_report(results)
    report_path = output_dir / "validation_report.partial.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def load_checkpoint(output_dir: Path) -> dict[str, dict]:
    checkpoint = output_dir / "predictions.json"
    if not checkpoint.exists():
        return {}
    try:
        saved = json.loads(checkpoint.read_text(encoding="utf-8"))
        return {
            row["sha256"].lower(): row
            for row in saved
            if row.get("status") == "success"
        }
    except (OSError, json.JSONDecodeError, TypeError):
        logging.warning("Ignoring invalid checkpoint: %s", checkpoint)
        return {}


def is_correct(prediction: str, ground_truth: str) -> bool:
    if prediction.strip().casefold() == ground_truth.strip().casefold():
        return True
    return ALIASES.get(ground_truth.strip(), "").casefold() == prediction.strip().casefold()


def group_metrics(rows: list[dict], key: str) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row[key]].append(row)
    return [
        {
            "group": group,
            "total": len(members),
            "correct": sum(is_correct(r["prediction"], r["ground_truth"]) for r in members),
            "accuracy": round(
                sum(is_correct(r["prediction"], r["ground_truth"]) for r in members)
                / len(members),
                4,
            ),
        }
        for group, members in sorted(
            groups.items(), key=lambda item: (-len(item[1]), item[0])
        )
    ]


def classification_metrics(rows: list[dict]) -> dict:
    labels = sorted(
        {row["ground_truth"] for row in rows}
        | {row["prediction"] for row in rows}
    )
    per_family = []
    for label in labels:
        true_positive = sum(
            row["ground_truth"] == label and row["prediction"] == label for row in rows
        )
        false_positive = sum(
            row["ground_truth"] != label and row["prediction"] == label for row in rows
        )
        false_negative = sum(
            row["ground_truth"] == label and row["prediction"] != label for row in rows
        )
        per_family.append(
            {
                "family": label,
                "support": true_positive + false_negative,
                "precision": round(
                    true_positive / (true_positive + false_positive), 4
                )
                if true_positive + false_positive
                else 0.0,
                "recall": round(
                    true_positive / (true_positive + false_negative), 4
                )
                if true_positive + false_negative
                else 0.0,
            }
        )
    correct = sum(is_correct(row["prediction"], row["ground_truth"]) for row in rows)
    return {
        "evaluated": sum(row["status"] == "success" for row in rows),
        "errors": sum(row["status"] != "success" for row in rows),
        "accuracy": round(correct / len(rows), 4) if rows else 0.0,
        "precision_macro": round(
            sum(row["precision"] for row in per_family) / len(per_family), 4
        )
        if per_family
        else 0.0,
        "recall_macro": round(
            sum(row["recall"] for row in per_family) / len(per_family), 4
        )
        if per_family
        else 0.0,
        "per_family_precision_recall": per_family,
    }


def build_report(rows: list[dict]) -> dict:
    failures = [
        row
        for row in rows
        if row["status"] != "success"
        or not is_correct(row["prediction"], row["ground_truth"])
    ]
    return {
        "dataset": str(GROUND_TRUTH),
        "evaluation_mode": "accurate_family_identification_steps_1_9",
        "skipped_pipeline_steps": list(range(10, 19)),
        "total_samples": len(rows),
        "overall": classification_metrics(rows),
        "per_family_accuracy": group_metrics(rows, "ground_truth"),
        "per_source_accuracy": group_metrics(rows, "source"),
        "failure_count": len(failures),
        "failures": failures[:15],
        "prediction_counts": dict(Counter(row["prediction"] for row in rows)),
    }


def main() -> None:
    # Load .env into os.environ so child workers inherit NIM key
    load_dotenv(PROJECT_ROOT / ".env")

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-samples", type=int, default=0)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--parallel", "-p", type=int, default=0,
                        help="Number of parallel workers (0 = sequential, 1+ = parallel)")
    args = parser.parse_args()

    rows = load_ground_truth()
    if args.max_samples:
        rows = rows[: args.max_samples]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    settings.WORK_DIR = args.output_dir
    disable_ground_truth_lookup()
    install_accuracy_mode()
    pipeline_module.STEP_TIMEOUTS[5] = 300
    pipeline_module.STEP_TIMEOUTS[6] = 180
    pipeline_module.STEP_TIMEOUTS[7] = 180
    pipeline_module.STEP_TIMEOUTS[8] = 300
    pipeline_module.STEP_TIMEOUTS[9] = 180
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    saved_results = load_checkpoint(args.output_dir)
    results = []
    pending_rows = []
    for row in rows:
        sha256 = row["sha256"].lower()
        saved = saved_results.get(sha256) or result_from_saved_pipeline(row, args.output_dir)
        if saved:
            results.append(saved)
        else:
            pending_rows.append(row)
    print(
        f"Checkpoint: recovered {len(results)} completed sample(s); "
        f"{len(pending_rows)} remaining.",
        flush=True,
    )

    if not pending_rows:
        report = build_report(results)
        (args.output_dir / "validation_report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print(f"Reports: {args.output_dir}")
        return

    os.environ["LLM_PROVIDER"] = "ollama"
    os.environ["OLLAMA_HOST"] = "http://127.0.0.1:11435"
    print("Using Ollama for LLM", flush=True)
    ollama_process = start_ollama()
    try:
        recovered_count = len(results)
        parallel = args.parallel
        if parallel <= 1:
            # --- Sequential (original behavior) ---
            for index, row in enumerate(pending_rows, start=1):
                global_index = recovered_count + index
                print(f"[{global_index}/{len(rows)}] {row['sha256']} ({row['source']})", flush=True)
                result = run_one(row, args.output_dir)
                results.append(result)
                save_checkpoint(args.output_dir, results)
                print(
                    f"  {result['status']}: {result['prediction']} ({result['confidence']})",
                    flush=True,
                )
        else:
            # --- Parallel ---
            n_workers = min(parallel, len(pending_rows))
            print(f"Processing {len(pending_rows)} samples with {n_workers} workers...", flush=True)
            with ProcessPoolExecutor(
                max_workers=n_workers,
                initializer=_init_worker,
            ) as executor:
                futures = {
                    executor.submit(_worker_run_one, row, str(args.output_dir)): row
                    for row in pending_rows
                }
                done = 0
                for future in as_completed(futures):
                    row = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "sha256": row["sha256"].lower(),
                            "source": row["source"],
                            "ground_truth": row["family"],
                            "prediction": "error",
                            "confidence": 0.0,
                            "method": "error",
                            "reasoning": f"{type(exc).__name__}: {exc}",
                            "candidates": [],
                            "risk_score": None,
                            "severity": "error",
                            "status": "error",
                        }
                    done += 1
                    results.append(result)
                    save_checkpoint(args.output_dir, results)
                    print(
                        f"  [{recovered_count + done}/{len(rows)}] {row['sha256']}: "
                        f"{result['status']}: {result['prediction']} ({result['confidence']})",
                        flush=True,
                    )

        report = build_report(results)
        (args.output_dir / "predictions.json").write_text(
            json.dumps(results, indent=2), encoding="utf-8"
        )
        (args.output_dir / "validation_report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print(json.dumps(report["overall"], indent=2))
        print(f"Reports: {args.output_dir}")
    finally:
        stop_ollama(ollama_process)
        print("Stopped Ollama.", flush=True)


if __name__ == "__main__":
    main()
