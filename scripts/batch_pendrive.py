"""Batch driver: DroidForensix forensic_pipeline over unique pendrive APKs."""

import csv
import json
import multiprocessing
import sys
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

PROJECT = Path("/home/kali/DroidForensix")
sys.path.insert(0, str(PROJECT))

ROOT = PROJECT / "PENDRIVE DATA" / "PENDRIVE DATA"
INVENTORY = PROJECT / "reports" / "pendrive_inventory.csv"
WORK_DIR = PROJECT / "reports" / "pendrive_work"
RESULTS = PROJECT / "reports" / "pendrive_forensic_results.json"
MAX_WORKERS = 2
TIMEOUT_S = 1200


def analyze(apk_path: str) -> dict:
    from scripts.forensic_pipeline import run_forensic_pipeline

    try:
        report = run_forensic_pipeline(apk_path, str(WORK_DIR))
        fa = report.get("final_assessment", {})
        s1 = report.get("stage_1_threat_indicators", {})
        return {
            "apk": apk_path,
            "ok": True,
            "classification": fa.get("classification"),
            "risk_score": fa.get("risk_score"),
            "mitre_tactics": fa.get("mitre_tactics", []),
            "reasoning": fa.get("llm_consolidation", {}).get("reasoning", ""),
            "indicators_found": len(s1.get("c2_indicators", s1.get("indicators", [])) or []),
            "report": report,
        }
    except Exception:
        return {"apk": apk_path, "ok": False, "error": traceback.format_exc()[-2000:]}


def _worker(apk_path: str, queue):
    res = analyze(apk_path)
    # keep only compact summary in queue; full report read from disk afterwards
    compact = {k: v for k, v in res.items() if k != "report"}
    if res["ok"]:
        rep = res["report"]
        compact["full_report_keys"] = list(rep.keys())
    queue.put(compact)


def _run_with_timeout(apk_path: str):
    queue = multiprocessing.Queue()
    p = multiprocessing.Process(target=_worker, args=(apk_path, queue))
    p.start()
    try:
        item = queue.get(timeout=TIMEOUT_S + 60)
    except Exception:
        item = {"apk": apk_path, "ok": False, "error": f"TIMEOUT after {TIMEOUT_S}s"}
    finally:
        if p.is_alive():
            p.terminate()
        p.join()
    return item


def main():
    inv = list(csv.DictReader(open(INVENTORY)))
    seen, targets = set(), []
    for row in inv:
        sha = row["sha256"]
        if sha not in seen:
            seen.add(sha)
            targets.append((sha, row["filename"], str(ROOT / row["rel_path"])))

    print(f"{len(targets)} unique APKs to analyze with {MAX_WORKERS} workers")
    results = {}
    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(_run_with_timeout, apk): (sha, name) for sha, name, apk in targets}
        done = 0
        for fut in as_completed(futs):
            sha, name = futs[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"apk": name, "ok": False, "error": str(e)}
            results[sha] = res
            done += 1
            cls = res.get("classification") or ("ERROR/TIMEOUT")
            print(f"[{done}/{len(targets)}] {name[:50]:<50} -> {cls} "
                  f"(risk {res.get('risk_score', '-')})", flush=True)

    json.dump(results, open(RESULTS, "w"), indent=1, default=str)
    print(f"\nsaved -> {RESULTS}")


if __name__ == "__main__":
    main()
