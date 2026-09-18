"""Sequential retry of timed-out pendrive APKs with larger budget."""

import json
import sys
import time
from pathlib import Path

PROJECT = Path("/home/kali/DroidForensix")
sys.path.insert(0, str(PROJECT))

RESULTS = PROJECT / "reports" / "pendrive_forensic_results.json"
WORK_DIR = PROJECT / "reports" / "pendrive_work"
TIMEOUT_S = 2400


def run_one(apk_path: str):
    import multiprocessing

    from droidforensix_llm import LLMVerifier, set_verifier
    from scripts.forensic_pipeline import run_forensic_pipeline

    set_verifier(LLMVerifier(enabled=False))  # heuristic-only mode, no Ollama calls
    try:
        report = run_forensic_pipeline(apk_path, str(WORK_DIR))
        fa = report.get("final_assessment", {})
        return {
            "apk": apk_path,
            "ok": True,
            "classification": fa.get("classification"),
            "risk_score": fa.get("risk_score"),
            "mitre_tactics": fa.get("mitre_tactics", []),
            "reasoning": fa.get("llm_consolidation", {}).get("reasoning", ""),
        }
    except Exception as e:
        return {"apk": apk_path, "ok": False, "error": repr(e)[-500:]}


def _worker(apk_path, queue):
    queue.put(run_one(apk_path))


def run_with_timeout(apk_path):
    import multiprocessing

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
    res = json.load(open(RESULTS))
    failed = [r["apk"] for r in res.values() if not r.get("ok")]
    print(f"{len(failed)} APKs to retry, {TIMEOUT_S}s budget each", flush=True)
    for i, apk in enumerate(failed, 1):
        t0 = time.time()
        print(f"[retry {i}/{len(failed)}] {Path(apk).name}", flush=True)
        r = run_with_timeout(apk)
        r["retry_seconds"] = round(time.time() - t0)
        # merge back keyed by matching original entry
        for sha, old in res.items():
            if old.get("apk") == apk:
                res[sha] = {**old, **r}
                break
        print(f"[done {i}/{len(failed)}] {Path(apk).name} -> "
              f"{r.get('classification') or 'ERROR/TIMEOUT'} "
              f"(risk {r.get('risk_score', '-')}, {r['retry_seconds']}s)", flush=True)
        json.dump(res, open(RESULTS, "w"), indent=1, default=str)
    print("RETRY COMPLETE", flush=True)


if __name__ == "__main__":
    main()
