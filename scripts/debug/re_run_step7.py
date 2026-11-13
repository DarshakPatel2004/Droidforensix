"""
Re-run step 7 (LLM assessment) on previously analysed samples.

Loads existing step5/step6/step8 results and re-assesses each sample. Merges the former
re_run_step7.py (Ollama) and re_run_step7_openrouter.py (OpenRouter) scripts.

Usage:
    python scripts/debug/re_run_step7.py --provider ollama
    python scripts/debug/re_run_step7.py --provider openrouter   # needs OPENROUTER_API_KEY
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from analysis.step7_llm_assessment import assess_with_llm  # noqa: E402
from backend.config import settings  # noqa: E402

PROVIDERS = ("ollama", "openrouter")


def configure_provider(provider: str) -> str:
    """Set the environment for the chosen provider. Returns the model name for the log."""
    os.environ["LLM_PROVIDER"] = provider
    if provider == "ollama":
        os.environ.pop("NVIDIA_NIM_API_KEY", None)
        os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
        os.environ.setdefault("OLLAMA_MODEL", "mistral:7b-instruct-q4_K_M")
        return os.environ["OLLAMA_MODEL"]
    if not os.environ.get("OPENROUTER_API_KEY"):
        sys.exit("[!] Set OPENROUTER_API_KEY first (it is never read from source code).")
    return os.environ.get("OPENROUTER_MODEL", settings.OPENROUTER_MODEL)


def load_inputs(sample_dir: Path):
    with open(sample_dir / "step6_chains.json", "r", encoding="utf-8") as f:
        chains = json.load(f)
    with open(sample_dir / "step5_c2s.json", "r", encoding="utf-8") as f:
        c2s = json.load(f)
    obf = None
    step8_path = sample_dir / "step8_obfuscation.json"
    if step8_path.exists():
        with open(step8_path, "r", encoding="utf-8") as f:
            obf = json.load(f)
    return chains, c2s, obf


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--provider", choices=PROVIDERS, default="ollama")
    args = parser.parse_args()

    model = configure_provider(args.provider)
    work_dir = settings.WORK_DIR
    samples = sorted(
        d for d in work_dir.iterdir()
        if d.is_dir() and not d.name.startswith("test") and d.name not in ("mal", "RTO")
        and (d / "step6_chains.json").exists()
    )

    llm_ok = llm_fallback = 0
    total = len(samples)
    print(f"[*] Re-running step7 on {total} samples via {args.provider}, model {model}")
    print("=" * 70)

    for i, sample_dir in enumerate(samples, 1):
        sid = sample_dir.name
        try:
            chains, c2s, obf = load_inputs(sample_dir)
            start = time.time()
            result = assess_with_llm(chains, c2s, obf)
            elapsed = time.time() - start

            method = result.get("method", result.get("status", "unknown"))
            severity = result.get("severity", result.get("threat_level", "unknown"))
            risk_score = result.get("risk_score", 0)
            if method == "llm":
                llm_ok += 1
                tag = "LLM"
            else:
                llm_fallback += 1
                tag = f"FALLBACK({method})"

            print(f"  [{i:3d}/{total}] {sid[:16]:16s} | {tag:20s} | severity={severity:8s} | risk={risk_score:3d} | {elapsed:5.1f}s")
            with open(sample_dir / "step7_assessment.json", "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            print(f"  [{i:3d}/{total}] {sid[:16]:16s} | ERROR: {e}")
            llm_fallback += 1

    print("=" * 70)
    print(f"[+] Complete: {total} samples")
    print(f"    LLM OK:       {llm_ok:4d} ({100 * llm_ok / max(total, 1):.1f}%)")
    print(f"    Fallback:     {llm_fallback:4d} ({100 * llm_fallback / max(total, 1):.1f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
