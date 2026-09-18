"""
Re-run step7 (LLM assessment) via OpenRouter (Qwen 80B).
Loads existing step6/step5/step8 results and re-assesses with the better model.
"""
import json
import os
import sys
import time
from pathlib import Path

os.environ['JAVA_HOME'] = r'C:\Program Files\Microsoft\jdk-21.0.11.10-hotspot'

# You must set OPENROUTER_API_KEY before running
api_key = os.environ.get("OPENROUTER_API_KEY")
if not api_key:
    print("[!] Set OPENROUTER_API_KEY first, e.g.:")
    print("    $env:OPENROUTER_API_KEY='sk-or-v1-...'")
    sys.exit(1)

os.environ['LLM_PROVIDER'] = 'openrouter'
# Model is read from .env → settings.OPENROUTER_MODEL; you can override here:
# os.environ['OPENROUTER_MODEL'] = 'nvidia/nemotron-3-ultra-550b-a55b:free'

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.step7_llm_assessment import assess_with_llm
from backend.config import settings

WORK_DIR = settings.WORK_DIR
OPENROUTER_MODEL = settings.OPENROUTER_MODEL

samples = sorted([
    d for d in WORK_DIR.iterdir()
    if d.is_dir() and not d.name.startswith('test') and d.name not in ('mal', 'RTO')
    and (d / 'step6_chains.json').exists()
])

llm_ok = 0
llm_fallback = 0
total = len(samples)

print(f"[*] Re-running step7 on {total} samples via OpenRouter...")
print(f"[*] Model: {OPENROUTER_MODEL}")
print("=" * 70)

for i, sample_dir in enumerate(samples, 1):
    sid = sample_dir.name
    step6_path = sample_dir / 'step6_chains.json'
    step5_path = sample_dir / 'step5_c2s.json'
    step8_path = sample_dir / 'step8_obfuscation.json'

    try:
        with open(step6_path, 'r', encoding='utf-8') as f:
            chains = json.load(f)
        with open(step5_path, 'r', encoding='utf-8') as f:
            c2s = json.load(f)

        obf = None
        if step8_path.exists():
            with open(step8_path, 'r', encoding='utf-8') as f:
                obf = json.load(f)

        start = time.time()
        result = assess_with_llm(chains, c2s, obf)
        elapsed = time.time() - start

        method = result.get('method', 'unknown')
        severity = result.get('severity', 'unknown')
        risk_score = result.get('risk_score', 0)

        if method == 'llm':
            llm_ok += 1
            tag = "LLM"
        else:
            llm_fallback += 1
            tag = f"FALLBACK({method})"

        print(f"  [{i:3d}/{total}] {sid[:16]:16s} | {tag:20s} | severity={severity:8s} | risk={risk_score:3d} | {elapsed:5.1f}s")

        result_path = sample_dir / 'step7_assessment.json'
        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)

    except Exception as e:
        print(f"  [{i:3d}/{total}] {sid[:16]:16s} | ERROR: {e}")
        llm_fallback += 1

print("=" * 70)
print(f"[+] Complete: {total} samples via OpenRouter ({OPENROUTER_MODEL})")
print(f"    LLM OK:       {llm_ok:4d} ({100 * llm_ok / max(total, 1):.1f}%)")
print(f"    Fallback:     {llm_fallback:4d} ({100 * llm_fallback / max(total, 1):.1f}%)")
