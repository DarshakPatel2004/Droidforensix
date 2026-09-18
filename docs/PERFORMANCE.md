# Performance

## Measured baseline

Per-step timings are recorded in every `pipeline_result.json` under `timeline`
(`step1` … `step18`, `total`). From existing completed runs (n=4):

| Metric | Value |
|--------|-------|
| Total runtime | avg **101 s**, median **119 s** (min 17 s, max 237 s) |
| Top hotspot | **step1 (APK extraction)** ≈ 20 s |
| 2nd | step5 (C2 extraction) ≈ 11 s |
| 3rd | step8 (obfuscation analysis) ≈ 7 s |

## Duplicate-parse fix (step1 → step2)

Step 1 (`step1_apk_extraction.py`) already parses every DEX with AndroGuard and
returns the full string set (`dex_strings`). Step 2 (`step2_string_enumeration.py`)
used to run a **second, identical AndroGuard parse** of the same APK through
`extract_androguard_strings`.

Fix: `enumerate_strings` now reuses `extraction_result["dex_strings"]` through the
same noise/DEX filter (`_filter_dex_strings`), producing byte-identical category
output, and only falls back to a direct AndroGuard parse when Step 1 produced no
strings. Expected saving ≈ one full AndroGuard APK/DEX pass per run — the measured
step1 hotspot — with no change to downstream results.

Regression coverage: `tests/test_step2_string_reuse.py` (reuse path + fallback path).

## Hunt the next hotspots

```bash
# after any pipeline run, show the slowest steps:
python - <<'PY'
import json, glob
for p in glob.glob("analysis/work/*/pipeline_result.json"):
    t = json.load(open(p)).get("timeline", {})
    top = sorted(((k, v) for k, v in t.items() if k.startswith("step")),
                 key=lambda kv: kv[1], reverse=True)[:3]
    print(p.split("\\")[-2][:12], f"{t.get('total',0):7.1f}s",
          ", ".join(f"{k}={v:.1f}s" for k, v in top))
PY
```

Existing levers for oversized/giant APKs (documented in `run_pipeline`):
- `stop_after=8` → stops after LLM assessment (no family/forensics steps).
- `skip_steps=frozenset({3})` → skip encoding detection on giant samples.
- Per-step JSON caches (`step*.json`) already short-circuit re-analysis within a
  work dir; reuse them instead of deleting `analysis/work/<sha>/`.

## Notes

- Step 7 (LLM assessment) is optional in practice — it degrades gracefully when
  Ollama/openrouter/NVIDIA NIM is unreachable.
- Tool calls (apktool) dominate step1 on non-Windows setups where `xdg-open`
  style re-scanning applies; JADX deep extraction only happens on demand in the
  dashboard (`--no-deep` skips it).