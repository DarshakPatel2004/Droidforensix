# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Coding standards live in `AGENTS.md` (minimal diffs, explicit names, no silent failures). Follow it.

## Commands

The local Windows interpreter is `.venv/Scripts/python.exe`; the system `python` has no pytest. Install deps with `pip install -r requirements-lock.txt` (pinned).

```bash
# Backend tests (CI runs tests/ on Python 3.10)
.venv/Scripts/python.exe -m pytest tests/ -q
.venv/Scripts/python.exe -m pytest tests/test_cli.py -q                  # one file
.venv/Scripts/python.exe -m pytest tests/test_cli.py::test_name -q       # one test
.venv/Scripts/python.exe -m pytest tests/ -q -m "not slow"               # skip JADX/external-tool tests

# Frontend (Vitest + jsdom; tests live in frontend/__tests__/)
cd frontend
npm test                                  # vitest run
npx vitest run __tests__/<name>.test.jsx  # one file (paths are relative to frontend/)
npm run lint
npm run build

# Run the app
python -m backend.main                    # FastAPI on :8000 (or: python -m droidforensix serve)
cd frontend && npm run dev                # Vite on :5173
python -m analysis.pipeline <apk>         # headless full pipeline -> analysis/work/<sha256>/pipeline_result.json
python analysis/step1_apk_extraction.py <apk> [work_dir]   # run one step; then step2 ... step18
python -m droidforensix analyze|classify|serve|unpack <apk>
```

Gotchas:
- `.github/workflows/test.yml` runs pytest, `ruff check analysis backend droidforensix tests` (pyflakes, bugbear, and isort rules, configured in `pyproject.toml`), and `npm run build`. Any failure fails the job. Run the same ruff command locally before pushing.
- `run_full_pipeline.ps1` calls `run_pipeline_direct.py`, which does not exist. Don't rely on that script.
- `tests/conftest.py` has an autouse fixture that redirects `WORK_DIR`/`UPLOADS_DIR` to a tmp dir. Mark a test `@pytest.mark.use_real_work_dir` only if it truly needs the real `analysis/work/`.
- `.env` holds live API keys and `setenv.sh` holds more. Never copy their values into code, commits, or tests.

## Architecture (big picture)

**Two-stage design.** The offline pipeline is the source of truth. The backend and dashboard only read its output.

1. `analysis/` runs 18 steps (`step1_*` … `step18_*`) against one APK. `analysis/pipeline.py:run_pipeline` orchestrates them. Each step has a timeout and validates its predecessor's output (`_validate_step_input`). The single artifact is `<work_dir>/<sha256>/pipeline_result.json`. `work_dir` defaults to `analysis/work` (`backend/config.py`).
2. `backend/` is a FastAPI app over that JSON. `backend/transformers.py:load_result` turns `pipeline_result.json` into view models. `backend/dissection.py` lazily builds the per-tab dissection data and caches it.
3. `frontend/` is a React/Vite dashboard over the REST routes and the `/ws` WebSocket. `POST /api/upload` → `POST /api/analyze/{upload_id}` (progress pushed over `/ws`) → `GET /api/sample/{sample_id}/...`.

Put detection logic in `analysis/`. Putting it in `backend/` breaks the "viewer only" split. `backend/family_id.py` is the exception: it does attribution.

**Family attribution** (`backend/family_id.py`) is three layers, in order:
1. `signature_v3`, hand-written signatures.
2. Knowledge-base matcher over `analysis/family_knowledge_base.json`, mined from corrected ground truth with anchored-token false-positive control.
3. LLM multiple-choice verdict over the signals that actually matched.

**LLM backends** (step 7 and family attribution) are Ollama, NVIDIA NIM, or OpenRouter, chosen via `.env`. `droidforensix_llm.py` (`LLMVerifier`) starts Ollama from the backend lifespan hook.

**Packer / unpacking** is static, with no emulator required. Detection is entropy and DEX-structure heuristics (`step10_binary_packing.py`) plus `data/packer_markers.json`. Recovery goes through `scripts/unpack.py`, which dispatches per packer, with `scripts/dissect.py`, `scripts/emulate.py`, and `scripts/ijiami_oracle.py` for per-artifact work. `stage3_replay.py` is a faithful port of the RTO stage-3 smali (see `tests/test_stage3_replay.py` for the acceptance check).

**Research code** is mixed in at the repo root. Root-level `.py` files (`batch_classify.py`, `brute_replay.py`, `ioc_scanner.py`, …) and `evaluation/` are one-off or validation tooling, not the product path. Don't refactor them as part of product work.

**Data and models** (`data/`, `analysis/*.pkl`, `evaluation/classifier_data/`) are shipped with the repo. Large or regenerable outputs (`analysis/work/`, `uploads/`, `samples/`, `jadx/`, `tools/`) are gitignored.

## Evaluation caveat

The README's headline numbers are not accuracy claims. Family-ID exact match is about 64%. Only about 2.4% of raw indicators are confirmed malicious C2. Ground truth is `ground_truth_all_corrected.csv`. Quote the README's "honest numbers" section, not the top-line counts, when writing about results.
