# DroidForensix — Usage Guide

DroidForensix is used at three levels depending on the task:

1. **Web dashboard** — interactive analysis in the browser.
2. **REST API** — scripted/automated analysis against the local server.
3. **Offline pipeline & scripts** — headless analysis without a server.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | 3.13 tested |
| Node.js | 20+ | Frontend only (`npm run dev`) |
| Ollama | optional | LLM threat assessment (default model `mistral:3b`); auto-started by the backend if present |
| API keys | optional | VirusTotal, OTX, Shodan, Censys, OpenRouter, NVIDIA NIM — see `.env.example` |

External tools are resolved automatically:
- **JADX** — bundled under `jadx/` (unzip `tools/jadx.zip` if the directory is missing).
- **apktool / DIE / 7-Zip** — Windows bundles under `tools/`; on Linux, `diec` and `7z` are expected on `PATH` (see `backend/config.py`).
- **GeoIP** — `data/GeoLite2-City.mmdb` (already in the repo).

---

## Setup

```powershell
# from the repo root
python -m venv .venv
.\.venv\Scripts\Activate.ps1       # Windows  (or `source .venv/bin/activate` on Linux/macOS)
pip install -r requirements.txt     # latest deps
# -- or -- pinned, reproducible:
pip install -r requirements-lock.txt

Copy-Item .env.example .env         # then add any API keys
```

---

## 1. Web dashboard

```powershell
# Terminal A — backend (http://localhost:8000)
.\run_backend.bat
#   equivalent: python -m backend.main
#   equivalent: python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal B — frontend (http://localhost:5173)
.\run_frontend.bat
#   equivalent: cd frontend; npm install; npm run dev
```

Open `http://localhost:5173`, drag-and-drop an APK, and wait for the live analysis stream
(sent over the `/ws` WebSocket). The dashboard shows verdict + confidence, family attribution,
dissection tabs (manifest/permissions/components/code/strings/DEX/native libs), threat chains,
threat intel, and a downloadable PDF report.

---

## 2. REST API

All endpoints live on `http://localhost:8000`. Health check:

```bash
curl http://localhost:8000/
# {"status":"ok", ...}
```

**Upload an APK and analyze it:**

```bash
# 1) upload (multipart form, field name "file")
curl -X POST http://localhost:8000/api/upload -F "file=@samples/RTO.apk"
# → { "upload_id": "...", "sample_id": "<sha256>", ... }

# 2) trigger analysis
curl -X POST http://localhost:8000/api/analyze/<upload_id>

# 3) fetch the full report
curl http://localhost:8000/api/sample/<sample_id>

# 4) key views
curl http://localhost:8000/api/sample/<sample_id>/threat-summary
curl http://localhost:8000/api/sample/<sample_id>/attribution
curl http://localhost:8000/api/sample/<sample_id>/dissection
curl http://localhost:8000/api/sample/<sample_id>/threat-intel
curl http://localhost:8000/api/sample/<sample_id>/obfuscation

# 5) exports
curl http://localhost:8000/api/sample/<sample_id>/threat-intel/export/csv
curl http://localhost:8000/api/sample/<sample_id>/threat-intel/export/stix
curl http://localhost:8000/api/sample/<sample_id>/threat-intel/export/yara

# 6) PDF report
curl -X POST http://localhost:8000/api/sample/<sample_id>/report/pdf
```

**Analyze without upload** (server must be able to read the path):

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"apk_path": "samples/malware/<hash>.apk"}'
```

Real-time progress: connect to `ws://localhost:8000/ws` and listen for `event_type` messages while
`/api/analyze/<upload_id>` runs.

---

## 3. Offline pipeline & scripts

### Full 18-step pipeline (no server needed)

```bash
python analysis/pipeline.py <apk_path> [work_dir]
#   default work_dir = analysis/work
```

- Output: `[work_dir]/<sha256>/pipeline_result.json` (plus per-step intermediate files).
- Each step has a 300 s timeout (`STEP_TIMEOUT` in `backend/config.py`).
- The pipeline also runs step-by-step: `python analysis/step1_apk_extraction.py <apk> [work_dir]`,
  then `step2`, `step3`, … — each validates the previous step's output.

### Fast malware/benign classifier

```python
from analysis.classify_fast import classify_malware_fast

is_malware, confidence = classify_malware_fast("path/to.apk", pipeline_timeout=600)
print(is_malware, f"{confidence:.1%}")
```

### API processor (single APK via backend code path)

```bash
python backend/core/apk_processor.py <path_to_apk>
python backend/core/androguard_analyzer.py <path_to_apk> [--no-deep]
```

### Reversing / packer research tools

```bash
# Ijiami oracle probing (native lib → JNI trace + blob sweep; Kali-oriented output paths)
python scripts/ijiami_oracle.py <lib.so> [symbol]         # symbol defaults to JNI_OnLoad

# generic APK/.so dissection
python scripts/dissect.py <apk_or_so> --workdir analysis/dissect --out result.json

# native emulation (Unicorn-based ELF replay)
python scripts/emulate.py --apk <apk> --workdir analysis/emulate
python scripts/emulate.py --so <lib.so> --sym <symbol> --prefer-arch arm64

# packer-agnostic unpack dispatcher (RTO master-key recovery)
python scripts/unpack.py <apk> --workdir analysis/unpack --out unpack_report.json

# IOC catalog scan (scans the configured sample tree from the top of the file)
python ioc_scanner.py
```

**RTO / BeatBanker stage-3 string replay** (the thesis case study) is exercised through its
acceptance test — it regenerates the installer strings from the CJK pool and compares against
the ground truth:

```bash
python -m pytest tests/test_stage3_replay.py -v
```

---

## 4. Command-line interface

A thin CLI wraps the core entry points (no install required — run from the repo root):

```bash
python -m droidforensix analyze <apk> [--workdir dir] [--json]   # full offline pipeline
python -m droidforensix classify <apk> [--timeout 600]           # fast mal/ben verdict
python -m droidforensix serve [--host 0.0.0.0 --port 8000 --reload]
python -m droidforensix unpack <apk> [--workdir dir] [--out file]
python -m droidforensix version
```

After `pip install .`, the same commands are available as `droidforensix ...`.
Smoke tests: `python -m pytest tests/test_cli.py -v`.

---

## 5. Tests

```bash
# Python backend + pipeline (533 tests)
python -m pytest tests/ -v

# Frontend (React + Vitest)
cd frontend && npm test
```

CI runs both suites on every push/PR (`.github/workflows/test.yml`).

---

## 5. Reproducing evaluation metrics

The family-ID and indicator-validation numbers are reproducible from committed artifacts:

```bash
python analysis/mine_family_knowledge.py                                    # re-mine knowledge base
python evaluation/reeval_families.py --output-dir evaluation/metrics_v2      # re-evaluate (needs Ollama)
python evaluation/metrics_recompute.py --gt ground_truth_all_corrected.csv \
    --predictions evaluation/metrics_v2/predictions.json --output-dir evaluation/metrics_v2
```

Full methodology and current numbers: see the **Evaluation** section of the root `README.md`.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Backend starts but LLM features fail | Start Ollama (`ollama serve`) or set `LLM_PROVIDER`/`OPENROUTER_API_KEY`/`NVIDIA_NIM_API_KEY` in `.env` |
| `ModuleNotFoundError` when running from a subfolder | Run from the repo root; modules import relative to the project root |
| Upload rejected | `MAX_UPLOAD_SIZE_MB` defaults to 100 — raise it in `.env` for larger APKs |
| CORS errors in the dashboard | Ensure `CORS_ORIGINS` in `.env` includes the Vite port (`http://localhost:5173`) |
| JADX extraction fails | Verify `jadx/` exists (unzip `tools/jadx.zip`), or set `--no-deep` for AndroGuard-only analysis |
| Linux: `die`/`7z` not found | Install DIE and p7zip; `backend/config.py` resolves them from `PATH` |
| First request is slow | Backend auto-starts Ollama on first request (10–15 s) |

---

Windows/lower-level tool configuration details live in `backend/config.py`. See
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md) for how the pieces fit together.