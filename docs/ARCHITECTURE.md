# DroidForensix — Architecture

## System overview

```
                         ┌────────────────────────────────────────────────────┐
                         │            OFFLINE RESEARCH PIPELINE              │
                         │  analysis/step1..step18 -> pipeline_result.json  │
                         └──────────────────────────┬────────────────────────┘
                                                    │ load_result / transformers
┌───────────┐  HTTP+WS   ┌──────────────────────────▼────────────────────────┐
│  React    │◄──────────►│          FASTAPI BACKEND (backend/main.py)        │
│ dashboard │            │  upload · analyze · dissection · family · threat  │
└───────────┘            └──────────────────────────────────────────────────┘
```

Every APK ultimately flows through the same core: **AndroGuard extracts structure →
the 18-step pipeline accumulates evidence → a structured report is produced**.
The backend and dashboard are *viewers* over that report; they add no detection logic
of their own beyond attribution/threat aggregation.

---

## Layers

| Layer | Location | Responsibility |
|-------|----------|----------------|
| Analysis engine | `analysis/` | 18-step offline pipeline, ML classifiers, family knowledge mining, campaign clustering |
| Backend service | `backend/` | FastAPI app: uploads, orchestration, attribution, dissection, threat intel, PDF/STIX/YARA export |
| Dashboard | `frontend/` | React/Vite UI over the REST + WebSocket API |
| Research tools | `scripts/`, repo root | Packer reversing (unpack/dissect/emulate/ijiami oracle), dataset + ground-truth tooling, `stage3_replay.py` |
| Data & models | `data/`, `*.pkl` | GeoIP, packer markers, allowlists, trained classifiers |
| Tests | `tests/` | 533 pytest cases + frontend Vitest suite |

---

## Analysis engine (`analysis/`)

`analysis/pipeline.py` exposes the orchestrator:

```python
def run_pipeline(apk_path: str, work_dir: Optional[str] = None, ...)
```

- Default `work_dir` = `analysis/work` (`SETTINGS.WORK_DIR`, `backend/config.py:45`).
- Produces `[work_dir]/<sha256>/pipeline_result.json` — the single artifact the backend reads.
- Each step is a separate module with a timeout (default 300 s) and validates its predecessor's output
  (`_validate_step_input`). Run individually: `python analysis/step1_apk_extraction.py <apk> [work_dir]`, then `step2` … `step18`.

Pipeline steps:

| # | Module | Output / purpose |
|---|--------|------------------|
| 0 | `step0_master_key.py` | Master-key derivation for RTO/master-key protected APKs |
| 1 | `step1_apk_extraction.py` | AndroGuard: manifest, permissions, components, DEX metadata |
| 2 | `step2_string_enumeration.py` | Dalvik bytecode string extraction (smali fallback) |
| 3 | `step3_encoding_detection.py` | Detect base64 / hex / XOR / cipher encodings |
| 4 | `step4_decoding.py` | Decode obfuscated strings |
| 5 | `step5_c2_extraction.py`, `step5_allowlists.py`, `step5_tiers.py` | C2 indicator extraction (domains, IPs, URLs, APIs) + allowlist/tier filtering |
| 6 | `step6_correlation.py` | Build threat chains across indicators |
| 7 | `step7_llm_assessment.py` | LLM verdict + method/chain explanations (Ollama/NIM/OpenRouter) |
| 8 | `step8_obfuscation_analysis.py` | Packing, reflection, custom encryption signals |
| 9 | `step9_post_process.py` | Dedupe, confidence scoring, report assembly |
| 10–16 | `step10_binary_packing.py` … `step16_certificate_analysis.py` | Binary packing detection, string clustering, reflective tracing, native ELF analysis, network protocols, reflective-permission correlation, cert analysis |
| 17 | `step17_family_clustering.py` | Cross-sample family clustering |
| 18 | `step18_threat_synthesis.py` | Final threat-intel synthesis report |

Supporting ML / mining modules:
- `ml_classifier.py` — train/predict model (`--train`, `--predict <sha>`); uses `family_ml.pkl` + `family_ml_vectorizer.pkl`.
- `classify_fast.py` — `classify_malware_fast(apk_path, pipeline_timeout)` fast mal/ben entrypoint.
- `mine_family_knowledge.py`, `mine_discriminators.py` — mine the family knowledge base from corrected ground truth.
- `campaign_clustering.py`, `gap_signature_mining.py`, `hardcoded_secrets.py`, `labels.py`, `manifest_analysis.py`, `cert_profiles.py`, `ip_validation.py` — deeper research analyses used by the evaluation suite.

---

## Backend service (`backend/`)

`main.py` (~1,690 lines) defines 40+ REST routes + the `/ws` WebSocket stream. Lifespan
lifecycle auto-starts Ollama through `LLMVerifier` (`droidforensix_llm.py`).

| Module | Responsibility |
|--------|----------------|
| `main.py` | FastAPI app, routes, upload/analyze/orchestration, CORS, WebSocket `EventManager` |
| `core/apk_processor.py` | Full-analysis orchestrator for one APK (wraps `analysis.pipeline.run_pipeline`) |
| `core/androguard_analyzer.py` | AndroGuard-native extraction (manifest, permissions, DEX, strings); `--no-deep` mode |
| `config.py` | Pydantic `Settings`: env file, tool paths, work/reports/uploads dirs, CORS, timeouts |
| `transformers.py` | `load_result(load_all_results, transform_graph/clusters/timeline/samples_list)` — pipeline_result.json → view models |
| `dissection.py` | `APKDissector`, `SampleAPKCache` — cached, lazy tab dissection |
| `family_id.py` | 3-layer family attribution: `signature_v3` (hand-written) → knowledge-base matcher → LLM with candidate guidance |
| `threat_intel.py` | Threat-feed aggregation (VT/OTX/Shodan/Censys) — imported by `main.py` |
| `threat_intelligence.py` | Stand-alone threat-intel module (earlier variant) |
| `community_intel.py` | Cached community/C2 intel enrichment |
| `censys_enrichment.py`, `circl_client.py` | Censys Platform + CIRCL feed clients |
| `elf_analyzer.py` | Native ELF library analysis |
| `code_analysis.py` | Method-level code analysis / explanations |
| `obfuscation_view.py` | Obfuscation summary view + `deobfuscate_text` |
| `events.py`, `validators.py` | WebSocket event types/validation |
| `pdf_report.py`, `pdf_report_enhanced.py` | PDF report generation |

Request → response flow for the dashboard:

1. `POST /api/upload` (multipart `file`) → `upload_id`, `sample_id` (sha256).
2. `POST /api/analyze/{upload_id}` → runs `APKProcessor`/`run_pipeline`; progress is pushed over `/ws`.
3. Dashboard polls `GET /api/sample/{sample_id}/...`; each `transform_*` in `transformers.py`
   shapes `pipeline_result.json` + dissection caches into the view payloads.

---

## Family attribution (the 64.2% headline result)

Three independent layers vote (see `backend/family_id.py`):

1. **signature_v3** — hand-written family signatures; fires at ~93% precision.
2. **Knowledge-base matcher** — discriminators mined from corrected ground truth
   (`analysis/family_knowledge_base.json`, 38 families) with anchored-token FP control.
3. **LLM with candidate guidance** — multiple-choice verdict over actually-matched signals.

Ground truth lives at `ground_truth_all_corrected.csv` (359 malware + 100 benign, externally
re-verified on VirusTotal/MalwareBazaar). See `README.md` → Evaluation for the honest numbers.

---

## Machine-learning artifacts

| File | Role |
|------|------|
| `analysis/family_ml.pkl` + `analysis/family_ml_vectorizer.pkl` | Trained family classifier + vectorizer |
| `evaluation/family_classifier_clean.pkl` | Cleanly-retrained family model used in validation |
| `evaluation/classifier_data/malben_rf.pkl` | RandomForest mal/ben model (`ml_classifier.py`) |
| `analysis/family_knowledge_base.json`, `discriminators_36.json` | Mined per-family discriminators |

Model files for the mal/ben classifier: `analysis/classify_fast.py` and `analysis/ml_classifier.py`.

---

## Data files (`data/`)

| File | Purpose |
|------|---------|
| `GeoLite2-City.mmdb` | Offline MaxMind geolocation for C2 IPs |
| `packer_markers.json` | Packer-detection marker signatures |
| `known_bad_certificates.json` | Signing-cert blacklist |
| `engine_allowlist.json`, `engine_apps_manifest.csv` | Indicator allowlists (Firebase/Google/CDN etc. FP control) |
| `drebin_sha256_family.csv` | Drebin dataset ground-truth mapping |

---

## Packer handling

DroidForensix reconstructs protected payloads statically — no emulator required:

- **Detection:** entropy + DEX-structure heuristics (`analysis/step10_binary_packing.py`) plus
  brand-marker matching against `data/packer_markers.json` (emits `packer_brands`).
- **Dispatch / recovery:** `scripts/unpack.py` is the packer-agnostic dispatcher with typed
  error codes; `scripts/dissect.py` and `scripts/emulate.py` provide per-artifact reversal.
- **Ijiami:** native-library embedding probed via `scripts/ijiami_oracle.py`.
- **RTO / BeatBanker (thesis case study):** `stage3_replay.py` faithfully ports the Stage-3
  smali bytecode (CZRR/seed pool → LMK/NkWa rotate-multiply digest) to regenerate the
  installer strings from `cjk_pool.txt`. Acceptance: `tests/test_stage3_replay.py`
  (174 exact matches + 6 documented ground-truth artifacts).

Deep-dive write-ups: `thesis/06_unpacking_case_study.md` and `rto_analysis/`.

---

## Directory layout

```
DroidForensix/
├── backend/            FastAPI service (main.py, core/, family_id, dissection, threat_intel, …)
├── frontend/           React/Vite dashboard
├── analysis/           Offline 18-step pipeline + ML + knowledge mining
├── scripts/            Research + tooling (unpack/dissect/emulate, GT/dataset builders)
├── tests/              pytest suite (+ tests/fixtures)
├── evaluation/         Validation harness, retrained models, metrics
├── data/               GeoLite2, packer markers, allowlists, cert feeds
├── docs/               This doc, USAGE.md, dashboard guide, codebase reference
├── archive/            Archived scratch/reversing artifacts (historical, not source)
├── tools/              Bundled external binaries (apktool, DIE, jadx.zip, ghidra, node) — gitignored
├── jadx/               Extracted JADX (gitignored; unzip from tools/jadx.zip)
├── rto_analysis/       RTO unpacking case-study artifacts (gitignored)
├── samples/, APK/, data/…   Datasets (gitignored)
├── stage3_replay.py    RTO stage-3 bytecode replay
├── ioc_scanner.py      IOC scanning utility
├── droidforensix/      CLI package (python -m droidforensix <analyze|classify|serve|unpack>)
└── pyproject.toml      Packaging manifest + [project.scripts] entry point
```

Generated analysis artifacts (`analysis/work/`, `uploads/`, `evaluation_results/`, smali/JADX
outputs) are gitignored — they are regenerable from committed code.