# DroidForensix

**Automated Android malware static-analysis pipeline** — extract C2 infrastructure from bytecode without execution.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![React](https://img.shields.io/badge/React-18-blue?logo=react)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://github.com/DarshakPatel2004/project-zero/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/DarshakPatel2004/project-zero/actions/workflows/test.yml)

> **63x speedup** over manual analysis (277-sample article run). **1,711 C2 indicators** extracted from **277 malware samples** across 12 countries. **75% concentrated** in Chinese cloud providers. Dataset since grown to 459 APKs.
>
> **Read this before citing headline numbers:** validation shows exact-match family identification at **64.2%** (68.6% on specific families) and only **2.4% of raw extracted indicators confirmed as genuine C2** — see [Evaluation & Validation](#evaluation). Raw counts above reflect extraction coverage, not verified accuracy.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Key Results](#key-results)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Dashboard](#dashboard)
- [API Reference](#api-reference)
- [Evaluation](#evaluation)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Environment Variables](#environment-variables)
- [Known Limitations](#known-limitations)
- [Future Work](#future-work)

---

## What It Does

DroidForensix analyzes Android APKs **without execution** — no emulator, no sandbox. It decompiles bytecode to Java, traces method calls, extracts hardcoded indicators, correlates them against threat feeds, geolocates C2 servers, and produces a structured report.

**The problem it solves:** Manual APK analysis takes ~1 hour per sample. This pipeline does it in ~1 minute (~90 s on the LLM path, ~24 s with heuristic skip).

```
APK → Decompile (JADX) → Trace Suspicious APIs → Extract Indicators
      → Correlate (VT, OTX, Shodan, Censys) → Geolocate → Score → Report
```

### Pipeline

The 18-step pipeline (`analysis/step1_*.py` … `step18_*.py`):

1. **Extract** APK (AndroGuard: manifest, permissions, components)
2. **Enumerate** Dalvik bytecode strings via JADX
3. **Detect** encodings (base64, hex, XOR, ciphers)
4. **Decode** obfuscated strings
5. **Extract** C2 indicators (domains, IPs, hardcoded URLs, API endpoints)
6. **Correlate** across VT, OTX, Shodan, Censys (parallel threat feeds)
7. **Assess** findings via LLM (Ollama/NVIDIA NIM/OpenRouter)
8. **Analyze** obfuscation (packing, reflection, custom encryption)
9. **Post-process** dedup, scoring, report assembly
10. **Detect** binary packing
11. **Cluster** strings for decryption correlation
12. **Trace** reflective method calls
13. **Analyze** native ELF libraries
14. **Analyze** network protocols
15. **Correlate** reflective permissions
16. **Analyze** signing certificates
17. **Cluster** samples by family
18. **Synthesize** threat intelligence report

Output: structured JSON + PDF with per-phase timing.

---

## Key Results

> This table documents the published 277-sample run (see [Publication](#publication)). The dataset has since grown to **459 APKs** (359 malware + 100 benign).

| Metric | Value |
|--------|-------|
| Samples analyzed | 277 (204 timed) |
| C2 indicators extracted | **1,711** |
| Unique IPs | 203 (191 geolocated, 94%) |
| Geographic clusters | 26 across 12 countries |
| Chinese cloud concentration | **75%** (Alibaba, Tencent, CHINANET) |
| Pipeline speed (LLM path) | ~1.5 min/sample |
| Pipeline speed (heuristic skip) | ~0.4 min/sample (~40% of samples) |
| Total runtime (204 samples) | 3.2 hours sequential |
| Speedup vs. manual | **63x** |
| Recall (after heuristic fix) | **95%** (recovered from 80%) |
| Family-ID accuracy (exact match, 352 GT) | **64.2%** (226/352); **68.6%** on specific families |
| Indicator precision (validated, 380 indicators) | **2.4%** confirmed malicious; **68%** clearly benign |

### What I Got Wrong (And Fixed)

This section is intentional — research is iterative, and documenting mistakes is as important as documenting wins.

- **LLM bottleneck:** Initial pipeline called Ollama per-sample synchronously. Fixed with a heuristic pre-filter that skips the LLM layer for ~40% of benign-looking samples (~2x speedup).
- **Heuristic over-optimization:** An aggressive string-entropy filter was dropping valid C2 domains. Disabled after validation (3% recall drop → 95% recall recovered).
- **Threat intel layer design:** Initial design queried feeds sequentially. Rewrote to parallel async requests (5s → 800ms per sample).

---

## Architecture

```mermaid
flowchart LR
    A[APK Input] --> B[AndroGuard<br/>Manifest, Permissions]
    A --> C[JADX<br/>Bytecode → Java]
    C --> D[Suspicious API Tracer]
    B --> D
    D --> E[Indicator Extraction<br/>Domains, IPs, Strings]
    E --> F[Threat Intel<br/>VT, OTX, Shodan, Censys]
    F --> G[Geolocation<br/>MaxMind GeoLite2]
    G --> H[Confidence Scoring]
    H --> I[Report<br/>JSON + PDF]

    style A fill:#0f172a,stroke:#06b6d4
    style D fill:#111827,stroke:#f59e0b
    style F fill:#111827,stroke:#8b5cf6
    style I fill:#0f172a,stroke:#10b981
```

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Git**
- **Ollama** (for LLM threat assessment) — [Download](https://ollama.com)
- **API keys** for threat intel feeds (optional, see `.env.example`)

The repo ships portable copies of JADX, APKTool, JDK, and Node.js under `tools\`.

### Setup

```bash
git clone https://github.com/DarshakPatel2004/project-zero.git
cd project-zero

python -m venv venv
source venv/bin/activate      # Linux/macOS
# or: venv\Scripts\Activate.ps1  (Windows)

pip install -r requirements-lock.txt   # pinned, reproducible
cp .env.example .env
```

### Run

Open three terminals:

```bash
# Terminal 1: Ollama (LLM backend)
ollama serve

# Terminal 2: Backend
python -m backend.main       # serves on http://localhost:8000

# Terminal 3: Frontend (optional)
cd frontend
npm install
npm run dev                 # serves on http://localhost:5173
```

Submit an APK via the dashboard (drag-and-drop) or CLI:

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"apk_path": "samples/malware/example.apk"}'
```

Or run headless:

```bash
python -m analysis.pipeline samples/malware/example.apk
```

Output is written to `analysis/work/<sha256>/pipeline_result.json`.

---

## Dashboard

The React dashboard provides layered analysis views:

| View | Description |
|------|-------------|
| **Glance** | Threat summary with score, family, red-flag indicators |
| **Family Attribution** | Collapsible card with primary match, confidence bars, related samples |
| **Dissection** | Tabs for Manifest, Permissions, Components, Code (syntax-highlighted), Strings, DEX (entropy chart), Native Libs |
| **Threat Chains** | Interactive chain viewer with built-in decoders (Base64, hex, URL, XOR, custom JS) |
| **Threat Intel** | MITRE ATT&CK mapping, VT/OTX hit counts, Shodan host profiles |

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### Component Hierarchy

```mermaid
graph TD
    App[App.jsx] --> UP[UploadPanel]
    App --> SS[SampleSearch]
    App --> LS[LoadingSpinner]
    App --> TB[ThreatBadge]
    App --> SD[SampleDetail]
    App --> AV[AnalysisView]

    SD --> TSum[ThreatSummary]
    SD --> AE[AttributionEvidence]
    SD --> DT[DissectionTabs]

    DT --> MT[ManifestTab]
    DT --> PT[PermissionsTab]
    DT --> CT[ComponentsTab]
    DT --> CodeT[CodeTab]
    DT --> ST[StringsTab]
    DT --> DX[DEXTab]
    DT --> NL[NativeLibsTab]

    AV --> OV[ObfuscationView]
    AV --> MV[ManifestView]
    AV --> FS[FamilySignalsCard]
    AV --> TS[ThreatSynthesisPanel]

    style App fill:#0f172a,stroke:#06b6d4
    style SD fill:#111827,stroke:#f59e0b
    style DT fill:#111827,stroke:#8b5cf6
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health check |
| GET | `/api/samples` | List analyzed samples |
| GET | `/api/sample/{sample_id}` | Full analysis report |
| GET | `/api/sample/{sample_id}/attribution` | MAFIA attribution evidence |
| GET | `/api/sample/{sample_id}/threat-summary` | Threat summary (glance) |
| GET | `/api/sample/{sample_id}/dissection` | Full dissection data |
| GET | `/api/sample/{sample_id}/dissection/{manifest\|permissions\|components\|dex\|classes\|strings}` | Per-tab dissection data |
| GET | `/api/sample/{sample_id}/code-analysis/{class}` | Method-level code analysis |
| GET | `/api/graph/{sample_id}` | 3D graph data |
| GET | `/api/clusters` | Clustering data |
| GET | `/api/timeline/{sample_id}` | Attack-chain timeline |
| POST | `/api/upload` | Upload APK for analysis |
| POST | `/analyze` | Trigger APK analysis |
| WS | `/ws` | Real-time analysis events |

---

## Evaluation

- **459 Android APKs** across 6 sources: AndroZoo-Drebin (149), MalwareBazaar (97), modern_eval (63), AndroZoo (26), abusech (24), benign_eval (100 benign)
- **Top malware families (corrected GT):** FakeInstaller (25), Opfake (21), Plankton (17), DroidKungFu (16), GinMaster (15), NGate (15), SpyNote (14), TeaBot (13), Ermac (12), Hydra (11), FakeTikTok (11), BaseBridge (10)
- Full metadata in `sample_metadata.csv`

### Indicator False-Positive Validation (Aug 2026)

Every indicator the pipeline auto-extracted from 22 malware samples (380 total) was manually reviewed:

| Classification | Count | Share |
|----------------|-------|-------|
| Confirmed malicious (C2 / exfiltration endpoint) | 9 | 2.4% |
| Suspicious but unverified | 111 | 29% |
| Clearly benign (Firebase, Google OAuth, CDNs, Mono runtime paths) | 260 | **68%** |

An automated pass over 21 samples (439 indicators) produced the same split: **299 benign (68%), 129 suspicious, 11 malicious**. A domain-legitimacy check of 285 domains landed **68 junk / 134 benign / 75 suspicious / 8 malicious**.

**What this means:** indicator extraction is high-recall, low-precision. The headline "1,711 C2 indicators" is an *extraction* count — only a low single-digit percent survives manual review as genuine C2. Most false positives come from:
- Legitimate Google infrastructure (Firebase analytics, OAuth client IDs, `*.googleusercontent.com`)
- CDN/content domains (`i.ytimg.com`, `www.srgb.com`, assoc-amazon)
- Mono/.NET runtime paths (`*.cc` files) flagged by the "unusual protocol" heuristic
- `.top`/`.xyz` TLD heuristics hitting parked or sinkholed domains

Raw review data is committed in `evaluation_results/`: `fp_final_report.json`, `fp_validation_auto.json`, `legitimacy_check.json`, `indicators_extracted.json`, `fp_validation_results.json`.

### Family-Identification Accuracy (352-sample validation, Aug 2026)

Exact-match family accuracy against corrected ground truth is **64.2% (226/352)** overall and **68.6% (216/315)** when only specific (non-catch-all) families are counted.

**Why this number is trustworthy:** the ground truth was independently re-verified against VirusTotal (291) and MalwareBazaar (168) — all 459 samples `confirmed_external` — then corrected with an authoritative resolution order (filename prefix → MalwareBazaar signature → GT specific → VT recheck → verified pipeline C2 evidence → MB tags). This replaced the old GT where **48.5%** of labels were catch-alls (AndroidOS, GenericKD, Agent, Banker, Gen, ...) that inflated naive scoring. The old 32.0% figure was measured on that inflated label set; after correction the same engine scored 17.3%, and the upgraded engine below recovered to 64.2%.

**How the engine improved:** three layers work together:
1. **signature_v3** (hand-written families) — fires on 70 samples at 92.9% precision (65/70; all 5 misses are Plankton false positives).
2. **knowledge-base matcher** (new) — discriminators mined from the corrected GT (`analysis/family_knowledge_base.json`, 38 families; ≥2 matched tokens + an anchor token at ≤5% corpus FP). Offline mining precision ~95%; 76.3% precision on the re-eval (151/198 fires).
3. **LLM with candidate guidance** (new prompt) — the context now lists candidate families with their actually-matched signals plus observable evidence strings, turning open recall into a multiple-choice decision. The old prompt showed only string *counts* and refused 63.8% of samples (229/359); with the new prompt the LLM produces a verdict on 84/352 samples while the knowledge base handles the rest.

### Reproducibility (352-sample family validation)

The validation metrics are committed and reproducible with the tooling in the repo:

```bash
# Re-mine the family knowledge base from corrected GT
python analysis/mine_family_knowledge.py

# Re-run family identification on cached pipeline results (needs Ollama running)
python evaluation/reeval_families.py --output-dir evaluation/metrics_v2

# Compute metrics against the corrected ground truth
python evaluation/metrics_recompute.py \
    --gt ground_truth_all_corrected.csv \
    --predictions evaluation/metrics_v2/predictions.json \
    --output-dir evaluation/metrics_v2
```

Headline metrics (exact-match family accuracy, corrected ground truth):

| Metric | Value |
|--------|-------|
| Overall | 64.2% (226/352) |
| Specific families only (non-catch-all) | 68.6% (216/315) |
| High-confidence specific labels | 70.0% (189/270) |
| Unknown-refusal (GT = `unknown`) | 30.3% (10/33) |

Per source (accuracy on specific families): AndroZoo-Drebin 68.5% (149 specific), MalwareBazaar 77.0% (87), modern_eval 63.8% (47), AndroZoo 83.3% (12), abusech 35.0% (20).

Remaining misses are honest: Opfake/FakeInstaller/FakeChrome leave no observable static signal (opaque obfuscation), and toolkit-shared families (TeaBot↔Hydra↔Ermac↔FluBot) are hard even for human analysts.

### Validation Status

| Criterion | Status |
|-----------|--------|
| Methodology documented | ✅ |
| Threat feeds integrated | ✅ |
| Code open-source | ✅ |
| Sample APKs collected | ✅ |
| Recall on balanced set | ✅ 95% |
| Speedup verified | ✅ 63x (204 timed samples) |
| Family-ID accuracy vs ground truth | ✅ measured: 64.2% exact-match (352 samples, corrected GT) |
| FP rate validation | ✅ measured: 68% of indicators clearly benign, 2.4% confirmed malicious (380 indicators, 22 samples) |
| Comparative aggregator validation | ⏳ Future work |

## Known Limitations

- **Indicator precision is low**: 68% of auto-extracted indicators are clearly benign strings; only 2.4% were confirmed as genuine C2 in manual review (see [validation](#evaluation)). Heuristics favor recall over precision by design.
- **Family identification is imperfect**: 64.2% exact-match accuracy on 352-sample corrected ground truth — opaque-obfuscation families (Opfake, FakeChrome) and toolkit-shared families (TeaBot↔Hydra↔Ermac↔FluBot) remain hard; treat family output as advisory.
- Encrypted native libraries flagged for manual inspection
- Reflection-heavy obfuscation handled by heuristics (not perfect)
- C2-blind malware (zero static artifacts) — documented limitation

## Future Work

- **Threat Synthesis Engine:** Multi-sample attribution clustering (Q1 2027)
- **Dynamic Validation:** Frida-based runtime confirmation of static C2 candidates (Q2 2027)
- **String decryption correlation:** Cipher.doFinal tracing — expected +5-10% recall

---

## Testing

### Backend (Python)

```bash
pytest tests/ -v
```

### Frontend (React)

```bash
cd frontend
npm test     # 247 tests across 38 test files — all pass
```

CI runs both suites on every push and PR.

---

## Project Structure

```
backend/          — FastAPI server, threat intel integration, pipeline logic
frontend/         — React dashboard (Leaflet C2 maps, FamilySignalsCard, threat chains)
analysis/         — 18-step pipeline (extraction → decoding → correlation → synthesis → report)
scripts/          — Batch analysis, data collection utilities
data/             — GeoIP databases, YARA rules
evaluation_results/ — Committed validation results (FP review, family-ID metrics)
tests/            — Python backend tests (pytest)
docs/             — Dashboard guide, codebase reference, superpower plans
```

---

## Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Key variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `NVIDIA_NIM_API_KEY` | Optional | NVIDIA NIM (preferred LLM backend) |
| `OLLAMA_HOST` | Optional | Local Ollama endpoint |
| `OPENROUTER_API_KEY` | Optional | Cloud LLM (Qwen, Gemma) |
| `VT_KEY` | Optional | VirusTotal API |
| `OTX_KEY` | Optional | AlienVault OTX |
| `SHODAN_KEY` | Optional | Shodan host search |
| `CENSYS_TOKEN` | Optional | Censys Platform API |

### Publication

Read the full article: **"Static Analysis Beats Sandboxing. Here's How I Analyzed 277 Malware Samples in 3.2 Hours."**

Key article sections:
- The hypothesis: Static analysis extracts infrastructure faster than sandboxing
- Real findings: Coverage, accuracy, performance metrics (all reproducible)
- What I got wrong: Mistakes discovered and fixed (LLM bottleneck, heuristic over-optimization)
- Limitations: Encrypted libraries, reflection obfuscation, C2-blind malware
- Next: Threat Synthesis Engine (multi-sample attribution, Q1 2027)

---

## License

MIT
