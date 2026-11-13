# DroidForensix — REST & WebSocket API Reference

Base URL: `http://localhost:8000` (see `docs/USAGE.md` for how to start the backend.)

Conventions:

- `sample_id` is the APK's **SHA-256** (returned by upload/analysis).
- Errors use FastAPI's shape: `{"detail": "..."}` with status 400/404/408/413/500.
- All endpoints are available at `http://localhost:8000/docs` (Swagger UI auto-generated).
- The authoritative route list is the frozen schema in `docs/api/openapi.json`. `tests/test_api_contract.py` fails when the live app drifts from it. Update this page in the same change when you regenerate it (`python -m backend.api_contract --write`).

---

## Quick start

```bash
# 1) upload (multipart, field name "file")
curl -X POST http://localhost:8000/api/upload -F "file=@samples/RTO.apk"
# → { "upload_id": "<uuid>", "sha256": "<sha256>", "status": "uploaded", ... }
#   The sha256 becomes the sample_id once analysis finishes.

# 2) trigger the pipeline (async; runs in a background thread, pipeline limit 600 s)
curl -X POST http://localhost:8000/api/analyze/<upload_id>
# → { "upload_id": "...", "status": "queued", "message": "..." }

# 3) track progress
curl http://localhost:8000/api/sample/<upload_id>/status
# connect to ws://localhost:8000/ws for live progress events

# 4) fetch the report + views once status == completed
curl http://localhost:8000/api/sample/<sample_id>
```

---

## System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health check → `{"status": "ok", "version": "1.0.0", "api_prefix": "/api"}` |
| WS | `/ws` | Live event stream. Client sends JSON `{"action": "ping"}` → server replies `{"event_type": "pong"}`. While `/api/analyze/{id}` runs, pipeline progress events are pushed to all connected clients. |

---

## Upload & analysis

| Method | Path | Request | Description |
|--------|------|---------|-------------|
| POST | `/api/upload` | multipart `file` | Validates filename, `MAX_UPLOAD_SIZE_MB`, empty file and disk space, checks the `PK\x03\x04` zip header, dedups by SHA-256 (a re-upload returns the first `upload_id` with `"deduplicated": true`). → `upload_id`, `filename`, `sha256`, `status` |
| POST | `/api/analyze/{upload_id}` | — | Runs `analysis.pipeline.run_pipeline` in the default thread pool and streams events over `/ws`. A second call while the run is `analyzing` returns the current status instead of starting another run. → `{"status": "queued"}` |
| POST | `/api/analysis/full` | multipart `file` | Synchronous full analysis via `APKProcessor.process()`. → `{"status": "success"|"partial"|"error", "data": ...}` (`partial` adds `failed_steps`) |
| POST | `/api/analysis/androguard-only` | multipart `file` | Synchronous AndroGuard-only analysis via `APKAnalyzer.run()`. Fast, no full pipeline. |
| GET | `/api/sample/{id}/status` | — | `id` may be an `upload_id` or a `sample_id`. Returns the job status (`analyzing`, `completed`, `failed`; `sample_id` is set once completed) or, for a finished sample on disk, `completed` plus `severity` and `risk_score`. 404 if unknown. |

Notes:

- Job state (`upload_id` → status) is held in memory. A backend restart forgets in-flight and finished jobs; finished samples are still found on disk by `sample_id`.
- The HTTP request that started a run stops waiting after 300 s (`ANALYSIS_AWAIT_TIMEOUT_S`), but the pipeline keeps running up to its own 600 s limit. Poll status or watch `/ws` for the real outcome.
- `/api/analysis/*` write the upload to `uploads/<filename>` (filename collisions overwrite), read the whole file into memory, and block the server while they run. Prefer `/api/upload` + `/api/analyze/{id}`.

---

## Reports

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/samples` | List all analyzed samples (summary fields) → `{"samples": [...], "total": n}` |
| GET | `/api/sample/{sample_id}` | Full `pipeline_result.json` report for a sample |
| GET | `/api/graph/{sample_id}` | 3D graph nodes/edges |
| GET | `/api/clusters` | 3D clustering across all samples |
| GET | `/api/timeline/{sample_id}` | Attack-chain / timeline progression |
| GET | `/api/sample/{sample_id}/attribution` | Signature → knowledge-base → LLM attribution layers |
| GET | `/api/sample/{sample_id}/custody` | Chain-of-custody log, re-verified on every request → `{"verification": {"valid", "entries", "head_hash", "broken_at", "reason"}, "entries": [...]}` |

`/api/samples` and `/api/clusters` read every result on disk and cache the list for 300 s, so a sample analyzed in that window can be missing from them until the cache expires. `GET /api/sample/{sample_id}` is not cached and sees it at once.

---

## Analyst state

Status, tags, and notes an analyst attaches to a sample. Stored in one SQLite file, `analysis/work/analyst_state.sqlite3` (`backend/analyst_store.py`).

| Method | Path | Request body | Description |
|--------|------|--------------|-------------|
| GET | `/api/sample/{sample_id}/analyst-state` | — | → `{"sample_id", "status", "tags", "notes", "updated_utc"}` |
| PUT | `/api/sample/{sample_id}/analyst-state` | `{"status": "new"|"reviewing"|"closed", "tags": [str], "notes": str}` | Replaces the state. Up to 20 tags of 1–40 chars, notes up to 10,000 chars. 400 on a malformed `sample_id`, 404 if the sample does not exist. |
| GET | `/api/analyst-state` | `?status=new|reviewing|closed` (optional) | Every recorded state, newest first |

---

## Dissection (lazy, per-tab)

All under `/api/sample/{sample_id}/dissection`. Every route except `strings` accepts `?refresh=true` to discard the cached dissection and rebuild it from the APK. Routes that need the APK return 404 `APK file not found for sample` when the original APK is no longer on disk.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/sample/{sample_id}/dissection` | Full dissection payload (built on first request, then cached as `dissection.json`) |
| GET | `.../manifest` | Parsed manifest (`raw_manifest` truncated to 5 KB) |
| GET | `.../permissions` | Declared permissions with risk levels |
| GET | `.../components` | Activities/services/receivers/providers |
| GET | `.../dex` | DEX file metadata |
| GET | `.../classes` | Class index without method bodies. `?offset=0&limit=50` (limit 1–200) → `{"classes", "total", "offset", "limit"}` |
| GET | `.../class-methods/{class_name:path}` | Method bodies for one class |
| GET | `.../code/{class_name:path}` | Decompiled source for one class |
| GET | `.../strings` | Step 2 strings (`step2_strings.json`) |
| GET | `.../summary` | LLM threat-assessment summary |

---

## Explanations

| Method | Path | Request body | Description |
|--------|------|--------------|-------------|
| POST | `/api/sample/{sample_id}/dissection/explain-method` | `{"class_name": str, "method_name": str, "method_code": str, "flags": [str]|null}` | Two layers: **static** line annotations (synchronous, always present) + **LLM** summary (in thread pool; empty if LLM down) |
| POST | `/api/sample/{sample_id}/explain-chain` | `{"chain": {...}}` | LLM explanation of a threat-chain object → `{"chain_id", "llm": {...}}` |

---

## Threat intel & exports

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/sample/{sample_id}/threat-intel` | Aggregated C2 indicator intel (VT/OTX/Shodan/Censys) |
| GET | `/api/sample/{sample_id}/community-intel` | Community/C2 enrichment |
| GET | `/api/sample/{sample_id}/threat-summary` | Summarized threat picture |
| GET | `/api/sample/{sample_id}/threat-intel/export/csv` | CSV blocklist (`droidforensix_<sha16>_blocklist.csv`) |
| GET | `/api/sample/{sample_id}/threat-intel/export/stix` | STIX 2.0 bundle (JSON download) |
| GET | `/api/sample/{sample_id}/threat-intel/export/yara` | Auto-built `.yar` rule from extracted indicators |
| GET | `/api/sample/{sample_id}/threat-intel/export/suricata` | Suricata rules from extracted indicators |
| POST | `/api/sample/{sample_id}/report/pdf` | Full forensic PDF. Body: `{"mode": "quick"|"full", "sections": {"metadata": true, "llm_assessment": true, "obfuscation": true, "c2_infrastructure": true, "suspicious_methods": true}}`. `quick` = LLM summaries for top 30 suspicious methods; `full` = all (slow). If `mode != "quick"`, `sections` is ignored. |

---

## Family, obfuscation, code

| Method | Path | Request body | Description |
|--------|------|--------------|-------------|
| GET | `/api/sample/{sample_id}/family` | — | Family attribution result |
| GET | `/api/sample/{sample_id}/obfuscation` | — | Obfuscation summary view |
| GET | `/api/sample/{sample_id}/code-analysis/{class_name:path}` | — | Method risk scores, suspicious lines, attack-flow for a class |
| GET | `/api/sample/{sample_id}/string-references/{string_value:path}` | — | Where an extracted string is referenced |
| POST | `/api/sample/{sample_id}/deobfuscate` | `{"text": str, "hint": str|null}` | Best-effort deobfuscation of a user-supplied string |

---

## Client support

| Method | Path | Request body | Description |
|--------|------|--------------|-------------|
| POST | `/api/log-error` | `{"message": str, "stack": str|null}` | Client-side error logging → `{"ok": true}` |

---

## WebSocket protocol

Connect: `ws://localhost:8000/ws`

- Client → server: any JSON; `{"action": "ping"}` is acknowledged.
- Server → client (all connected clients receive): pipeline progress events with an `event_type` field (e.g. step completion, LLM stage). Events are built in `backend/events.py` and broadcast by the connection manager in `backend/realtime.py`; the frontend drives the in-memory progress UI from these events.
- There is no per-sample subscription: every client sees every run's events and filters on `sample_id`.

---

## Security model

There is no authentication. `python -m backend.main` and `python -m droidforensix serve` bind to `0.0.0.0`, so anyone on the network can upload files, read reports, and trigger LLM calls. Run it on an isolated host or pass `--host 127.0.0.1` to `droidforensix serve`.

---

See `docs/ARCHITECTURE.md` for where each endpoint maps in the backend module structure.