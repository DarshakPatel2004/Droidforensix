# DroidForensix — REST & WebSocket API Reference

Base URL: `http://localhost:8000` (see `docs/USAGE.md` for how to start the backend.)

Conventions:

- `sample_id` is the APK's **SHA-256** (returned by upload/analysis).
- Errors use FastAPI's shape: `{"detail": "..."}` with status 400/404/408/413/500.
- All endpoints are available at `http://localhost:8000/docs` (Swagger UI auto-generated).

---

## Quick start

```bash
# 1) upload (multipart, field name "file")
curl -X POST http://localhost:8000/api/upload -F "file=@samples/RTO.apk"
# → { "upload_id": "<uuid>", "sample_id": "<sha256>", ... }

# 2) trigger the pipeline (async; runs in background, max 300 s)
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
| POST | `/api/upload` | multipart `file` | Validates filename/`MAX_UPLOAD_SIZE_MB`/empty file/disk space, checks `PK\x03\x04` zip header, dedups by SHA-256. → `upload_id`, `sample_id` |
| POST | `/api/analyze/{upload_id}` | — | Runs `analysis.pipeline.run_pipeline` in a thread pool (300 s timeout), streams events over `/ws`. → `{"status": "queued"}` |
| POST | `/analyze` | `{"apk_path": "path/to.apk"}` | Same as above for a server-readable local path (backward compat). → `job_id` |
| POST | `/api/analysis/full` | multipart `file` | Synchronous full analysis via `APKProcessor.process()`. Returns full result dict. |
| POST | `/api/analysis/androguard-only` | multipart `file` | Synchronous AndroGuard-only analysis via `APKAnalyzer.run()`. Fast, no full pipeline. |
| GET | `/api/sample/{sample_id}/status` | — | Status of a job (`queued|analyzing|completed|failed|error`) or a completed sample (adds `severity`, `risk_score`). 404 if unknown. |

> Note: `/api/analysis/*` write the upload to `uploads/<filename>` verbatim (filename collisions overwrite); prefer `/api/upload` + `/api/analyze/{id}` for the full flow.

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

Legacy aliases (kept for backward compatibility):

| Method | Path |
|--------|------|
| GET | `/samples` |
| GET | `/samples/{sample_id}` |

---

## Dissection (lazy, per-tab)

All under `/api/sample/{sample_id}/dissection`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/sample/{sample_id}/dissection` | Top-level overview payload |
| GET | `.../manifest` | Manifest data |
| GET | `.../permissions` | Permission analysis |
| GET | `.../components` | Activities/services/receivers/providers |
| GET | `.../dex` | DEX file metadata |
| GET | `.../classes` | Class index |
| GET | `.../classes/{class_name:path}` | Class detail (path-safe class names) |
| GET | `.../code/{class_name:path}` | Decompiled code for a class |
| GET | `.../strings` | Extracted strings (smali/DEX/bytecode) |
| GET | `.../summary` | LLM threat-assessment summary (`?refresh=true` to re-run) |

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
- Server → client (all connected clients receive): pipeline progress events with an `event_type` field (e.g. step completion, LLM stage). Callbacks are wired via `EventManager`/`events.py`; the frontend drives the in-memory progress UI from these events.

---

See `docs/ARCHITECTURE.md` for where each endpoint maps in the backend module structure.