# Report export spec (draft)

Status: draft for review. Field names and sources were checked against the sample outputs listed below. Nothing here is implemented yet.

## Why export is not in the mock page

The mock is an Artifact page. Viewers cannot download files or print from it: `window.print()` does nothing, and `<a download>` links are blocked. An "Export" button inside the page would not work for anyone who opens the link. Export therefore has to come from the pipeline (backend), not from the page.

## Formats

| Format | Purpose | Produced by |
|---|---|---|
| PDF | Reading, filing, sharing | Renderer over the report model (reportlab, as in `backend/pdf_report.py`) |
| JSON bundle | Machine reading, audit, re-rendering | Serialiser over the report model |
| CSV | Indicator and permission tables for spreadsheets | Serialiser, one file per table |

The JSON bundle is the source of truth. The PDF and CSV are rendered from it, so the three cannot disagree.

## Report model (JSON), top level

Each key maps to a mock section. Source files are the ones seen in the sample outputs.

| Key | Content | Source |
|---|---|---|
| `sample` | sha256, md5, size, package, sample name | `pipeline_result.json` metadata, `custody.jsonl` seq 0 |
| `custody` | record count, sequence check, hash-chain check, last event, result time | `custody.jsonl` |
| `pipeline` | version, stop_after, skipped steps | `pipeline_meta.json` |
| `assessment` | severity, rule-based risk, model risk, model confidence, rule trace | `step7_assessment.json`, `pipeline_result.json` |
| `family` | family, method, signals matched and required, reasoning, certificate analysed, deterministic | `family.json` |
| `network` | endpoint, protocol, pipeline label, live-check status, evidence ID | `step5_c2s.json` |
| `permissions` | name, group, declared, used-in-code status | manifest (step 1 or 2) |
| `obfuscation` | reflection, dynamic loading, crypto, packer, score with method note | `step8_obfuscation.json` |
| `packing` | packer name, verdict, confidence, heuristics hit, payload candidates, recovered count | triage report, emulation report |
| `unpacked_items` | each recovered item with parent hash and stage label; empty when nothing recovered | unpack output |
| `evidence` | register of IDs E1 to E8 with source file | derived |
| `limitations` | list of strings | fixed text plus per-run flags |
| `model_disclosure` | model, backend, date, prompt version | `step7_assessment.json` |

## Rules for export

1. A claim with status UNVERIFIED or MODEL must carry its status into every format. It must not be shown as plain fact.
2. Every evidence ID referenced in a section must resolve in `evidence`. Otherwise export fails.
3. Values the pipeline did not produce are written as `null` in JSON and as "not produced" in PDF and CSV. They are never filled in by hand.
4. "Clean" from the emulator is exported as "ran without exception". It is not exported as "recovered".
5. Quick and full modes are not separate formats. Full is the only export; quick is a view that drops the appendix.

## Open decisions

- Whether PDF rendering reuses `backend/pdf_report.py` or replaces it.
- Whether the CSV export is needed at first, or only the JSON and PDF.
- Where the export endpoint lives. The current one is `POST /api/sample/{id}/report/pdf`.

Skipped: no code, no endpoint change, no test. Risk: a JSON model that is not checked against real output will drift from the PDF.
