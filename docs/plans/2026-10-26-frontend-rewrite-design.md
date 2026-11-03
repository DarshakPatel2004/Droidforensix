# DroidForensix Viewer Rewrite: System Design

Status: design only. No code changes yet. Implementation starts with Phase 1 (section 12).
Date: 2026-10-26
Method: system-design framework (requirements, high-level design, deep dive, scale, trade-offs). Decisions come from a grill-me interview on this plan.

## Decisions at a glance

| Area | Decision |
|---|---|
| Scope | Full rewrite of the viewer: backend API layer and frontend. The analysis pipeline is out of scope. |
| Goals | Maintainable code, better analyst workflow, thesis or demo quality, and display of the newer pipeline output. |
| Delivery | Phased: backend first (Phase 1), then frontend (Phase 2). |
| Stack | React + Vite, as it exists today. |
| First screen | One simple sample view, for the APK being worked on now. |
| Done (Phase 2) | Sample view shows all nine new steps; CI green; contract test passes; Vitest for every new component. |

Open decisions are in section 9.

## 1. Requirements

### Functional

- Upload an APK and run the pipeline. Exists: `POST /api/upload`, `POST /api/analyze/{upload_id}`.
- Find samples by hash prefix, full hash, or package name. Exists: `GET /api/samples?q=`.
- Per-sample view, first screen: summary, attribution, investigation tabs, and the results of all nine new pipeline steps.
- Investigation tabs: Manifest, Permissions, Components, Code, Strings, DEX, Native Libs.
- Analysis Results tabs: Overview, Secrets, LLM Summary, Dissection Summary, Obfuscation, Threat Chains, Threat Synthesis, Manifest.
- Threat intelligence view and exports (CSV, STIX, YARA, Suricata, PDF). These exist.
- Analyst status, tags, and notes per sample. Exists: `backend/analyst_store.py`.

### Non-functional

- Single analyst on a local machine. Request load is negligible; analysis time dominates.
- No screen may show a half-finished sample as if it were complete.
- Numbers on screen must match the data they come from.
- CI stays green: `pytest`, `ruff`, `npm run lint`, `npm test`, `npm run build`.

### Constraints

- `analysis/` and its `pipeline_result.json` output stay as they are. The rewrite changes only the viewer, as `CLAUDE.md` requires.
- Detection logic stays in `analysis/`. The backend is a viewer, except for family attribution in `backend/family_id.py`.
- The API contract in `docs/api/openapi.json` is frozen. Any route change is a deliberate, reviewed diff.
- The team is new to this stack, so each phase must be small.

## 2. Current state

```
analysis/ (18 steps)  --writes-->  analysis/work/<sha256>/pipeline_result.json (+ dissection.json)
                                                      |
                                                      v
backend/ (FastAPI, 6 routers, 44 documented paths)  <--HTTP/WS-->  frontend/ (React + Vite, 37 JSX, 39 test files)
```

- Backend: 44 paths in `docs/api/openapi.json`. Three legacy routes sit outside `/api/`: `POST /analyze`, `GET /samples`, `GET /samples/{id}`.
- Frontend: two navigation shells. The sidebar app (`AppInner` in `frontend/src/App.jsx`) runs on `/`. The sample route (`/sample/:id`) has its own tab bar. They don't share navigation.

## 3. Target design

```
analysis/ (unchanged)  -->  pipeline_result.json  -->  backend viewer (/api only)  -->  frontend viewer
                                                        |                              |
                                                        status endpoint                sample view (first)
                                                                                       Analysis Results, Attribution,
                                                                                       Investigation, Raw Code, Threat Intel
```

1. **One navigation model.** Keep either the sidebar app or the sample route, not both. Today they conflict (section 8).
2. **Status gate.** The frontend reads `GET /api/sample/{id}/status` before requesting analysis data. Until the status is `completed`, it shows progress, not 404 errors.
3. **One card pattern for steps 10–18.** All nine steps render with the same component.
4. **Routes cleaned up.** Remove the three legacy routes. Decide the six unreferenced routes one at a time (section 9).

## 4. Deep dive

### 4.1 Data model

`pipeline_result.json` is the source of truth. `backend/transformers.py:load_result` builds the view models. The new steps write these keys. The key names were checked on two samples (section 12, item 3). The "frontend references" column comes from a key-name search, not a render test.

| Step | Result key | Frontend references (key-name search) |
|---|---|---|
| 10 | `binary_packing` | 2 files |
| 11 | `string_clustering` | 1 file |
| 12 | `reflective_tracing` | 1 file |
| 13 | `native_elf_analysis` | none |
| 14 | `network_protocols` | none |
| 15 | `permission_correlation` | none |
| 16 | `certificate_analysis` | none |
| 17 | `family_clustering` | none |
| 18 | `threat_synthesis` | 1 file |

### 4.2 API

- Keep the `/api/sample/{id}/...` shape and `/api/samples` for the list.
- Remove `POST /analyze`, `GET /samples`, and `GET /samples/{id}`. Nothing in `frontend/src` or outside `tests/` calls them. The only caller of `POST /analyze` is the test `test_analyze_missing_apk` in `tests/test_backend.py`.
- Six paths have no caller in `frontend/src` and none outside `tests/`:
  - `POST /api/analysis/full`, `POST /api/analysis/androguard-only`: covered by `tests/test_security_regressions.py` (P2-A1).
  - `GET /api/analyst-state`: covered by `tests/test_analyst_state.py`.
  - `GET /api/clusters`, `GET /api/graph/{id}`, `GET /api/timeline/{id}`: covered by `tests/test_backend.py`.
- The contract is a test-enforced snapshot. Any route change regenerates `docs/api/openapi.json` (`python -m backend.api_contract --write`) in the same diff.

### 4.3 Caching and loading

- The frontend already has `apiFetchCached` and `fetchWithCache`. Reuse them. Don't add a third cache.
- The backend caches `dissection.json` per sample.
- The status gate replaces retry logic for analysis pages. Retry only on network errors, not on 404.

### 4.4 Upload race (confirmed in browser)

- The sidebar unlocks when the upload starts, before analysis finishes.
- Pages that load during analysis get HTTP 404 with no retry: Code Dissection ("Dissection Error: HTTP 404") and Raw Code ("HTTP 404").
- Threat Intelligence shows "Phase 2 enrichment is not available... Ensure analysis completed successfully". This blames the analysis after it has finished.
- After analysis completes, all five sidebar pages load with no errors.
- Fix (frontend, Phase 2): unlock the sidebar on status `completed`, and show progress until then.

### 4.5 Attribution numbers

- `backend/routers/samples.py` line 260 reports "C2 indicators overlap with N known indicators". N is the count of all unique C2 domains in the sample, not an overlap.
- The 0% "C2 Overlap" (lines 194–196) is the overlap with the family baseline. It falls back to 0 when the family has no baseline.
- Verified for the KungFu sample: the baseline has 3 domains, the sample has 9 unique domains, and the overlap is 0. The score is right; the text is wrong.
- Fix (backend, Phase 1): use the exact wording in section 12, item 2.

### 4.6 Security

- `POST /analyze` accepts a client-supplied path. Removing it removes that surface.
- The upload filename guard (`_resolve_upload_path` in `backend/routers/jobs.py`) stays. It has no tests today; Phase 1 adds them.
- The security property tested by P2-A1 (no client-supplied path reaches the pipeline unchecked) must still be tested on the routes that remain, if the two `/api/analysis/*` routes are removed.

## 5. Scale and reliability

- Load: one analyst, one machine. Requests per screen are small. The bottleneck is the pipeline. Step timeouts are in `STEP_TIMEOUTS` (`analysis/pipeline.py`), up to 900 seconds for step 8.
- Timeouts: `run_with_timeout` abandons the thread on timeout instead of stopping it, so the work keeps running. Known limit. Upgrade path: run each step in a subprocess that can be stopped.
- Failover and redundancy: not applicable to a local tool.
- Monitoring: backend logs to stdout. No alerting is needed for one analyst.
- Ollama (LLM steps) is optional. The viewer must render when Ollama is off.

## 6. Trade-offs

| Decision | Chosen | Considered | Why |
|---|---|---|---|
| Frontend stack | React + Vite | + TypeScript; new framework | Already in place and easiest for someone new to it. TypeScript can come later. |
| Delivery | Phased, backend first | Big-bang release | Chosen by the user. Smaller reviewable steps suit a new team on this stack. |
| API | Cleanup (remove legacy routes) | Redesign all 44 paths | A redesign regenerates the whole contract in one diff and rewrites tests. Cleanup is smaller and reviewable. |
| Unreferenced routes | Decide one by one | Remove all six now; keep all six | Each has a test. Removing a route also removes its test. |
| Step display | All nine in the sample view | Only the steps with data | One card pattern for all nine is simpler to build and test. |
| Sidebar unlock | On `completed` status | On upload start (current) | Fixes the 404 race. |

## 7. Done criteria

Phase 2 (decided, "stricter"):

- The sample view shows all nine new steps for the current APK.
- CI is green: `pytest`, `ruff`, `npm run lint`, `npm test`, `npm run build`.
- The API contract test passes.
- Every new component has Vitest coverage.

Test plan:

- Backend: pytest for each changed route. Contract test for every route change.
- Frontend: Vitest for each new component, including loading and error states.
- Browser: headless Chrome pass. Scripts are in `C:\Users\darsh\AppData\Local\Temp\claude\D--DroidForensix\705ff1b8-257e-43c1-9a7c-c2037eabc9f9\scratchpad\` (`check_ui.mjs`, `check_ui2.mjs`, `check_ui3.mjs`, `check_tabs.mjs`).

## 8. Browser check findings (2026-10-26)

Checked in headless Chrome against the running backend and dev server. Screenshots: `C:\Users\darsh\AppData\Local\Temp\df_shots\` (folders `all`, `pass2`, `pass3`, `tabs`).

**Working**
- Upload page renders.
- The sample route's Threat Summary, Attribution, Investigation, and Related tabs render. All seven Investigation sub-tabs render. No console errors on any of them.
- Hash-prefix search works: a 16-character prefix returns one result. (An earlier "No samples found" came from a bug in the test script.)
- After analysis completes, all five sidebar pages load with no errors.

**Problems**
- Attribution contradicts itself: "C2 Overlap" is 0%, but a supporting signal says "overlap with 9 known indicators" (section 4.5).
- Threat Summary shows "Evasion Techniques: 1691" with no explanation.
- Threat Summary shows "Active C2 Endpoints: N/A" because enrichment is `not_enriched`. The card doesn't say why.
- Threat Summary shows "Obfuscation: LOW" in red, next to a score of 16/100. The colour and label may not match the score.
- Upload race (section 4.4).
- Of the nine step titles, only Threat Synthesis appears as a titled section (zero-day risk 0/100, "No threat signals detected"). Steps 10–17 have no titled section in the Analysis Results tab bar. This is a text match; their data may appear under other labels, which I didn't confirm.
- Investigation sub-tabs Components (370 characters) and Native Libs (210 characters) are sparse. Unknown whether that's correct data or a missing render.
- Nav items are disabled until a sample is selected (`frontend/src/App.jsx`, line 706). Picking a sample from search navigates to `/sample/:id`, which has no sidebar.

**Limits of this check**
- All sidebar results come from a small upload (`com.android.adbkeyboard.apk`). The KungFu sample's APK is not on disk, so it could not be re-uploaded.
- Clicks were scripted over the Chrome DevTools protocol. Hover, keyboard, and responsive layouts were not tested.

## 9. Open decisions

Decided and recorded in this doc: scope, goals, phased delivery (backend first), stack, first screen, and done criteria. The items below still need an answer.

1. **Remove the six unreferenced routes?** Recommendation: decide route by route. Keep them until the new UI is decided.
2. **Show all nine steps in the sample view?** Decided: yes, one card pattern, under the heading "Deep analysis". The UI never says "step"; each card is named by its check (for example "Binary packing").
3. **Which C2 count does the UI show?** Decided: unique domains everywhere. Note: KungFu's 9 "unique" domains include the junk value `{0}`; the real count is 8 (section 13, item 0).
4. **Is the obfuscation colour intended?** Decided: no. The colour follows the score.
5. **Is `backend/core/apk_processor.py` live?** Answered: only `POST /api/analysis/full` uses it (one of the six unreferenced routes). The upload path (`/api/upload` → `/api/analyze/{id}`) runs `analysis/pipeline.py` and never reaches it.
6. **Navigation model.** Decided: mock D ("Combined") in the design canvas `https://claude.ai/artifact/GZnvTWK4KRQKHLT3X4L9WM` (private). Sample list on the left, tab bar per sample, no second shell.

## 10. Other issues (backlog, not part of the rewrite decision)

- `analysis/pipeline.py` header says "9-step". The code runs 18.
- `analysis/step19_container_repair.py`, `step20_payload_kdf_crack.py`, and `step21_string_deobfuscation.py` exist, but `run_pipeline` never calls them.
- `run_with_timeout` abandons the thread on timeout instead of stopping it (section 5).
- Test side effect: the browser check uploaded `samples/legitimate/com.android.adbkeyboard.apk`. It created sample `f9446fd3d7f775a764eb0df696b6819a7f3a4ea85bd17871855848ef72d6bb21` under `uploads/` and `analysis/work/`.

## 11. Revisit as the system grows

- **Several analysts:** add authentication and a shared store. `analyst_store.py` is SQLite and per-machine today.
- **Thousands of samples:** paginate the sample list and index the search.
- **Long analyses:** run each pipeline step in a subprocess, so a timeout can stop the work (section 5).
- **TypeScript:** add it once the API contract is stable enough to generate types from.

## 12. Scope of work

Delivery is phased. Each phase ends with CI green and the contract test passing.

### Phase 1: backend

In scope:

1. **Remove the legacy routes.** `POST /analyze` in `backend/routers/jobs.py`, and `GET /samples` and `GET /samples/{id}` in `backend/routers/samples.py`. Remove any helper that becomes unused. Remove the test `test_analyze_missing_apk` (`tests/test_backend.py`, line 120).
2. **Fix the attribution text.** In `_build_supporting_signals` (`backend/routers/samples.py`, line 260):
   - With a family baseline: "M of N C2 indicators match the family baseline", where N is the unique domain count and M is the overlap the score uses. For KungFu: "0 of 9 C2 indicators match the family baseline".
   - With no baseline: "no family baseline to compare against". No overlap figure.
   - The score itself does not change.
3. **Step keys: verified on two samples.** All nine keys are present as dicts in the KungFu and adbkeyboard `pipeline_result.json`. Read-only; no change.
4. **Add tests for the upload filename guard.** `_resolve_upload_path` in `backend/routers/jobs.py` rejects empty and traversal filenames. No test covers either. Add one test for each, before removing `POST /analyze`.
   - Correction (found during Phase 1): `POST /api/upload` does not call `_resolve_upload_path`. It has its own empty and illegal-character checks, and always saves to `uploads/<uuid>/file.apk`, so `../escape.apk` returns 200 and stays inside `uploads/`. Only the two `/api/analysis/*` routes call the guard. `tests/test_upload_guard.py` tests the guard directly and the upload route's containment over HTTP.
5. **Regenerate the contract.** Run `python -m backend.api_contract --write` and commit the new `docs/api/openapi.json` with the route changes.

Out of scope for this phase:

- The six unreferenced routes (section 9, item 1).
- Any new endpoint. Existing responses change only where item 2 requires it.
- Any change under `analysis/`, including `pipeline_result.json`.
- Frontend changes of any kind. This includes the upload race and the obfuscation colour.

Acceptance:

- `pytest` passes for `tests/`.
- `ruff check analysis backend droidforensix tests` passes.
- The contract test passes against the regenerated `docs/api/openapi.json`.
- Nothing in `frontend/src` or `tests/` calls the removed routes.
- The attribution text for KungFu reads "0 of 9 C2 indicators match the family baseline".
- The new upload-guard tests from item 4 (empty and traversal filenames) exist and pass.

Risks:

- `test_analyze_missing_apk` is the only test of `POST /analyze`, and it checks only that a missing file returns 400. Removing the route removes that check. Item 4 covers the path logic that matters.
- The attribution fix changes text users read. The score is unchanged.

Data recorded for later, not changed in this phase:

- The threat summary reports 12 C2 indicators for KungFu. That's the list length with duplicates. The attribution uses 9 unique domains (section 9, item 3).
- The C2 and permission baselines come from signatures in `backend/family_id.py`. The KungFu baseline has 3 C2 domains and 3 permissions.

### Phase 2: frontend

Scope is in section 13. Status: proposed, not yet approved.

## 13. Phase 2 scope (proposed)

Target screen: mock D in the design canvas (section 9, item 6). Layout: sample list on the left; for the selected sample, a header (package, family, status, analyst status, export), a tab bar, and the tab body.

Tabs and what each mounts (existing components are reused, not rewritten):

| Tab | Content |
|---|---|
| Overview | New: KPI tiles (LLM risk, unique C2 domains, obfuscation, zero-day risk), "Needs your attention", attribution summary, "Deep analysis" (nine check cards), "All checks" list. |
| Attribution | `AttributionEvidence`, `RelatedSamples` |
| Checks | `AnalysisView` (Secrets, LLM summary, obfuscation, threat chains, ...), unchanged at first |
| Investigation | `DissectionTabs` |
| Raw code | `RawCodeView` |
| Threat intel | `ThreatIntelView` |
| Notes | Analyst status, tags and notes (existing analyst-state API) |

Data: `GET /api/sample/{id}` already returns the full `pipeline_result.json`, including all nine deep-analysis keys. No new endpoint is needed.

Work items, in order. Each one is a separate, reviewable change with CI green:

0. **Backend: unique C2 domain count.** Drop non-domain values such as `{0}` when counting unique C2 domains (attribution signal and threat summary). KungFu then reads "0 of 8". Viewer-side count only; `analysis/` is unchanged.
1. **Status gate.** A `useSampleStatus(id)` hook over `GET /api/sample/{id}/status`. Tabs render only on `completed`; before that the sample shows progress. List rows for running analyses show progress and are not selectable. Fixes the upload race (section 4.4).
2. **Check cards.** One `CheckCard` component and a "Deep analysis" section that renders the nine checks from the sample result. Each card: check name, Finding/Clear tag, one-line result. No step numbers in the UI.
3. **One shell.** Routes `/` (upload + list) and `/sample/:id/:tab`. The sample list sits beside every sample page. Remove the per-sample pages from the old sidebar (`AppInner`) and the separate `/sample/:id` tab bar (`SampleDetail`). Upload and WebSocket progress keep working.
4. **Overview tab.** KPI tiles (obfuscation colour follows the score via `riskLevelBadgeClass`), attribution summary, "All checks" list.
5. **Needs your attention.** A short list built from what the checks already found: C2 domains vs family baseline, threat chains of medium severity or higher, checks tagged Finding. Presentation only; no new detection logic.
6. **Notes tab.** Analyst status, tags and notes on the existing analyst-state API.

Out of scope: rewriting `AnalysisView` internals; TypeScript; the six unreferenced routes; any change under `analysis/`. The LLM-vs-secrets contradiction found on KungFu (the LLM claims hardcoded AWS credentials, but the secrets step found none) and step 14 reporting 0 endpoints are logged here, not fixed in Phase 2.

Done criteria: section 7 (Phase 2), plus the headless browser pass with no 404 during analysis.

Open for approval:
- Visual style: decided 2026-10-27 to keep the dark theme (the app's existing tokens). Mock D's light palette is not adopted.
- "Checks" tab: mount `AnalysisView` unchanged first (smaller), or split it into the new layout now?
