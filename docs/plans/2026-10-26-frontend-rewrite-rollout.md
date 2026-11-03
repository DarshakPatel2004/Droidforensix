# DroidForensix Viewer Rewrite: Rollout Runbook

Audience: one engineer new to this stack.
Companion to: `docs/plans/2026-10-26-frontend-rewrite-design.md` (the design, and the scope of work in its section 12).

This runbook says what to do, in what order, and when to stop. It does not repeat the design rationale; read the design doc first.

## 0. How "deploy" works here

DroidForensix is a local tool. There is no staging environment and no production server. A "deploy" means:

1. The change is merged to `main`.
2. CI is green on the merged commit.
3. The backend is restarted from the merged code: `python -m backend.main` (or `python -m droidforensix serve`).
4. The smoke checks in section 4 pass against the running backend.

A rollback means reverting the merge commit and restarting the backend.

## 1. Before you start

### Access and tools

- Repository: `D:\DroidForensix`, branch `main`.
- Python: the project venv, `.venv\Scripts\python.exe`. Do not use the system `python`; it has no pytest.
- Node: `frontend/` dependencies installed (`npm ci` if not).
- Do not copy values from `.env` or `setenv.sh` into code, commits, or tests.

### Commands you will use

Backend tests:

```
.venv\Scripts\python.exe -m pytest tests/ -q
.venv\Scripts\python.exe -m pytest tests/test_backend.py -q      # one file
.venv\Scripts\python.exe -m pytest tests/test_backend.py::test_name -q   # one test
```

Lint (the same command CI runs; run it before every push):

```
ruff check analysis backend droidforensix tests
```

Frontend (run from `frontend/`):

```
npm test
npm run lint
npm run build
```

Contract regeneration (Phase 1 only):

```
.venv\Scripts\python.exe -m backend.api_contract --write
```

Start the backend and frontend for manual checks:

```
.venv\Scripts\python.exe -m backend.main            # API on :8000
cd frontend && npm run dev                           # UI on :5173
```

## 2. Baseline (do this first, before any change)

Record the starting state. You need it to tell later whether a failure is new.

- [ ] `git status` is clean on `main`. If not, stop and find out what is uncommitted.
- [ ] Run the backend tests. Write down the pass count and any failures.
- [ ] Run `ruff check analysis backend droidforensix tests`. Write down the result.
- [ ] In `frontend/`, run `npm test`, `npm run lint`, and `npm run build`. Write down each result.
- [ ] Save the current API surface: `curl http://127.0.0.1:8000/openapi.json` into a scratch file, for diffing later.

If the baseline is already red, record which tests fail and stop. Do not start Phase 1 on a red baseline. Ask the repository owner first.

## 3. Phase 1: backend

Goal: remove the three legacy routes, fix the attribution text, add upload-guard tests, and regenerate the contract. Scope and acceptance criteria are in design section 12.

Work in this order. Each step is small enough to review on its own.

### Step 1.1: add the upload-guard tests (no behaviour change)

- [ ] Add a test that `POST /api/upload` rejects an empty filename with 400.
- [ ] Add a test that it rejects a traversal filename (for example `../escape.apk`) with 400.
- [ ] Run the new tests. **They must pass against the unchanged code**, because the guard already exists. If they fail, the guard does not do what the design says. Stop and record the failure before going further.
- [ ] Commit: "test: cover upload filename guard".

The guard is `_resolve_upload_path` in `backend/routers/jobs.py`. Correction: `/api/upload` never calls it and returns 200 for `../escape.apk` (stored safely as `uploads/<uuid>/file.apk`). The tests in `tests/test_upload_guard.py` call the guard directly and check the upload route's containment.

Also found in step 1.2: the attribution endpoint caches to `attribution_cache.json`. The cache `schema_version` was bumped from 2 to 3 so existing caches don't keep serving the old text. Each sample's attribution is recomputed on its next request.

### Step 1.2: fix the attribution text (text change only)

- [ ] In `_build_supporting_signals` (`backend/routers/samples.py`, around line 260), replace the text with the two cases from design section 12, item 2:
  - With a family baseline: "M of N C2 indicators match the family baseline".
  - With no baseline: "no family baseline to compare against".
- [ ] Do not change the score or any other field.
- [ ] Add a unit test for both cases. For the baseline case, use the KungFu numbers: baseline `adwo.com`, `gongfu-android.com`, `waps.cn`; sample domains with no overlap; expected text "0 of 9 C2 indicators match the family baseline".
- [ ] Run the attribution tests (`tests/test_attribution.py`) and the new test.
- [ ] Commit: "fix(attribution): report baseline overlap in signal text".

Before merging, confirm with the repository owner that the wording is what they want. The design proposes it; it is not yet approved.

### Step 1.3: remove the legacy routes

- [ ] Remove `POST /analyze` from `backend/routers/jobs.py`.
- [ ] Remove `GET /samples` and `GET /samples/{sample_id}` from `backend/routers/samples.py`, including the comment "Legacy endpoints".
- [ ] Remove the test `test_analyze_missing_apk` from `tests/test_backend.py` (around line 119).
- [ ] Run `ruff check analysis backend droidforensix tests`. Remove any import or helper that becomes unused. Do not remove anything else.
- [ ] Run the backend tests. The only expected changes are the removed test and the new ones.
- [ ] Confirm nothing still calls the removed routes:
  ```
  grep -rn -E '"/analyze"|"/samples"|"/samples/' frontend/src tests backend
  ```
  The only matches should be the route definitions you just removed, or none.
- [ ] Commit: "refactor(api): remove legacy unprefixed routes".

Do **not** remove the six unreferenced `/api/` routes in this phase. They are an open decision (design section 9, item 1).

### Step 1.4: regenerate the contract

- [ ] Run `.venv\Scripts\python.exe -m backend.api_contract --write`.
- [ ] Diff `docs/api/openapi.json`. Expected changes:
  - Removed: `/analyze`, `/samples`, `/samples/{sample_id}`.
  - Changed: the attribution signal text only, if the schema describes it.
  - Nothing else.
- [ ] If the diff contains anything else, stop. Find out why before committing.
- [ ] Run the contract test. It must pass.
- [ ] Commit: "docs(api): regenerate contract after legacy route removal".

Keep steps 1.3 and 1.4 in the same merge so `main` never has routes removed without the contract updated.

### Step 1.5: full checks before merge

- [ ] `.venv\Scripts\python.exe -m pytest tests/ -q` passes. Pass count is the baseline count, minus the one removed test, plus the new tests.
- [ ] `ruff check analysis backend droidforensix tests` passes.
- [ ] `npm test`, `npm run lint`, and `npm run build` in `frontend/` pass. No frontend files changed, so these should match the baseline.
- [ ] The contract test passes.

### Step 1.6: merge and deploy

- [ ] Open a pull request into `main` with the four commits.
- [ ] CI is green on the PR (pytest, ruff, npm lint, npm test, npm run build).
- [ ] Merge.
- [ ] Restart the backend from the merged code: stop the running `backend.main` process, then start it again.
- [ ] Run the smoke checks in section 4.

### Phase 1 rollback

Triggers (any one):

- A test that passed in the baseline fails after the merge.
- The contract test fails, or the diff in step 1.4 contains unexpected changes.
- A smoke check in section 4 fails.
- The backend fails to start.

Action:

1. Revert the merge commit on `main`: `git revert -m 1 <merge-sha>`. Do not rewrite history.
2. Regenerate the contract from the reverted code, and confirm it matches the pre-change file.
3. Restart the backend.
4. Rerun the smoke checks against the reverted code.
5. Record in the design doc what failed, and why.

## 4. Smoke checks (run after every backend change)

Start the backend, then run these against `http://127.0.0.1:8000`. Use the KungFu sample for attribution, since its analysis exists locally: `85cafe005c7f893cae65fa0a5ebf1c103eca579529ebd5d531c672408acdb9d0`.

| Check | Command | Expected |
|---|---|---|
| Health | `curl http://127.0.0.1:8000/` | 200, `"status":"ok"` |
| Sample list | `curl "http://127.0.0.1:8000/api/samples?limit=5"` | 200 |
| Sample detail | `curl http://127.0.0.1:8000/api/sample/85cafe005c7f893cae65fa0a5ebf1c103eca579529ebd5d531c672408acdb9d0` | 200 |
| Attribution text | `curl .../api/sample/<id>/attribution` | `supporting_signals` contains "0 of 9 C2 indicators match the family baseline" (after step 1.2) |
| Legacy removed | `curl -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/samples` | 404 |
| Legacy removed | `curl -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:8000/analyze` | 404 or 405 |
| Upload containment | `curl -F "file=@samples/legitimate/com.android.adbkeyboard.apk;filename=../escape.apk" http://127.0.0.1:8000/api/upload` | 200, file stored under `uploads/<uuid>/file.apk` |

After Phase 1, no file may appear outside `uploads/`. (`/api/upload` does not call `_resolve_upload_path`; it ignores the client filename for the storage path. See design section 12, item 4.)

The browser pass (`check_ui.mjs` and the other scripts in the scratchpad) is not required for Phase 1, since no frontend code changes. Run it in Phase 2.

## 5. Phase 2: frontend (outline only)

Phase 2 does not start until Phase 1 is merged and smoke checks pass. Its scope is set after Phase 1 (design section 12).

Entry conditions:

- [ ] Phase 1 merged and verified.
- [ ] Open decisions 1–5 in design section 9 answered. The routes decision matters most here.
- [ ] Phase 2 scope written as a section of the design doc and approved.

Expected items (to be confirmed when the scope is written):

- One navigation model (sidebar or sample route, not both).
- Status gate: no analysis page requests data until status is `completed`.
- All nine steps rendered with one card component.
- Obfuscation colour matches its score.
- Vitest coverage for each new component.

Phase 2 will need its own deploy checklist and rollback triggers, written when its scope is written. Do not reuse Phase 1's triggers.

## 6. Escalation

- Single-engineer project. The repository owner makes the open decisions in design section 9.
- If a baseline is red, or a rollback is needed and the cause is unclear, stop and record the evidence in the design doc before trying a fix.

## 7. Record of this runbook

- Written: 2026-10-26.
- Based on: design doc section 12 (Phase 1 scope), and the commands in `CLAUDE.md` and `.github/workflows/test.yml`.
- Not yet verified: the commands in sections 1 and 4 have not been run from this document. Run the baseline (section 2) first; if a command differs, fix this runbook.
