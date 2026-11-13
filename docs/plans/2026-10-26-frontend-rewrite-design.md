# DroidForensix Viewer Remake: Design Spec

Status: approved scope, not yet built. Supersedes the 2026-10-26 Phase 2 proposal. The backend Phase 1 work described in section 6 is done.
Product context: `PRODUCT.md` (repo root). Users, header facts, principles and anti-references live there and are not repeated here.
Mode: Operate (the visitor completes a task: triage, verify, export).

## 1. Scope

Full remake of the viewer frontend (`frontend/`). The backend API contract and the analysis pipeline (`analysis/`, `pipeline_result.json`) do not change in this remake.

In scope:
- Every screen the sample viewer shows: the index rail, the sample header, the tab bar, and seven tab bodies (Overview, Attribution, Checks, Investigation, Raw code, Threat intel, Notes).
- The upload and search entry point on `/`.
- Visual system: tokens, typography, primitives, states (loading, empty, error, not ready).
- Tests for every new component (Vitest), and the browser pass in section 8.

Out of scope:
- Any change under `analysis/`, `pipeline_result.json`, or the API routes in `docs/api/openapi.json`.
- TypeScript.
- The six unreferenced routes (decided separately).
- Multi-analyst features. The viewer serves one analyst on one machine.

## 2. Users and what they need

From `PRODUCT.md`: a DFIR analyst triaging, a report writer exporting, and a researcher checking how a verdict was reached. Every screen must make three things easy: see the verdict and its basis, see what is still missing, and get the evidence out.

Requirements that follow:
- **Provenance on every figure.** Each number names its source (for example "from static analysis" or "not enriched").
- **Unknown is not zero.** Missing values show as a dash or a named state, never 0 or an empty chart.
- **No half-finished sample is presented as complete.** Until the status is `completed`, the sample shows progress and only the Checks tab is open.
- **Copyable identifiers.** Hashes, package names, domains and IPs can be selected and copied.
- **Keyboard and screen-reader use.** Every control reachable by keyboard, with a visible focus ring.

## 3. Layout (decided)

Two columns, following mock D in the design canvas (decision recorded 2026-10-26):

```
+-------------------+-----------------------------------------------------------+
| Index rail        | Sample header                                             |
|                   |   name · hash (copy) · exports (after completion)         |
| New upload        |   facts: Analysis | Verdict | Family | Analyst status     |
| Filter            +-----------------------------------------------------------+
|                   | Tab bar: Overview · Attribution · Checks · Investigation · |
| 01 sample  high 78|          Raw code · Threat intel · Notes                  |
|    KungFu         +-----------------------------------------------------------+
| 02 sample  low 4  | Tab body                                                  |
|    Unattributed   |                                                           |
|                   |                                                           |
| status · docs     |                                                           |
+-------------------+-----------------------------------------------------------+
```

- The index rail is the only navigation. There is no second shell and no separate sample route with its own tab bar.
- Routes: `/` for upload and search, `/sample/:id/:tab` for a sample. Unknown tabs fall back to Overview.
- The rail is always visible on the sample page. Below 720px it stacks above the content.

Note: the rail shows row numbers in the mock. Section 5 explains why the shipped version omits them.

## 4. Visual system (decided)

Direction: "Quiet instrument panel". Dense but calm, neutral surfaces, one signal colour family for risk, system-like sans for UI, mono only for hashes and figures.

- **Theme:** dark, using the existing token names in `frontend/src/index.css` and `App.css`. Light theme is out of scope.
- **Type:** IBM Plex Sans for UI text, IBM Plex Mono for hashes, IOCs and numbers. Body measure 65–75ch on prose screens (Notes, Checks summaries).
- **Colour:** verdict colours only. High and critical use rose, medium uses amber, low uses emerald. Everything else is neutral. Colour is never the only carrier of meaning; each verdict also carries its word.
- **Structure:** hairline dividers and a single surface level. No cards inside cards, no decorative gradients, no glow.
- **Icons:** one drawn stroke set, one weight. No emoji and no Unicode glyphs as icons.
- **Motion:** one entrance on sample load, exponential ease-out. Reduced motion disables it.

## 5. Decisions that changed since 2026-10-26

| Item | Earlier decision | Now | Why |
|---|---|---|---|
| Row numbers in the index | Shown (mock D) | Not shown | Numbers add noise to a list the analyst reads by name and verdict. |
| Eyebrow above the header | Shown | Removed | Repeats the heading; the craft rules ban it. |
| Display font | Serif headings | Sans throughout | The serif "case file" look read as generic and scattered in review. |
| Accent | Amber on many elements | Verdict colour only | One signal per screen keeps findings readable. |
| Family confidence | Not shown | Shown with the family | Asked for in the analyst's header facts. |
| Verdict in the rail | Not shown | Shown per row | Lets triage happen from the list. |

## 6. Backend (done, no further change in this remake)

Phase 1 is complete on the branch:
- Legacy routes removed: `POST /analyze`, `GET /samples`, `GET /samples/{id}`.
- Attribution text: "M of N C2 indicators match the family baseline", or "no family baseline to compare against".
- C2 count: unique domains, junk values such as `{0}` dropped (`_unique_c2_indicators`).
- Upload-guard tests added (`tests/test_upload_guard.py`).
- Contract regenerated.

The six unreferenced routes stay until decided.

## 7. Data and endpoints the viewer uses

| Need | Endpoint | Notes |
|---|---|---|
| Sample list | `GET /api/samples?q=&limit=` | Rows carry name, family, severity, risk score. |
| Status gate | `GET /api/sample/{id}/status` | Tabs other than Checks stay locked until `completed`. |
| Full result | `GET /api/sample/{id}` | Contains all nine deep-analysis keys. |
| Attribution | `GET /api/sample/{id}/attribution` | Family, confidence, supporting signals. |
| Threat summary | `GET /api/sample/{id}/threat-summary` | Unique C2 count. |
| Analyst state | `GET` / `PUT /api/sample/{id}/analyst-state` | Status, tags, notes. |
| Exports | `GET /api/sample/{id}/threat-intel/export/{csv,stix,yara,suricata}` | Plain download links. |
| Upload and progress | `POST /api/upload`, `POST /api/analyze/{id}`, `/ws` | Unchanged. |

## 8. Phases and done criteria

Each phase ends with `npm run lint`, `npx vitest run`, and `npm run build` green. Each phase is its own reviewable commit.

**Phase A: foundation.** Tokens for the direction in section 4. Shared primitives: `Panel`, `FactStrip`, `VerdictChip`, `EmptyState`, `ErrorState`, `NotReady`. Done when every primitive has Vitest coverage for its states.

**Phase B: shell.** Index rail and sample header rebuilt on the primitives, the status gate, and the tab bar. Done when the shell renders for a completed sample, a running sample, and a failed sample, and the tab bar locks correctly.

**Phase C: Overview.** Four key figures with provenance, "Needs your attention" built from existing check results, attribution summary, the nine deep-analysis check cards, and the "All checks" list. Done when no figure is shown without its source and unknown values show as named states.

**Phase D: Attribution, Checks, Notes.** Attribution evidence and related samples; the Checks view (existing `AnalysisView` content, restyled); Notes with status, tags and autosave feedback. Done when every field round-trips through `analyst-state`.

**Phase E: Investigation, Raw code, Threat intel.** The three heavy views. Done when each renders for the largest sample in the local set without layout overflow, and exports download.

**Phase F: verification.**
- Browser pass against a running backend, scripted over the Chrome DevTools protocol: upload, watch progress, confirm no 404 on any tab during analysis, open every tab on a completed sample, export each format.
- Keyboard-only pass through the shell and every tab.
- Reduced-motion pass.
- Detector run over every changed file (`impeccable detect`).
- Done when the pass is clean or each remaining issue is listed with its reason.

## 9. Risks

- Phases C–E touch most current components. Existing tests (180 today) will change with them; each phase updates its own tests rather than deleting them.
- Investigation and Raw code are the largest views and the most likely to regress. They are last, so the earlier phases are not blocked by them.
- The analysis pipeline still produces the numbers the viewer shows. If a figure looks wrong, the cause may be upstream; the viewer reports what the result file says and does not correct it.

## 10. Open items

- Whether the six unreferenced API routes are removed (section 6).
- Whether the Checks tab keeps the existing `AnalysisView` internals or splits them into the new layout during Phase D.
- Whether the header shows a package name. The sample list has no package field today; showing it needs a backend change, which is out of scope here.
