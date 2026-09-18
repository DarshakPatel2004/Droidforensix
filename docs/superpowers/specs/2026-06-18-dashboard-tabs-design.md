# Dashboard Tabs Enhancement — Design Spec

**Date:** 2026-06-18  
**Approach:** A — Reuse existing components (minimal wiring)  
**Status:** Pending implementation approval

---

## 1. Overview

The analysis result view in the DroidForensix frontend currently has placeholder or incomplete tabs. This spec wires up the existing backend endpoints and reusable frontend components so that the following features work:

1. **Code Dissection tab** — list decompiled classes (with suspicious/obfuscated/all filters), view source code for a selected class, and highlight obfuscated classes. Inline source decoding is Phase 2.
2. **Manifest tab** — show the full parsed `AndroidManifest.xml` (app details, permissions, activities, services, receivers, providers).
3. **Dead IP visibility** — show all C2 indicators including dead IPs, with DNS status badges in both the Analysis C2 tab and the Threat Intelligence tab.
4. **Obfuscated code & decode** — surface obfuscated classes in the dissection list and provide a standalone deobfuscation tool in the Obfuscation tab.

---

## 2. Goals

- Make every Analysis result tab functional and data-backed.
- Reuse existing components (`SmartDissection`, `ObfuscationView`) where possible to minimize risk and delivery time.
- Do not degrade initial upload/analysis performance; data is fetched lazily per tab.
- Keep the Dissection tab responsive on large APKs by limiting the initial class-list render.

---

## 3. Non-Goals

- Full virtualization of the class list (out of scope; chunked rendering is the safeguard).
- Changing the pipeline result JSON format.
- Adding new analysis capabilities; this is a frontend/backend-integration task only.

---

## 4. Design Decisions

### 4.1 Approach A: Reuse existing components

Selected because it is the fastest, lowest-risk path. The backend already exposes all required endpoints in `backend/main.py`:

- `GET /api/sample/{id}/dissection/classes`
- `GET /api/sample/{id}/dissection/code/{class}`
- `GET /api/sample/{id}/dissection/manifest`
- `GET /api/sample/{id}/dissection/components`
- `GET /api/sample/{id}/dissection/permissions`
- `GET /api/sample/{id}/obfuscation`
- `POST /api/sample/{id}/deobfuscate`
- `GET /api/sample/{id}/threat-intel`

Frontend components `SmartDissection` and `ObfuscationView` already exist in `frontend/src/components/` and only need to be wired into `AnalysisView`.

The backend's `build_threat_intel()` already enriches every C2 with `status` (active / likely_active / dead) and `classification` (benign / suspicious / malicious).

### 4.2 Lazy tab data loading

Each tab fetches its own data on first mount. The Overview tab renders immediately from the already-loaded pipeline result; no extra network call is made until the user clicks another tab.

### 4.3 Class-list chunking

The Dissection tab renders only the first 250 classes by default. A "Load all" button fetches/renders the remainder. The default filter is **Suspicious**, which is typically a small subset. Search input is debounced (300 ms).

### 4.4 Source viewer loads on demand

Source code for a class is fetched only when the user clicks a class. No bulk source download occurs.

---

## 5. Component Changes

### 5.1 `AnalysisView.jsx`

- Pass `sampleId` (from `analysisState.sampleId`) down to all result tabs.
- Replace placeholder tabs:
  - `DissectionTab` → render `SmartDissection` (passed a sample object with `sampleId`) plus a new inline `ClassSourceViewer`.
  - `ManifestTab` → fetch and render full manifest from `/dissection/manifest`.
  - `C2Tab` → fetch `/threat-intel` and render C2 cards with `status` and `classification` badges.
  - `ObfuscationTab` → render the existing `ObfuscationView` component (passed a sample object with `sampleId`).
- `OverviewTab` and `ChainsTab` remain unchanged.

### 5.2 `SmartDissection` (existing component)

- Accept an `onSelectClass` callback prop.
- Trigger `onSelectClass(className)` when a class row is clicked.
- Keep existing filters, search, and expandable method cards.

### 5.3 New `ClassSourceViewer` component

- Props: `sampleId`, `className`, `apiUrl`.
- Fetches `GET /api/sample/{id}/dissection/code/{class}`.
- Displays code in a scrollable `<pre>` block with syntax highlighting.
- For the initial implementation, source display only. The Obfuscation tab already provides a standalone decode tool that covers the "ability to decode" requirement.
- Inline clickable decode for encoded strings in source is a Phase-2 enhancement.

### 5.4 `ManifestTab`

- Fetch three dissection endpoints on mount:
  - `/api/sample/{id}/dissection/manifest` — app/package metadata.
  - `/api/sample/{id}/dissection/components` — activities, services, receivers, providers.
  - `/api/sample/{id}/dissection/permissions` — declared and requested permissions.
- Display:
  - App details (package, version name, version code, min/target SDK).
  - Permissions as a tag cloud with protection-level badges.
  - Activities, services, receivers, providers as lists with `exported` flags highlighted.

### 5.5 `C2Tab` (AnalysisView)

- Fetch `/api/sample/{id}/threat-intel` on mount.
- Use `threatData.c2s` instead of `result.c2_infrastructure`.
- Render cards with:
  - Domain or IP
  - Protocol, port, type, confidence
  - Status badge: `active`, `likely_active`, `dead`, `unknown`
  - Classification badge: `benign`, `suspicious`, `malicious`

### 5.6 `ThreatIntelView.jsx`

- Verify C2 list already includes dead indicators (backend `build_threat_intel` returns all C2s).
- Add status badges to each C2 row if not already present.

### 5.7 `ObfuscationView` integration

- Replace the simple `ObfuscationTab` with the full `ObfuscationView` component.
- Pass `sample` and `apiUrl` props. The component already includes the deobfuscation tool.

---

## 6. Data Flow

| Tab | Endpoint(s) | Notes |
|-----|-------------|-------|
| Overview | pipeline result (already loaded) | no extra fetch |
| Dissection | `/dissection/classes`, `/obfuscation`, `/dissection/code/{class}` | lazy, source on demand |
| Manifest | `/dissection/manifest`, `/dissection/components`, `/dissection/permissions` | lazy |
| C2 | `/threat-intel` | lazy, enriched status |
| Threat Chains | pipeline result | no extra fetch |
| Obfuscation | `/obfuscation`, `/deobfuscate` | lazy |

---

## 7. Performance Safeguards

- Tabs fetch data only on first mount.
- Dissection class list defaults to **Suspicious** filter and renders first 250 classes.
- "Load all" button reveals the full list.
- Debounced search (300 ms).
- Source code fetched per class, not in bulk.
- No polling; all updates are event-driven or one-shot fetches.

---

## 8. Error Handling

- Each tab shows a user-friendly error state if its endpoint returns non-2xx or throws.
- Source viewer shows an error if a class source cannot be loaded.
- Decode action shows an error inline if the backend cannot decode a string.
- Network failures in tabs do not crash the whole result view.

---

## 9. Testing Plan

1. **Backend import test** — ensure `backend.main` still imports cleanly after any changes.
2. **Frontend build** — `npm run build` succeeds with no new errors.
3. **End-to-end smoke test** — upload a small APK, open each tab, verify data loads.
4. **Large APK sanity test** — open Dissection tab on a sample with many classes and confirm the UI stays responsive (only 250 rendered initially).
5. **Dead IP check** — analyze a sample with dead C2s and confirm they appear with status badges in both C2 and Threat Intelligence tabs.

---

## 10. Out of Scope / Future Work

- Virtualized scrolling for the class list (react-window or similar).
- Server-side rendering of tabs.
- Refactoring tabs into a shared data hook (Approach B).
- Embedding manifest/status into the pipeline result JSON (Approach C).
