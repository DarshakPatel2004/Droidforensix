# Design: Promote Code Dissection to a Main Tab

## Goal
Move the **Code Dissection** view out of the "Analysis Results" sub-tabs and make it a top-level main navigation tab in the DroidForensix dashboard.

## Current State
- `frontend/src/App.jsx` defines three main nav items: **Upload & Analyze**, **Analysis Results**, **Threat Intelligence**.
- `frontend/src/components/AnalysisView.jsx` renders six sub-tabs: Overview, Code Dissection, Obfuscation, C2 Infrastructure, Threat Chains, Manifest.
- `frontend/src/components/SmartDissection.jsx` fetches and displays the APK dissection (manifest, permissions, components, DEX, classes, strings) and lets the user open decompiled class source in an overlay.

## Proposed Design

### 1. Navigation
Add a new top-level sidebar item in `App.jsx`:

```js
{ id: 'dissection', label: 'Code Dissection', icon: '🔬' }
```

It follows the same enable/disable rule as the other non-upload items: disabled until a sample is selected.

### 2. Top-Level Rendering
Create a small wrapper component (inline in `App.jsx` or as `components/DissectionPage.jsx`) that:
- Holds local state for `selectedClass` and `showSource`.
- Renders `<SmartDissection sample={selectedSample} apiUrl={API_URL} onSelectClass={...} />`.
- Renders the class-source overlay when `showSource` is true.

`App.jsx` will conditionally render this wrapper when `activeTab === 'dissection'`.

### 3. Remove from Sub-Tabs
In `AnalysisView.jsx`:
- Remove the `dissection` entry from the sub-tab list.
- Remove the `activeResultTab === 'dissection'` content block.
- Keep Overview, Obfuscation, C2 Infrastructure, Threat Chains, and Manifest unchanged.

### 4. Routing / State
- No backend changes are required; existing `/api/sample/{sample_id}/dissection/...` endpoints are reused.
- Selecting or uploading a sample continues to switch to the **Analysis Results** tab by default.
- The user can then click **Code Dissection** in the sidebar to view the dedicated dissection page.

### 5. Styling
- Reuse existing `SmartDissection` and source-overlay styles.
- Ensure the wrapper fills the main content area consistently with the other views.

## Error Handling
- If no sample is selected, the nav item is disabled.
- `SmartDissection` already handles loading, missing data, and failed API calls.

## Testing
- Manual UI verification:
  1. Upload/select a sample.
  2. Confirm **Code Dissection** appears in the sidebar and is clickable.
  3. Confirm clicking it shows the dissection view and class source overlay works.
  4. Confirm the **Analysis Results** sub-tabs no longer contain Code Dissection.
  5. Confirm other sub-tabs still render correctly.

## Trade-offs
- **Pros**: Gives dissection equal prominence to Threat Intelligence; more screen real estate; clearer mental model (analysis = verdict + chains, dissection = deep-dive code inspection).
- **Cons**: Slightly more state lifted into `App.jsx`; another sidebar item increases navigation density.
