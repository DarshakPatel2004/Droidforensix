# Code Dissection Main Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote the Code Dissection view from a sub-tab inside Analysis Results to its own top-level sidebar navigation tab.

**Architecture:** Create a new `DissectionPage` component that owns the class-source overlay state, register it as a main route in `App.jsx`, and remove the corresponding sub-tab from `AnalysisView.jsx`. Existing backend APIs and `SmartDissection` are reused unchanged.

**Tech Stack:** React 19, Vite, plain CSS.

---

## File map

| File | Responsibility |
|------|----------------|
| `frontend/src/components/DissectionPage.jsx` | New top-level view: renders `SmartDissection` and the class-source overlay. |
| `frontend/src/App.jsx` | Adds "Code Dissection" to main navigation and renders `DissectionPage`. |
| `frontend/src/components/AnalysisView.jsx` | Removes the "Code Dissection" sub-tab and its overlay state. |

---

### Task 1: Create the `DissectionPage` component

**Files:**
- Create: `frontend/src/components/DissectionPage.jsx`
- Modify: `frontend/src/App.jsx`

- [ ] **Step 1: Write `DissectionPage.jsx`**

```jsx
import { useState } from 'react'
import './AnalysisView.css'
import SmartDissection from './SmartDissection'
import ClassSourceViewer from './ClassSourceViewer'

export default function DissectionPage({ sample, apiUrl }) {
  const [selectedClass, setSelectedClass] = useState(null)
  const [showSource, setShowSource] = useState(false)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  if (!sampleId) {
    return (
      <div className="analysis-idle">
        <p>Select a sample to view code dissection.</p>
      </div>
    )
  }

  return (
    <div className="view-wrapper">
      <SmartDissection
        sample={sample}
        apiUrl={apiUrl}
        onSelectClass={(name) => {
          setSelectedClass(name)
          setShowSource(true)
        }}
      />
      {showSource && (
        <div className="source-overlay">
          <div className="source-overlay-header">
            <h4 className="source-class-name text-mono">{selectedClass}</h4>
            <button
              className="source-close-button"
              onClick={() => {
                setShowSource(false)
                setSelectedClass(null)
              }}
              aria-label="Close source view"
            >
              Close
            </button>
          </div>
          <div className="source-overlay-content">
            <ClassSourceViewer
              sampleId={sampleId}
              className={selectedClass}
              apiUrl={apiUrl}
            />
          </div>
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 2: Import and render `DissectionPage` in `App.jsx`**

Add the import near the top:

```jsx
import DissectionPage from './components/DissectionPage'
```

Add the nav item to `NAV_ITEMS`:

```jsx
const NAV_ITEMS = [
  { id: 'upload', label: 'Upload & Analyze', icon: '⬆' },
  { id: 'analysis', label: 'Analysis Results', icon: '🔍' },
  { id: 'dissection', label: 'Code Dissection', icon: '🔬' },
  { id: 'threat-intel', label: 'Threat Intelligence', icon: '🌐' },
]
```

Add the conditional render block inside `<main className="app-content">` after the threat-intel block:

```jsx
{activeTab === 'dissection' && selectedSample && (
  <div className="view-wrapper">
    <DissectionPage
      sample={selectedSample}
      apiUrl={API_URL}
    />
  </div>
)}
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/DissectionPage.jsx frontend/src/App.jsx
git commit -m "feat(frontend): promote Code Dissection to a main tab"
```

---

### Task 2: Remove Code Dissection from `AnalysisView.jsx`

**Files:**
- Modify: `frontend/src/components/AnalysisView.jsx`

- [ ] **Step 1: Remove unused imports**

Change:

```jsx
import SmartDissection from './SmartDissection'
import ClassSourceViewer from './ClassSourceViewer'
import ObfuscationView from './ObfuscationView'
```

To:

```jsx
import ObfuscationView from './ObfuscationView'
```

- [ ] **Step 2: Remove overlay state**

In `ResultView`, change:

```jsx
const [activeResultTab, setActiveResultTab] = useState('overview')
const [selectedClass, setSelectedClass] = useState(null)
const [showSource, setShowSource] = useState(false)
```

To:

```jsx
const [activeResultTab, setActiveResultTab] = useState('overview')
```

- [ ] **Step 3: Remove the dissection sub-tab and content**

Remove `{ id: 'dissection', label: 'Code Dissection' },` from the `resultTabs` array so it becomes:

```jsx
{[
  { id: 'overview', label: 'Overview' },
  { id: 'obfuscation', label: 'Obfuscation' },
  { id: 'c2', label: 'C2 Infrastructure' },
  { id: 'chains', label: 'Threat Chains' },
  { id: 'manifest', label: 'Manifest' },
].map(tab => (...
```

Remove the entire `activeResultTab === 'dissection'` content block (from `{activeResultTab === 'dissection' && (` through its closing `)}`).

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/AnalysisView.jsx
git commit -m "refactor(frontend): remove Code Dissection sub-tab from Analysis Results"
```

---

### Task 3: Verify the change

**Files:**
- None (manual verification)

- [ ] **Step 1: Build the frontend to catch compile errors**

```bash
cd frontend
npm run build
```

Expected: build completes with no errors.

- [ ] **Step 2: Run the linter**

```bash
cd frontend
npm run lint
```

Expected: no lint errors related to the changed files.

- [ ] **Step 3: Start the dev server and test manually**

In one terminal start the backend (if not already running):

```bash
python -m backend.main
```

In another terminal start the frontend:

```bash
cd frontend
npm run dev
```

Then:
1. Open the UI at the Vite URL (usually `http://localhost:5173`).
2. Upload or select an existing sample.
3. Confirm the sidebar shows **Code Dissection** and is clickable.
4. Click it and confirm the dissection view loads and class cards are listed.
5. Click **View source** on a class and confirm the source overlay opens.
6. Close the overlay and confirm it returns to the dissection list.
7. Switch to **Analysis Results** and confirm there is no **Code Dissection** sub-tab, and the remaining tabs (Overview, Obfuscation, C2 Infrastructure, Threat Chains, Manifest) still work.

- [ ] **Step 4: Commit verification notes (optional)**

No code changes; if everything passes, the task is complete.

---

## Self-review

**Spec coverage:**
- Top-level nav item added → Task 1, Step 2.
- Top-level rendering of Code Dissection → Task 1, Steps 1–2.
- Removal from Analysis Results sub-tabs → Task 2.
- Reuse existing APIs and styling → Tasks 1–2.
- Manual verification → Task 3.

**Placeholder scan:** No TBDs, TODOs, or vague steps. All code blocks contain the actual code to write.

**Type consistency:** `sample`, `apiUrl`, and `sampleId` derivations match existing patterns in `AnalysisView.jsx` and `SmartDissection.jsx`.
