# Dashboard Tabs Enhancement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing backend endpoints and frontend components into the Analysis result tabs so Code Dissection, Manifest, C2 status, and Obfuscation decode all work.

**Architecture:** Reuse `SmartDissection` and `ObfuscationView`, add a small `ClassSourceViewer`, and replace the placeholder tabs in `AnalysisView`. Each tab lazy-loads its own data. No backend changes are required.

**Tech Stack:** React 19, Vite, CSS modules (project uses plain `.css` files per component).

---

## File map

| File | Responsibility |
|------|---------------|
| `frontend/src/components/ClassSourceViewer.jsx` | NEW — fetch and display decompiled source for one class |
| `frontend/src/styles/ClassSourceViewer.css` | NEW — source viewer styles |
| `frontend/src/components/SmartDissection.jsx` | MODIFY — add `onSelectClass` callback + "View source" button |
| `frontend/src/styles/SmartDissection.css` | MODIFY — add `.view-source-btn` style |
| `frontend/src/components/AnalysisView.jsx` | MODIFY — replace placeholder tabs, pass `sampleId` |
| `frontend/src/components/AnalysisView.css` | MODIFY — layout for two-pane dissection, manifest grid, C2 badges |
| `frontend/src/components/ThreatIntelView.jsx` | MODIFY — add C2 list with status/classification badges |
| `frontend/src/styles/ThreatIntelView.css` | MODIFY — C2 list + badge styles |

---

## Task 1: Add class-source selection to SmartDissection

**Files:**
- Modify: `frontend/src/components/SmartDissection.jsx`
- Modify: `frontend/src/styles/SmartDissection.css`

### Step 1.1: Accept `onSelectClass` prop and pass it to ClassCard

Edit the `SmartDissection` default export signature and the `filteredClasses.map` call.

```jsx
// old
export default function SmartDissection({ sample, apiUrl }) {

// new
export default function SmartDissection({ sample, apiUrl, onSelectClass }) {
```

```jsx
// old
filteredClasses.map((cls, idx) => (
  <ClassCard key={idx} classData={cls} isObfuscated={isObfuscatedClass(cls)} expandAll={expandAll} />
))

// new
filteredClasses.map((cls, idx) => (
  <ClassCard
    key={idx}
    classData={cls}
    isObfuscated={isObfuscatedClass(cls)}
    expandAll={expandAll}
    onSelectClass={onSelectClass}
  />
))
```

### Step 1.2: Add `onSelectClass` to ClassCard and render View source button

```jsx
// old
function ClassCard({ classData, isObfuscated, expandAll }) {

// new
function ClassCard({ classData, isObfuscated, expandAll, onSelectClass }) {
```

Inside the class header right-hand badges, add a view-source button before the method count badge:

```jsx
<div className="class-header-right">
  {isObfuscated && <span className="class-badge badge-violet">Obfuscated</span>}
  {isSuspicious && <span className="class-badge badge-high">Suspicious</span>}
  {suspiciousMethodCount > 0 && (
    <span className="class-badge badge-amber">{suspiciousMethodCount} hit(s)</span>
  )}
  {(classData.network_calls || []).length > 0 && (
    <span className="class-badge badge-cyan">{classData.network_calls.length} network</span>
  )}
  {onSelectClass && (
    <button
      className="class-badge view-source-btn"
      onClick={(e) => {
        e.stopPropagation()
        onSelectClass(classData.name)
      }}
      title="View decompiled source"
    >
      View source
    </button>
  )}
  <span className="class-badge badge-slate">{methods.length} method(s)</span>
</div>
```

### Step 1.3: Add CSS for the View source button

Append to `frontend/src/styles/SmartDissection.css`:

```css
.view-source-btn {
  background: var(--accent-cyan, #06b6d4);
  color: #fff;
  border: none;
  border-radius: 0.25rem;
  padding: 0.15rem 0.5rem;
  font-size: 0.75rem;
  cursor: pointer;
  transition: filter 0.15s ease;
}

.view-source-btn:hover {
  filter: brightness(1.1);
}
```

### Step 1.4: Verify lint/build

Run:

```bash
export PATH="/d/DroidForensix/tools/node/current:$PATH"
cd frontend
npm run lint
```

Expected: no new errors in `SmartDissection.jsx`.

### Step 1.5: Commit

```bash
git add frontend/src/components/SmartDissection.jsx frontend/src/styles/SmartDissection.css
git commit -m "feat(dissection): add onSelectClass callback and View source button"
```

---

## Task 2: Create ClassSourceViewer component

**Files:**
- Create: `frontend/src/components/ClassSourceViewer.jsx`
- Create: `frontend/src/styles/ClassSourceViewer.css`

### Step 2.1: Write component

```jsx
import { useState, useEffect } from 'react'
import '../styles/ClassSourceViewer.css'

export default function ClassSourceViewer({ sampleId, className, apiUrl }) {
  const [source, setSource] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const API_URL = apiUrl || 'http://localhost:8000'

  useEffect(() => {
    if (!sampleId || !className) {
      setSource(null)
      setError(null)
      return
    }

    let cancelled = false
    setLoading(true)
    setError(null)

    const fetchSource = async () => {
      try {
        const encoded = encodeURIComponent(className)
        const response = await fetch(`${API_URL}/api/sample/${sampleId}/dissection/code/${encoded}`)
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const data = await response.json()
        if (!cancelled) setSource(data.code || '')
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchSource()
    return () => { cancelled = true }
  }, [sampleId, className, API_URL])

  if (!className) {
    return (
      <div className="source-viewer empty">
        <p>Select a class from the list to view its decompiled source.</p>
      </div>
    )
  }

  return (
    <div className="source-viewer">
      <div className="source-header">
        <h4 className="source-class-name text-mono">{className}</h4>
      </div>
      {loading && <div className="source-loading">Loading source…</div>}
      {error && <div className="source-error">Error loading source: {error}</div>}
      {!loading && !error && source !== null && (
        <pre className="source-code">
          <code>{source}</code>
        </pre>
      )}
    </div>
  )
}
```

### Step 2.2: Write styles

```css
.source-viewer {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--bg-elevated, #0f172a);
  border: 1px solid var(--border-color, #1e293b);
  border-radius: 0.5rem;
  overflow: hidden;
}

.source-viewer.empty {
  align-items: center;
  justify-content: center;
  color: var(--text-muted, #94a3b8);
  padding: 2rem;
  text-align: center;
}

.source-header {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border-color, #1e293b);
  background: var(--bg-card, #1e293b);
}

.source-class-name {
  margin: 0;
  font-size: 0.95rem;
  color: var(--text-primary, #f8fafc);
  word-break: break-all;
}

.source-loading,
.source-error {
  padding: 1rem;
  font-size: 0.9rem;
}

.source-error {
  color: var(--accent-rose, #f43f5e);
}

.source-code {
  flex: 1;
  margin: 0;
  padding: 1rem;
  overflow: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.85rem;
  line-height: 1.5;
  color: var(--text-primary, #f8fafc);
  background: var(--bg-elevated, #0f172a);
  white-space: pre;
}

.source-code code {
  font-family: inherit;
}
```

### Step 2.3: Verify build

```bash
export PATH="/d/DroidForensix/tools/node/current:$PATH"
cd frontend
npm run build
```

Expected: build succeeds.

### Step 2.4: Commit

```bash
git add frontend/src/components/ClassSourceViewer.jsx frontend/src/styles/ClassSourceViewer.css
git commit -m "feat(dissection): add ClassSourceViewer component"
```

---

## Task 3: Wire tabs in AnalysisView

**Files:**
- Modify: `frontend/src/components/AnalysisView.jsx`
- Modify: `frontend/src/components/AnalysisView.css`

### Step 3.1: Pass `sampleId` into ResultView and tabs

Inside `ResultView`, extract `sampleId` from `analysisState` and pass it to each tab.

```jsx
const ResultView = memo(({ analysisState, apiUrl, sample }) => {
  // ... existing state ...

  const sampleId = analysisState.sampleId

  // ... keep existing fetchResult useEffect ...

  return (
    <div className="analysis-result">
      {/* hero section unchanged */}

      <div className="result-tabs">
        {/* tab buttons unchanged */}
      </div>

      <div className="tab-content">
        {activeResultTab === 'overview' && (
          <OverviewTab result={fullResult} verdict={verdict} />
        )}
        {activeResultTab === 'dissection' && (
          <DissectionTab sampleId={sampleId} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'obfuscation' && (
          <ObfuscationTab sampleId={sampleId} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'c2' && (
          <C2Tab sampleId={sampleId} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'chains' && (
          <ChainsTab result={fullResult} />
        )}
        {activeResultTab === 'manifest' && (
          <ManifestTab sampleId={sampleId} apiUrl={apiUrl} />
        )}
      </div>
    </div>
  )
})
```

### Step 3.2: Replace placeholder tab components

Replace the existing `DissectionTab`, `ObfuscationTab`, `C2Tab`, and `ManifestTab` definitions with the implementations below. Insert them just before `ResultView.displayName = 'ResultView'`.

```jsx
/**
 * Code Dissection Tab
 */
const DissectionTab = memo(({ sampleId, apiUrl }) => {
  const [selectedClass, setSelectedClass] = useState(null)

  return (
    <div className="tab-panel dissection-tab-panel">
      <div className="dissection-pane dissection-list-pane">
        <SmartDissection
          sample={{ sampleId }}
          apiUrl={apiUrl}
          onSelectClass={setSelectedClass}
        />
      </div>
      <div className="dissection-pane dissection-source-pane">
        <ClassSourceViewer
          sampleId={sampleId}
          className={selectedClass}
          apiUrl={apiUrl}
        />
      </div>
    </div>
  )
})
DissectionTab.displayName = 'DissectionTab'

/**
 * Obfuscation Tab
 */
const ObfuscationTab = memo(({ sampleId, apiUrl }) => {
  return (
    <div className="tab-panel">
      <ObfuscationView sample={{ sampleId }} apiUrl={apiUrl} />
    </div>
  )
})
ObfuscationTab.displayName = 'ObfuscationTab'

/**
 * C2 Infrastructure Tab
 */
const C2Tab = memo(({ sampleId, apiUrl }) => {
  const [threatData, setThreatData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const API_URL = apiUrl || 'http://localhost:8000'

  useEffect(() => {
    let cancelled = false
    setLoading(true)

    const fetchThreatIntel = async () => {
      try {
        const response = await fetch(`${API_URL}/api/sample/${sampleId}/threat-intel`)
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const data = await response.json()
        if (!cancelled) {
          setThreatData(data)
          setError(null)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message)
          setThreatData(null)
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchThreatIntel()
    return () => { cancelled = true }
  }, [sampleId, API_URL])

  if (loading) return <div className="tab-panel"><p>Loading C2 intelligence…</p></div>
  if (error) return <div className="tab-panel"><p className="result-error">C2 load failed: {error}</p></div>

  const c2s = threatData?.c2s || []

  return (
    <div className="tab-panel">
      {c2s.length === 0 ? (
        <p>No C2 infrastructure detected.</p>
      ) : (
        <div className="c2-grid">
          {c2s.map((c2, idx) => (
            <div key={idx} className="card c2-card">
              <h4>{c2.domain || c2.ip || 'Unknown'}</h4>
              <div className="c2-badges">
                <span className={`c2-badge c2-status-${c2.status || 'unknown'}`}>
                  {c2.status || 'unknown'}
                </span>
                <span className={`c2-badge c2-classification-${c2.classification || 'unknown'}`}>
                  {c2.classification || 'unknown'}
                </span>
              </div>
              <div className="c2-details">
                <p><strong>Protocol:</strong> {c2.protocol}</p>
                <p><strong>Port:</strong> {c2.port || '—'}</p>
                <p><strong>Type:</strong> {c2.communication_type}</p>
                <p><strong>Confidence:</strong> {Math.round((c2.confidence || 0) * 100)}%</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
})
C2Tab.displayName = 'C2Tab'

/**
 * Manifest Tab
 */
const ManifestTab = memo(({ sampleId, apiUrl }) => {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const API_URL = apiUrl || 'http://localhost:8000'

  useEffect(() => {
    let cancelled = false
    setLoading(true)

    const fetchManifest = async () => {
      try {
        const [manifestRes, componentsRes, permissionsRes] = await Promise.all([
          fetch(`${API_URL}/api/sample/${sampleId}/dissection/manifest`),
          fetch(`${API_URL}/api/sample/${sampleId}/dissection/components`),
          fetch(`${API_URL}/api/sample/${sampleId}/dissection/permissions`),
        ])
        if (!manifestRes.ok) throw new Error(`Manifest HTTP ${manifestRes.status}`)
        if (!componentsRes.ok) throw new Error(`Components HTTP ${componentsRes.status}`)
        if (!permissionsRes.ok) throw new Error(`Permissions HTTP ${permissionsRes.status}`)

        const [manifestData, componentsData, permissionsData] = await Promise.all([
          manifestRes.json(),
          componentsRes.json(),
          permissionsRes.json(),
        ])

        if (!cancelled) {
          setData({
            manifest: manifestData.manifest || {},
            components: componentsData.components || {},
            permissions: permissionsData.permissions || [],
          })
          setError(null)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message)
          setData(null)
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchManifest()
    return () => { cancelled = true }
  }, [sampleId, API_URL])

  if (loading) return <div className="tab-panel"><p>Loading manifest…</p></div>
  if (error) return <div className="tab-panel"><p className="result-error">Manifest load failed: {error}</p></div>

  const manifest = data?.manifest || {}
  const components = data?.components || {}
  const permissions = data?.permissions || []

  const renderComponentList = (items, label) => {
    const list = items || []
    return (
      <div className="manifest-component-section">
        <h4>{label} ({list.length})</h4>
        {list.length === 0 ? (
          <p className="empty-state">No {label.toLowerCase()} declared.</p>
        ) : (
          <ul className="manifest-component-list">
            {list.map((item, idx) => (
              <li key={idx} className="manifest-component-item">
                <code className="text-mono">{item.name}</code>
                {item.exported && <span className="badge badge-rose exported-badge">exported</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
    )
  }

  return (
    <div className="tab-panel manifest-tab">
      <div className="manifest-grid">
        <div className="card">
          <h3>App Details</h3>
          <p><strong>Package:</strong> {manifest.package || '—'}</p>
          <p><strong>Version:</strong> {manifest.version_name || '—'} ({manifest.version_code || '—'})</p>
          <p><strong>Min SDK:</strong> {manifest.min_sdk || '—'}</p>
          <p><strong>Target SDK:</strong> {manifest.target_sdk || '—'}</p>
          <p><strong>Max SDK:</strong> {manifest.max_sdk || '—'}</p>
        </div>

        <div className="card">
          <h3>Permissions ({permissions.length})</h3>
          <div className="permissions-cloud">
            {permissions.map((perm, idx) => (
              <span
                key={idx}
                className={`permission-badge ${perm.protection_level === 'dangerous' ? 'dangerous' : ''}`}
                title={perm.description || perm.name}
              >
                {perm.name}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="card manifest-components">
        <h3>Components</h3>
        {renderComponentList(components.activities, 'Activities')}
        {renderComponentList(components.services, 'Services')}
        {renderComponentList(components.receivers, 'Receivers')}
        {renderComponentList(components.providers, 'Providers')}
      </div>
    </div>
  )
})
ManifestTab.displayName = 'ManifestTab'
```

### Step 3.3: Add imports to AnalysisView

At the top of `AnalysisView.jsx`, add:

```jsx
import SmartDissection from './SmartDissection'
import ClassSourceViewer from './ClassSourceViewer'
import ObfuscationView from './ObfuscationView'
```

### Step 3.4: Add CSS for the new tab layouts

Append to `frontend/src/components/AnalysisView.css`:

```css
/* Dissection two-pane layout */
.dissection-tab-panel {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  height: 100%;
  min-height: 60vh;
}

.dissection-pane {
  min-height: 0;
  overflow: auto;
}

@media (max-width: 900px) {
  .dissection-tab-panel {
    grid-template-columns: 1fr;
  }
}

/* C2 status / classification badges */
.c2-badges {
  display: flex;
  gap: 0.5rem;
  margin: 0.5rem 0;
  flex-wrap: wrap;
}

.c2-badge {
  font-size: 0.75rem;
  padding: 0.2rem 0.5rem;
  border-radius: 0.25rem;
  text-transform: uppercase;
  font-weight: 600;
}

.c2-status-active { background: #059669; color: #fff; }
.c2-status-likely_active { background: #d97706; color: #fff; }
.c2-status-dead { background: #dc2626; color: #fff; }
.c2-status-unknown { background: #64748b; color: #fff; }

.c2-classification-benign { background: #10b981; color: #fff; }
.c2-classification-suspicious { background: #f59e0b; color: #fff; }
.c2-classification-malicious { background: #ef4444; color: #fff; }
.c2-classification-unknown { background: #64748b; color: #fff; }

/* Manifest grid */
.manifest-tab .manifest-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-bottom: 1rem;
}

.manifest-tab .permissions-cloud {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.manifest-components {
  margin-top: 1rem;
}

.manifest-component-section {
  margin-bottom: 1rem;
}

.manifest-component-section h4 {
  margin: 0 0 0.5rem 0;
  color: var(--text-primary, #f8fafc);
}

.manifest-component-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.manifest-component-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.35rem 0.5rem;
  background: var(--bg-elevated, #0f172a);
  border-radius: 0.25rem;
}

.exported-badge {
  font-size: 0.7rem;
  padding: 0.15rem 0.4rem;
}
```

### Step 3.5: Build check

```bash
export PATH="/d/DroidForensix/tools/node/current:$PATH"
cd frontend
npm run build
```

Expected: build succeeds.

### Step 3.6: Commit

```bash
git add frontend/src/components/AnalysisView.jsx frontend/src/components/AnalysisView.css
 git commit -m "feat(analysis): wire SmartDissection, ClassSourceViewer, Manifest, C2, Obfuscation tabs"
```

---

## Task 4: Add C2 status badges to ThreatIntelView

**Files:**
- Modify: `frontend/src/components/ThreatIntelView.jsx`
- Modify: `frontend/src/styles/ThreatIntelView.css`

### Step 4.1: Render a C2 indicator list

After the geo map section and before the Exports section, add:

```jsx
<div className="threat-card card">
  <h3 className="section-title">C2 Indicators ({c2s.length})</h3>
  {c2s.length === 0 ? (
    <p className="empty-state">No C2 indicators available.</p>
  ) : (
    <div className="c2-indicator-list">
      {c2s.map((c2, idx) => (
        <div key={idx} className="c2-indicator-row">
          <div className="c2-indicator-main">
            <code className="text-mono">{c2.domain || c2.ip || 'Unknown'}</code>
            <span className="c2-indicator-meta">
              {c2.protocol} {c2.port ? `:${c2.port}` : ''} · {c2.communication_type}
            </span>
          </div>
          <div className="c2-indicator-badges">
            <span className={`c2-badge c2-status-${c2.status || 'unknown'}`}>
              {c2.status || 'unknown'}
            </span>
            <span className={`c2-badge c2-classification-${c2.classification || 'unknown'}`}>
              {c2.classification || 'unknown'}
            </span>
          </div>
        </div>
      ))}
    </div>
  )}
</div>
```

### Step 4.2: Add CSS

Append to `frontend/src/styles/ThreatIntelView.css`:

```css
.c2-indicator-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.c2-indicator-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.6rem 0.75rem;
  background: var(--bg-elevated, #0f172a);
  border-radius: 0.35rem;
}

.c2-indicator-main {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  min-width: 0;
}

.c2-indicator-main code {
  word-break: break-all;
}

.c2-indicator-meta {
  font-size: 0.8rem;
  color: var(--text-muted, #94a3b8);
}

.c2-indicator-badges {
  display: flex;
  gap: 0.35rem;
  flex-shrink: 0;
}
```

### Step 4.3: Build check

```bash
export PATH="/d/DroidForensix/tools/node/current:$PATH"
cd frontend
npm run build
```

### Step 4.4: Commit

```bash
git add frontend/src/components/ThreatIntelView.jsx frontend/src/styles/ThreatIntelView.css
git commit -m "feat(threat-intel): show all C2 indicators with status/classification badges"
```

---

## Task 5: Verification

### Step 5.1: Backend import test

```bash
source venv/Scripts/activate
python -c "import backend.main; print('backend import OK')"
```

Expected: `backend import OK`

### Step 5.2: Frontend build + lint

```bash
export PATH="/d/DroidForensix/tools/node/current:$PATH"
cd frontend
npm run build
npm run lint
```

Expected: build succeeds; lint has no new errors (existing warnings in other files are acceptable).

### Step 5.3: Smoke test (manual)

1. Start backend: `./run_backend.bat`
2. Start frontend: `cd frontend && npm run dev`
3. Upload a small APK.
4. After analysis completes, open each tab:
   - **Dissection:** class list loads, clicking "View source" shows source code.
   - **Manifest:** app details, permissions, components appear.
   - **C2:** indicators appear with status/classification badges.
   - **Obfuscation:** scores + decode tool loads.
   - **Threat Intel:** C2 indicator list shows status badges.

### Step 5.4: Commit final

```bash
git add .
git commit -m "test(dashboard): verify tabs build and load data end-to-end"
```

---

## Self-review checklist

- **Spec coverage:**
  - Code Dissection tab ✅ Task 1, 2, 3
  - Manifest tab ✅ Task 3
  - Dead IP visibility ✅ Task 3 (C2 tab) + Task 4 (ThreatIntelView)
  - Obfuscated code/decode ✅ Task 1/2 (obfuscated class filter + source viewer) + Task 3 (ObfuscationView with decode tool)
- **No placeholders:** all code shown; no TBD/TODO.
- **Type consistency:** `sampleId` string passed everywhere; `apiUrl` used consistently; backend endpoint paths match existing routes.
- **Performance:** lazy loading per tab, 250-class chunking handled by existing SmartDissection logic.
