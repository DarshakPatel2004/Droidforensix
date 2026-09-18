# Frontend Design — DroidForensix

This document captures the frontend architecture, design decisions, and the features that have been implemented in the React + Vite dashboard.

---

## 1. Tech Stack

- **Framework:** React 18 (functional components + hooks)
- **Build Tool:** Vite
- **Styling:** Plain CSS with CSS custom properties (design tokens)
- **Icons:** Inline SVG (no external icon library dependency)
- **HTTP:** Native `fetch`
- **Real-time:** WebSocket (`/ws`) for live pipeline events
- **Fonts:** Inter + JetBrains Mono (Google Fonts)

---

## 2. Global Design Tokens

Defined in `frontend/src/index.css`.

```css
/* Core backgrounds */
--bg-primary: #0b0f19;
--bg-secondary: #111827;
--bg-surface: #1f2937;
--bg-surface-hover: #273449;

/* Borders & text */
--border-color: rgba(148, 163, 184, 0.12);
--border-strong: rgba(148, 163, 184, 0.22);
--text-primary: #f8fafc;
--text-secondary: #94a3b8;
--text-muted: #64748b;

/* Accents */
--accent-cyan: #06b6d4;
--accent-rose: #f43f5e;
--accent-amber: #f59e0b;
--accent-emerald: #10b981;
--accent-violet: #8b5cf6;

/* Semantic risk colors */
--risk-low: var(--accent-emerald);
--risk-medium: var(--accent-amber);
--risk-high: var(--accent-rose);

/* Shadows, radius, fonts */
--shadow-sm / --shadow-md / --shadow-lg;
--radius-sm: 6px;
--radius-md: 10px;
--radius-lg: 16px;
--font-sans: 'Inter', ...;
--font-mono: 'JetBrains Mono', ...;
```

---

## 3. Layout

- **Sidebar navigation** (`App.jsx` + `App.css`)
  - Fixed left sidebar with brand, nav items, and WebSocket status indicator.
  - Responsive: collapses to a hamburger menu on small screens.
- **Topbar**
  - Shows the active view title and backend online/offline status.
- **Main content area**
  - Max-width `1440px`, centered, with consistent `1.5rem` padding.

---

## 4. Views / Pages

### 4.1 Upload & Analyze

- **Component:** `UploadPanel.jsx` / `UploadDropzone.jsx`
- Drag-and-drop APK upload.
- After upload, the app auto-switches to **Analysis Results** and starts analysis.
- Recent uploads list with status, severity, and one-click re-analysis.

### 4.2 Analysis Results — `AnalysisView.jsx`

The main analysis landing page. Contains:

#### Hero Header
- Severity-colored accent line and glow.
- Package name as the main title.
- **Family identification badge** (when available).
- Copyable SHA256 chip, file size, class count, and analysis duration.
- Circular risk gauge with gradient stroke.
- Verdict pill: `VERDICT • SEVERITY`.

#### KPI Strip
Four metric cards with color-coded SVG icons and mini progress bars:
- C2 Endpoints
- Threat Chains
- Obfuscation score
- Permissions count

#### Tab Bar
Icon + label tabs:
- Overview
- Code Dissection
- Obfuscation
- C2 Infrastructure
- Threat Chains
- Manifest

Active tab has a cyan underline and soft gradient background.

#### Overview Tab
- Assessment summary card with narrative, verdict pill, and quick tags (risk score, primary threat, top obfuscation technique).
- Sample details list (package, SHA256, MD5, size, classes, strings, encodings, payloads).
- Risk factors list with severity-colored left borders and icons.

#### Code Dissection Tab — `SmartDissection.jsx`
- Filter toolbar: **Suspicious**, **Obfuscated**, **All Classes**.
- Search by class/method name.
- Global **Expand code / Collapse code** toggle.
- Class cards show badges for suspicious/obfuscated/network activity.
- Each class lists all methods (sorted by suspiciousness).
- Methods show a 3-line code preview by default; click to expand full body.
- Syntax highlighting for suspicious keywords.
- Sections for Network Activity and Permissions Used.

#### Obfuscation Tab — `ObfuscationView.jsx`
- Obfuscation score and level.
- Technique cards (reflection, dynamic loading, crypto APIs, etc.) with class/method evidence.
- Packed/encrypted DEX list with entropy.
- Native library artifacts.
- Built-in **Deobfuscation Tool** supporting Base64, hex, URL decode, and XOR brute force.

#### C2 Infrastructure Tab
- Section header with count.
- Grid cards per C2 endpoint showing protocol, confidence, raw URL, host, port, type, and classification.

#### Threat Chains Tab
- Pagination (5 chains per page).
- Timeline-style chain cards with numbered markers, connectors, severity badge, and confidence.
- Expandable artifacts for long strings.

#### Manifest Tab
- App details card (version name/code, target/min SDK).
- Permissions cloud with dangerous permissions highlighted in rose.

### 4.3 Threat Intelligence — `ThreatIntelView.jsx`

- DNS resolution status for C2 domains.
- IP classification and geolocation.
- WHOIS / ASN enrichment.
- Export actions: CSV blocklist, STIX 2.0 bundle, YARA rule.

---

## 5. Analysis Loading State

Shown immediately after uploading an APK while the pipeline runs.

- Animated **radar/scanner** visual instead of a plain spinner.
- Title: **"Static Analysis Running"**.
- Live **step tracker** showing every pipeline stage (done / current / pending).
- Progress bar with **live ETA**.
- Live metrics counters (strings, encodings, payloads, C2s, chains).
- Terminal-style event log with skeleton rows before the first event.

---

## 6. Component Patterns

- **Cards:** `.card` utility class for panels; `.card-hover` for lift + border glow on hover.
- **Badges:** `.badge`, `.badge-low`, `.badge-medium`, `.badge-high`, `.badge-violet`, `.badge-cyan`, `.badge-amber`, `.badge-slate`.
- **Section titles:** Uppercase, letter-spaced, muted color.
- **Empty states:** Centered icon + title + description inside a card.
- **Monospace text:** `.text-mono` for SHA256, class names, URLs, code.

---

## 7. API Integration

| Endpoint | Purpose |
|----------|---------|
| `POST /api/upload` | Upload APK |
| `POST /api/analyze/{upload_id}` | Start analysis |
| `GET /api/sample/{id}/status` | Poll analysis status |
| `GET /api/sample/{id}` | Full analysis result |
| `GET /api/sample/{id}/dissection/classes` | Decompiled classes |
| `GET /api/sample/{id}/obfuscation` | Obfuscation dashboard |
| `POST /api/sample/{id}/deobfuscate` | Decode user string |
| `GET /api/sample/{id}/family` | Family identification |
| `GET /api/sample/{id}/threat-intel` | Enriched C2 intel |
| `WS /ws` | Real-time pipeline events |

---

## 8. Responsive Behavior

- KPI strip collapses from 4 → 2 → 1 columns.
- Analysis hero stacks vertically on small screens.
- Overview and Manifest grids become single-column.
- Tab bar scrolls horizontally.
- Code Dissection toolbar stacks filters + search vertically.

---

## 9. Key Files

| File | Responsibility |
|------|----------------|
| `frontend/src/App.jsx` | Layout, routing, WebSocket, upload/analysis orchestration |
| `frontend/src/App.css` | Sidebar, topbar, layout skeleton |
| `frontend/src/index.css` | Design tokens, utilities, animations |
| `frontend/src/components/AnalysisView.jsx` | Analysis landing page + loading state |
| `frontend/src/styles/AnalysisView.css` | Analysis page styling |
| `frontend/src/components/SmartDissection.jsx` | Code Dissection tab |
| `frontend/src/styles/SmartDissection.css` | Code Dissection styling |
| `frontend/src/components/ObfuscationView.jsx` | Obfuscation tab |
| `frontend/src/styles/ObfuscationView.css` | Obfuscation styling |
| `frontend/src/components/ThreatIntelView.jsx` | Threat Intelligence view |
| `frontend/src/components/UploadPanel.jsx` | Upload + recent samples list |

---

## 10. Build & Test

```bash
# Production build
cd frontend
node_modules/.bin/vite build

# Backend tests
python -m pytest tests/ -q
```

Both commands are green as of the latest changes.
