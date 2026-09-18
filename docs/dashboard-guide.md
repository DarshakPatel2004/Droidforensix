# DroidForensix Dashboard Guide

## Overview

The dashboard provides three levels of analysis for Android APK samples:

- **Glance (Level 1):** Threat summary with score, family, and red flags
- **Triage (Level 2):** MAFIA attribution evidence with confidence breakdown
- **Investigation (Level 3):** Dissection tabs with code analysis, strings, DEX stats

## Workflow

### 1. Upload a Sample

1. Open the dashboard at `http://localhost:5173`
2. Drag-and-drop an APK file onto the upload panel, or click to browse
3. The 9-step pipeline runs automatically with a live progress bar
4. Each step shows its name, duration, and LLM verification when available

### 2. View Analysis Results

After analysis completes:

- **Threat Score** — Overall risk score (0-100) with severity level
- **Family** — MAFIA-attributed malware family with confidence percentage
- **Red Flags** — Quick indicators: dangerous permissions, active C2 endpoints, obfuscation level, evasion techniques

### 3. Examine Attribution Evidence

The Attribution tab shows:

- **Confidence Breakdown** — Per-dimension scores (permissions match, C2 overlap, obfuscation pattern, code similarity)
- **Supporting Signals** — Human-readable evidence statements
- **Related Samples** — Similar samples with similarity scores

### 4. Investigate with Dissection Tabs

Seven tabs for deep investigation:

| Tab | Content |
|-----|---------|
| Manifest | Package name, permissions, activities, services, providers |
| Permissions | All permissions with danger-level highlighting |
| Components | Activities, services, receivers, providers (exported shown) |
| Code | Class browser with syntax highlighting, method risk badges, attack flow, string references |
| Strings | Searchable/filterable string list with Base64/hex/URL auto-decode |
| DEX | DEX stats (classes, methods, strings, bytes) with entropy gauge |
| Native Libs | Native libraries (.so files) per architecture |

### 5. Threat Intelligence

The Threat Intel tab shows:

- C2 endpoint details with live/dead status
- Geolocation map of C2 infrastructure
- ISP/ASN enrichment
- Export options: CSV, STIX, YARA

## Sample Search

Use the search panel on the Upload page to find previously analyzed samples by hash, package name, or family.

## Keyboard Shortcuts

- `Enter` in search field — Trigger search
- Tab navigation — Click sidebar items to switch views

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| "Backend offline" | Ensure `run_backend.bat` is running on port 8000 |
| Upload fails | Check file is a valid APK (<100MB) |
| No dissection data | Some APKs fail JADX decompilation — Raw Code tab may still work |
| No C2 indicators | Sample may be C2-blind (zero static artifacts) |
