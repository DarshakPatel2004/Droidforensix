# Product

## Register

product

## Purpose

DroidForensix is a static-analysis viewer for Android APK samples. The offline pipeline (`analysis/`) produces a result file per sample; this viewer shows it. It serves a major project and is also meant to be defensible in front of law-enforcement and legal audiences (LEA/LEO), so every figure must be traceable to its source and every missing value must say it is missing.

## Users

- **Primary: DFIR analyst** working alone on a local machine. Triage first (malicious, suspicious or benign), then drill into evidence.
- **Report writer** gathering evidence and IOC exports (CSV, STIX, YARA, Suricata, PDF) for a case file or hand-off.
- **Researcher / reviewer** checking how the pipeline reached its verdict. Less time-pressured, more interested in provenance and confidence.

Users are trained, time-pressured in triage, and will be asked to justify findings later. Clarity and precision beat expression.

## What the header must show at a glance

1. Analysis status: complete, running or failed.
2. Verdict and risk score (0-100).
3. Family and attribution confidence, including "no family match".
4. Analyst status and tags (new, confirmed, false positive).

## Principles

- Numbers match their data source. Unknown is shown as unknown, never as zero.
- A sample still in analysis is never presented as complete.
- Hashes, package names and IOCs are shown exactly and can be copied.
- Dense is fine when it is ordered. Scannable rows, hairline structure, no decoration that competes with data.
- Colour carries meaning only: one signal colour family for risk, neutral everywhere else.

## Anti-references

- The "case file" look from the previous iteration: serif display headings, paper-like texture, amber accents on everything. The user judged it generic and scattered.
- Marketing-style hero blocks, gradient meshes, glowing status dots as decoration.
- Consumer security dashboards with big coloured tiles and no provenance.

## Constraints

- Dark theme. Keep the existing token names in `frontend/src/App.css` and `frontend/src/index.css`.
- Layout is fixed by the rewrite spec: sample list on the left, per-sample header, tab bar, tab body (`docs/plans/2026-10-26-frontend-rewrite-design.md`, section 9 item 6).
- Tab bodies are out of scope for this pass.
- Keyboard-operable, visible focus, reduced-motion respected.
