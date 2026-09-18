# DroidForensix Obsidian Vault - Windows Setup Guide

Complete automated setup for persistent memory in OpenCode + Obsidian on Windows.

---

## Prerequisites

Before you start, make sure you have:

- **Windows 10/11**
- **PowerShell 5.1+** (built-in on Windows 10/11)
- **Git for Windows** → https://git-scm.com/download/win
- **Node.js 22+** → https://nodejs.org/ (use LTS)
- **Obsidian** → https://obsidian.md/download

**Verify installation:**
```powershell
git --version
node --version
```

---

## Quick Start (3 steps)

### Step 1: Run Setup Script

Open PowerShell **as Administrator** and run:

```powershell
cd C:\Users\YourUsername\Documents
powershell -ExecutionPolicy Bypass -File Setup-ObsidianVault.ps1
```

This will:
- ✅ Clone obsidian-mind template to `C:\Users\YourUsername\Documents\my-forensics-vault`
- ✅ Create your North Star (goals + projects)
- ✅ Set up DroidForensix, PhishScope, VulnForge
- ✅ Create competency framework
- ✅ Initialize git

**Custom vault path:**
```powershell
powershell -ExecutionPolicy Bypass -File Setup-ObsidianVault.ps1 -VaultPath "D:\My Vault"
```

### Step 2: Open in Obsidian

1. Download and install **Obsidian** from https://obsidian.md/download
2. Open Obsidian
3. Click **"Open folder as vault"**
4. Select `C:\Users\YourUsername\Documents\my-forensics-vault`
5. Go to **Settings → General** and toggle **"Allow command line interface"** ON

### Step 3: Set Up OpenCode

Open PowerShell **as Administrator** and run:

```powershell
cd C:\Users\YourUsername\Documents\my-forensics-vault
powershell -ExecutionPolicy Bypass -File ..\Setup-OpenCodeAlias.ps1
```

Reload PowerShell:
```powershell
. $PROFILE
```

Now test it:
```powershell
oc
```

OpenCode should start with your vault context already loaded.

---

## What You Get

After setup:

✅ **Full vault at:** `C:\Users\YourUsername\Documents\my-forensics-vault`

✅ **North Star** with your research goals, timeline, constraints

✅ **Active Projects:**
- DroidForensix (primary)
- C2 Validation Study
- PhishScope Report
- VulnForge Maintenance

✅ **Competency Framework:**
- Static Analysis
- Research Communication

✅ **Brag Doc** for tracking wins

✅ **Git version control** for all changes

✅ **OpenCode `oc` alias** that auto-loads vault context

---

## File Structure

After setup, your vault looks like:

```
my-forensics-vault\
├── brain\
│   ├── North Star.md              ← Your goals (read every session)
│   ├── Key Decisions.md
│   ├── Patterns.md
│   └── Skills.md
│
├── work\
│   ├── active\
│   │   ├── DroidForensix.md
│   │   ├── C2 Validation Study.md
│   │   ├── PhishScope Report.md
│   │   └── VulnForge Maintenance.md
│   ├── archive\                   ← Completed work
│   └── 1-1\                       ← Meeting notes (add as needed)
│
├── org\
│   ├── people\                    ← Team members (empty for now)
│   └── teams\
│
├── perf\
│   ├── Brag Doc.md                ← Wins tracker
│   ├── competencies\
│   │   ├── Static Analysis.md
│   │   └── Research Communication.md
│   └── evidence\
│
├── reference\                     ← Architecture docs
├── thinking\                      ← Scratchpad
├── .claude\                       ← Claude Code config
├── bases\                         ← Database views
│
└── CLAUDE.md                      ← Operating manual
```

---

## Usage

### Start OpenCode with Context

```powershell
oc
```

OpenCode launches and **automatically knows:**
- Your research goals (publish at Virus Bulletin)
- Active projects (DroidForensix priority)
- Current blockers (validate aggregator miss)
- Deadline (May 2027)
- Technical environment (Windows, RTX 4050, Ollama)

### Ask OpenCode

```
What should I work on next for DroidForensix?
```

It reads your vault and suggests based on:
- North Star priorities
- Open tasks in C2 Validation Study
- Recent git changes
- Competency development areas

### Available Claude Code Commands

Once vault is open in Claude Code:

```
/om-standup           # Morning kickoff
/om-dump              # Brain dump anything
/om-wrap-up           # End of day review
/om-weekly            # Weekly synthesis
/om-vault-audit       # Check for issues
/om-review-brief      # Prep for review season
```

### Test Everything

```powershell
# 1. Start OpenCode
oc

# 2. In OpenCode, ask:
Tell me about DroidForensix and what's blocking us

# 3. It should know:
# - 277 samples, 1,711 C2 indicators
# - 63x speedup vs manual
# - Current blocker: validate "100% aggregator miss" claim
# - Next: LinkedIn article, then paper draft
# - Deadline: May 2027
```

If OpenCode knows all this without you explaining, setup is **working correctly**.

---

## Customization

### Change Your North Star

Edit `brain\North Star.md` in Obsidian. Changes auto-appear in next `oc` session.

### Add New Projects

Create new files in `work\active\`:

```markdown
---
title: My Project
status: In Progress
date: 2026-07-21
quarter: Q3 2026
---

# My Project

## Goal
What are you trying to achieve?

## Status
Current progress.

## Next Steps
- [ ] Task 1
- [ ] Task 2

## Related
[[DroidForensix]]
```

### Track Wins

Add to `perf\Brag Doc.md`:

```markdown
### Recent Win
- Did something important
- Achieved X metric
- **Evidence:** [[DroidForensix]]
```

---

## Troubleshooting

### "PowerShell cannot be loaded"

Run PowerShell **as Administrator**:
1. Right-click PowerShell → "Run as administrator"
2. Run setup script with full path:
```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\YourUsername\Documents\Setup-ObsidianVault.ps1"
```

### "Git not found"

Install Git for Windows:
1. Go to https://git-scm.com/download/win
2. Download and install (use defaults)
3. Restart PowerShell

### "Node not found"

Install Node.js 22+:
1. Go to https://nodejs.org/
2. Download LTS version
3. Install (use defaults)
4. Restart PowerShell

### "Vault not found"

Check the path:
```powershell
Test-Path "$env:USERPROFILE\Documents\my-forensics-vault"

# Should return True
# If False, check:
dir "$env:USERPROFILE\Documents" | grep forensics
```

### "Context not injecting"

Test context script directly:
```powershell
$env:OBSIDIAN_VAULT = "$env:USERPROFILE\Documents\my-forensics-vault"
node --experimental-strip-types Inject-Context.ts
```

Should output formatted markdown with your North Star, projects, tasks.

### "`oc` command not found"

Reload PowerShell profile:
```powershell
. $PROFILE
```

Or open a new PowerShell window.

---

## Next Steps

### 1. Use It Daily

**Morning:**
```powershell
oc
/om-standup
```

**During Day:**
Work on tasks. Take notes in vault.

**End of Day:**
```
/om-wrap-up
```

### 2. Add People & Meetings

Create meeting notes as you go:
```powershell
# Create in work\1-1\
work\1-1\Person Name 2026-07-21.md
```

### 3. Sync Across Devices

Push vault to GitHub:
```powershell
cd "$env:USERPROFILE\Documents\my-forensics-vault"
git remote add origin https://github.com/DarshakPatel2004/forensics-vault.git
git push -u origin main
```

Now pull on other devices:
```powershell
git clone https://github.com/DarshakPatel2004/forensics-vault.git
```

### 4. Advanced: QMD Semantic Search (Optional)

For smarter search:
```powershell
npm install -g @tobilu/qmd
cd "$env:USERPROFILE\Documents\my-forensics-vault"
node --experimental-strip-types scripts/qmd-bootstrap.ts
```

Query by meaning:
```powershell
qmd --index obsidian-mind query "what blocks our validation"
```

---

## Architecture

### How It Works

1. **You run:** `oc`

2. **PowerShell runs:**
   - `Inject-Context.ts` reads your vault
   - Extracts North Star, projects, tasks, git log
   - Formats as markdown

3. **Context injected into OpenCode system prompt**

4. **You ask:** `What's blocking DroidForensix?`

5. **OpenCode reads your vault context and knows:**
   - Current blocker
   - Related tasks
   - Deadline
   - Resources available

6. **No re-explaining needed.** Context carries over between sessions.

### Why This Works

- ✅ **Vault-first** — Everything in markdown files, git-tracked
- ✅ **No cloud** — All local, offline-capable
- ✅ **No API calls** — Context injection is deterministic
- ✅ **Works with any agent** — Claude Code, OpenCode, Cursor, etc.
- ✅ **Reproducible** — Same setup, same vault, same context

---

## Questions?

Refer to:
- `brain\North Star.md` — Your research goals
- `CLAUDE.md` — Operating manual for the vault
- `work\active\*.md` — Active projects

Or ask OpenCode directly:
```powershell
oc
How do I use this vault effectively?
```

---

## File Locations

Quick reference for Windows paths:

| Item | Location |
|------|----------|
| **Vault** | `C:\Users\YourUsername\Documents\my-forensics-vault` |
| **North Star** | `...\my-forensics-vault\brain\North Star.md` |
| **Projects** | `...\my-forensics-vault\work\active\` |
| **Competencies** | `...\my-forensics-vault\perf\competencies\` |
| **Wins** | `...\my-forensics-vault\perf\Brag Doc.md` |
| **Meetings** | `...\my-forensics-vault\work\1-1\` |
| **PowerShell Profile** | `$PROFILE` (usually `Documents\PowerShell\profile.ps1`) |

---

**You're all set!** 🎉 Start with `oc` and never re-explain your research again.
