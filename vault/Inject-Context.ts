#!/usr/bin/env node --experimental-strip-types

/**
 * Inject Obsidian vault context into OpenCode system prompt (Windows)
 * Usage: node --experimental-strip-types Inject-Context.ts
 * Environment: OBSIDIAN_VAULT (defaults to %USERPROFILE%\Documents\my-forensics-vault)
 */

import fs from "fs";
import path from "path";
import { execSync, spawnSync } from "child_process";
import os from "os";

function getVaultPath(): string {
  if (process.env.OBSIDIAN_VAULT) {
    return process.env.OBSIDIAN_VAULT;
  }

  const homeDir = os.homedir();
  const defaultPath = path.join(homeDir, "Documents", "my-forensics-vault");
  return defaultPath;
}

function readFile(filePath: string): string {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (err) {
    return "";
  }
}

function getActiveProjects(vaultPath: string): string[] {
  try {
    const activeDir = path.join(vaultPath, "work", "active");
    if (!fs.existsSync(activeDir)) return [];

    return fs
      .readdirSync(activeDir)
      .filter((f) => f.endsWith(".md"))
      .map((f) => f.replace(".md", ""));
  } catch {
    return [];
  }
}

function getRecentGit(vaultPath: string): string {
  try {
    // Windows-compatible git log command
    const result = spawnSync("git", ["log", "--oneline", "-5"], {
      cwd: vaultPath,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    if (result.status === 0 && result.stdout) {
      return result.stdout.trim();
    } else {
      return "No git history available";
    }
  } catch {
    return "Git not available";
  }
}

function getTasks(vaultPath: string): string[] {
  try {
    const activeDir = path.join(vaultPath, "work", "active");
    const tasks: string[] = [];

    if (fs.existsSync(activeDir)) {
      const files = fs
        .readdirSync(activeDir)
        .filter((f) => f.endsWith(".md"));

      for (const file of files.slice(0, 3)) {
        const content = readFile(path.join(activeDir, file));
        const taskMatches = content.match(/\- \[ \] (.+)/g) || [];
        tasks.push(
          ...taskMatches.slice(0, 3).map((t) => t.replace(/\- \[ \] /, ""))
        );
      }
    }

    return tasks.slice(0, 5);
  } catch {
    return [];
  }
}

function generateContext(): string {
  const vaultPath = getVaultPath();

  if (!fs.existsSync(vaultPath)) {
    console.error(`Vault not found at ${vaultPath}`);
    console.error(
      "Set OBSIDIAN_VAULT environment variable or run Setup-ObsidianVault.ps1 first"
    );
    process.exit(1);
  }

  const northStar = readFile(path.join(vaultPath, "brain", "North Star.md"));
  const activeProjects = getActiveProjects(vaultPath);
  const recentGit = getRecentGit(vaultPath);
  const tasks = getTasks(vaultPath);

  // Limit North Star to first 40 lines to keep token count reasonable
  const northStarExcerpt = northStar.split("\n").slice(0, 40).join("\n");

  // Format context
  const context = `
## 🧠 Your Research Brain

${northStarExcerpt}

## 📋 Active Projects
${activeProjects.length > 0 ? activeProjects.map((p) => `- ${p}`).join("\n") : "- None"}

## 🎯 Current Tasks
${tasks.length > 0 ? tasks.map((t) => `- [ ] ${t}`).join("\n") : "- None"}

## 📊 Recent Git Changes
\`\`\`
${recentGit}
\`\`\`

---

**Remember:** You're helping with DroidForensix research.
- Focus: Validation and publication at Virus Bulletin / DFRWS / ACSAC
- Deadline: May 2027 thesis submission
- Keep context in your vault (work/ for projects, brain/ for principles)
- Validate all claims against final_summary.json
- Prefer local inference (Mistral 7B via Ollama)
- Environment: Windows (Lenovo LOQ 15, RTX 4050)
`;

  return context;
}

// Main
try {
  const context = generateContext();
  console.log(context);
} catch (err) {
  console.error("Error generating context:", (err as Error).message);
  process.exit(1);
}
