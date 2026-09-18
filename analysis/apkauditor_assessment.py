"""C-track: selective APK feature extraction for 10 problem samples.

Extracts the 4 apkauditor-equivalent features that may discriminate families:
  1. Exported components (receivers/services) + their intent actions
  2. Certificate issuer/subject (self-signed patterns)
  3. Native lib names (specific .so filenames)
  4. Broadcast receiver intent actions (BOOT_COMPLETED, SMS_RECEIVED etc.)

Focuses on the 33 outcompeted samples: 3 FakeInst, 3 Opfake, 2 DroidKungFu-beaten
(KungFu), 2 random baseline (correct matches).

Outputs analysis/apkauditor_assessment.json with per-sample features and a
family-discriminator assessment section.

Run: python analysis/apkauditor_assessment.py
"""

import csv
import json
import logging
import sys
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

# Suppress androguard debug spam
logging.disable(logging.DEBUG)
logging.getLogger("androguard").setLevel(logging.ERROR)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from androguard.misc import AnalyzeAPK

RESULTS_PATH = ROOT / "analysis" / "test_draft_signatures_results.json"
GT_PATH      = ROOT / "ground_truth_all.csv"
OUT_PATH     = ROOT / "analysis" / "apkauditor_assessment.json"

NS = "http://schemas.android.com/apk/res/android"


def pick_samples(gt: dict[str, str], results: dict) -> list[dict]:
    """Pick 10 targeted samples: 3 FakeInst, 3 Opfake, 2 KungFu, 2 baseline."""
    diag = results["diagnosis_misses"]
    outcomp = [d for d in diag if d["category"] == "outcompeted"]

    fakeInst_shas = [d["sha256"] for d in outcomp if d["gt_family"] == "FakeInst"][:3]
    opfake_shas   = [d["sha256"] for d in outcomp if d["gt_family"] == "Opfake"][:3]
    kungfu_shas   = [d["sha256"] for d in outcomp if d["gt_family"] == "KungFu"][:2]

    # 2 correct baseline: one FakeInst correct, one Opfake correct
    correct = [s["sha256"] for s in results["samples"] if s["status"] == "correct"]
    baseline_fi   = next((s for s in correct if gt.get(s) == "FakeInst"), None)
    baseline_op   = next((s for s in correct if gt.get(s) == "Opfake"), None)
    baseline_shas = [s for s in [baseline_fi, baseline_op] if s][:2]

    chosen = []
    for sha in fakeInst_shas:
        chosen.append({"sha": sha, "role": "outcompeted", "gt": "FakeInst"})
    for sha in opfake_shas:
        chosen.append({"sha": sha, "role": "outcompeted", "gt": "Opfake"})
    for sha in kungfu_shas:
        chosen.append({"sha": sha, "role": "outcompeted", "gt": "KungFu"})
    for sha in baseline_shas:
        chosen.append({"sha": sha, "role": "baseline_correct", "gt": gt.get(sha, "?")})
    return chosen


def extract_manifest_features(apk_path: str) -> dict[str, Any]:
    """Parse AndroidManifest for exported components + intent actions."""
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        manifest_bytes = a.get_android_manifest_xml()
        root = ET.fromstring(manifest_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"error": str(exc)}

    receivers, services = [], []
    for el in root.iter("receiver"):
        name  = el.get(f"{{{NS}}}name", "")
        exp   = el.get(f"{{{NS}}}exported", "")
        acts  = [i.get(f"{{{NS}}}name", "") for f in el.findall("intent-filter") for i in f.findall("action")]
        receivers.append({"name": name.split(".")[-1], "exported": exp, "actions": acts})
    for el in root.iter("service"):
        name  = el.get(f"{{{NS}}}name", "")
        exp   = el.get(f"{{{NS}}}exported", "")
        acts  = [i.get(f"{{{NS}}}name", "") for f in el.findall("intent-filter") for i in f.findall("action")]
        services.append({"name": name.split(".")[-1], "exported": exp, "actions": acts})

    all_actions = sorted({a for comp in receivers + services for a in comp["actions"] if a})
    return {
        "receivers": receivers,
        "services":  services,
        "all_intent_actions": all_actions,
        "exported_receivers": [r for r in receivers if r["exported"] != "false"],
    }


def extract_cert_features(apk_path: str) -> dict[str, Any]:
    """Extract signing certificate subject/issuer."""
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        certs = a.get_certificates()
        if not certs:
            return {"certs": []}
        out = []
        for cert in certs:
            out.append({
                "issuer":  cert.issuer.human_friendly,
                "subject": cert.subject.human_friendly,
                "self_signed": cert.issuer.human_friendly == cert.subject.human_friendly,
            })
        return {"certs": out}
    except Exception as exc:
        return {"error": str(exc)}


def extract_native_libs(apk_path: str) -> list[str]:
    """Return distinct .so filenames from the APK zip."""
    try:
        with zipfile.ZipFile(apk_path) as z:
            return sorted({e.split("/")[-1] for e in z.namelist() if e.endswith(".so")})
    except Exception:
        return []


def assess_discriminators(samples: list[dict]) -> dict[str, Any]:
    """Compare features across families — surface family-specific patterns."""
    by_family: dict = {}
    for s in samples:
        fam = s["gt_family"]
        if fam not in by_family:
            by_family[fam] = {"all_actions": [], "cert_issuers": [], "native_libs": [], "receiver_names": []}
        if "error" not in s.get("manifest", {}):
            by_family[fam]["all_actions"].extend(s["manifest"].get("all_intent_actions", []))
            by_family[fam]["receiver_names"].extend(
                r["name"] for r in s["manifest"].get("receivers", [])
            )
        if "error" not in s.get("cert", {}):
            for c in s["cert"].get("certs", []):
                by_family[fam]["cert_issuers"].append(c["issuer"])
        by_family[fam]["native_libs"].extend(s.get("native_libs", []))

    notes = []
    # FakeInst vs Opfake intent action overlap
    fi_actions = set(by_family.get("FakeInst", {}).get("all_actions", []))
    op_actions = set(by_family.get("Opfake", {}).get("all_actions", []))
    shared = fi_actions & op_actions
    fi_only = fi_actions - op_actions
    op_only = op_actions - fi_actions
    notes.append({
        "comparison": "FakeInst vs Opfake intent actions",
        "FakeInst_only": sorted(fi_only),
        "Opfake_only":   sorted(op_only),
        "shared":        sorted(shared),
        "verdict": "DISCRIMINATING" if (fi_only or op_only) else "NO-DISCRIMINATOR",
    })

    # Cert self-signed patterns per family
    for fam, data in by_family.items():
        issuers = data["cert_issuers"]
        if issuers:
            notes.append({
                "comparison": f"{fam} cert issuers",
                "issuers": issuers,
            })

    # Native lib names per family
    for fam, data in by_family.items():
        libs = sorted(set(data["native_libs"]))
        if libs:
            notes.append({"comparison": f"{fam} native libs", "libs": libs})

    return {"per_family": {k: {kk: sorted(set(vv)) for kk, vv in v.items()} for k, v in by_family.items()}, "notes": notes}


def main() -> None:
    results = json.load(open(RESULTS_PATH, encoding="utf-8"))
    gt_rows = list(csv.DictReader(open(GT_PATH, encoding="utf-8")))
    gt = {r["sha256"].lower(): r["family"] for r in gt_rows}
    apk_path_map = {r["sha256"].lower(): r["apk_path"] for r in gt_rows}

    samples_meta = pick_samples(gt, results)
    print(f"Assessing {len(samples_meta)} samples...")

    processed = []
    for meta in samples_meta:
        sha = meta["sha"]
        apk = apk_path_map.get(sha, "")
        print(f"  {meta['gt']:<14} {sha[:16]}  {apk[-35:]}")
        if not apk or not Path(apk).exists():
            processed.append({**meta, "error": f"APK not found: {apk}"})
            continue
        manifest = extract_manifest_features(apk)
        cert     = extract_cert_features(apk)
        libs     = extract_native_libs(apk)
        processed.append({
            **meta,
            "gt_family": meta["gt"],
            "manifest":    manifest,
            "cert":        cert,
            "native_libs": libs,
        })

    assessment = assess_discriminators(processed)

    output = {
        "samples": processed,
        "discriminator_assessment": assessment,
        "conclusion": {
            "would_apkauditor_help_36": None,  # filled after reviewing notes
            "recommendation": "See discriminator_assessment.notes for family-specific patterns",
        },
    }

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("\n=== DISCRIMINATOR ASSESSMENT ===")
    for note in assessment["notes"]:
        print(f"\n  {note['comparison']}")
        for k, v in note.items():
            if k != "comparison" and v:
                print(f"    {k}: {v}")

    print(f"\nWritten to {OUT_PATH}")


if __name__ == "__main__":
    main()
