#!/usr/bin/env python3
"""
Extract manifest features from DEX strings and available apktool manifests.

Produces analysis/manifest_cache.json with per-sample:
  - intent_actions: list of intent action strings found in DEX
  - component_names: list of receiver/service class names (from manifests where available)
"""
import json
import os
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

GROUND_TRUTH = Path("D:/DroidForensix/ground_truth_all.csv")
GAP_CACHE = Path("D:/DroidForensix/analysis/gap_features_cache.json")
VALIDATION_DIR = Path("D:/DroidForensix/evaluation/validation_359")
OUTPUT = Path("D:/DroidForensix/analysis/manifest_cache.json")

NS = "{http://schemas.android.com/apk/res/android}"

# Intent action substrings that appear in DEX strings
INTENT_ACTION_PATTERNS = [
    "BOOT_COMPLETED",
    "SMS_RECEIVED",
    "SMS_SENT",
    "SMS_DELIVER",
    "PACKAGE_ADDED",
    "PACKAGE_REMOVED",
    "PACKAGE_REPLACED",
    "USER_PRESENT",
    "SCREEN_ON",
    "SCREEN_OFF",
    "CONNECTIVITY_CHANGE",
    "SHUTDOWN",
    "BATTERY_LOW",
    "BATTERY_OKAY",
    "NEW_OUTGOING_CALL",
    "SIM_STATE_CHANGED",
    "MY_PACKAGE_REPLACED",
    "LOCKED_BOOT_COMPLETED",
    "QUICKBOOT_POWERON",
    "MMS_RECEIVED",
    "WAP_PUSH_RECEIVED",
    "DATA_SMS_RECEIVED",
    "PHONE_STATE",
    "ACTION_POWER_CONNECTED",
    "ACTION_POWER_DISCONNECTED",
    "TIMEZONE_CHANGED",
    "TIME_TICK",
    "LOCALE_CHANGED",
    "EXTERNAL_APPLICATIONS_AVAILABLE",
    "MEDIA_SCANNER_SCAN_FILE",
]

# Component name suffixes that indicate manifest-declared components
COMPONENT_SUFFIXES = re.compile(
    r"(Boot Receiver|SmsReceiver|SmsService|BootService|AlarmReceiver|"
    r"PushReceiver|PushService|DeviceAdminReceiver|AccessibilityService)$",
    re.IGNORECASE,
)


def extract_intent_actions_from_strings(strings: list) -> list[str]:
    """Extract intent action names from DEX string literals."""
    found = set()
    for s in strings:
        if not isinstance(s, str):
            continue
        for action in INTENT_ACTION_PATTERNS:
            if action in s:
                found.add(action)
    return sorted(found)


def extract_component_names_from_strings(strings: list) -> list[str]:
    """Extract app-specific component class names from DEX class references."""
    components = set()
    for s in strings:
        if not isinstance(s, str):
            continue
        # Match L.../ClassName; pattern (exclude framework classes)
        m = re.match(
            r"^L((?!android/|java/|javax/|kotlin/|kotlinx/|androidx/)[A-Za-z0-9_/$]+/)?"
            r"([A-Za-z0-9_$]+);$",
            s,
        )
        if m:
            name = m.group(2).split("$")[0]
            # Only keep if it looks like a manifest component (not every class)
            if len(name) > 5 and any(
                x in name.lower()
                for x in [
                    "receiver",
                    "service",
                    "broadcast",
                    "boot",
                    "sms",
                    "alarm",
                    "deviceadmin",
                    "pushservice",
                    "accessibility",
                ]
            ):
                # Exclude common false positives
                if name not in (
                    "BroadcastReceiver",
                    "ExecutorService",
                    "IntentService",
                    "JobIntentService",
                    "Service",
                    "ServiceConnection",
                    "ServiceManager",
                ):
                    components.add(name)
    return sorted(components)


def parse_manifest_components(manifest_path: str) -> dict:
    """Parse AndroidManifest.xml for receiver/service components and their intent actions."""
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except Exception:
        return {"receivers": [], "services": [], "intent_actions": []}

    receivers = []
    for el in root.iter("receiver"):
        name = el.get(f"{NS}name", "")
        exported = el.get(f"{NS}exported", "")
        actions = []
        for f in el.findall("intent-filter"):
            for a in f.findall("action"):
                act_name = a.get(f"{NS}name", "")
                if act_name:
                    actions.append(act_name)
        short_name = name.split(".")[-1] if name else ""
        receivers.append({"name": short_name, "full_name": name, "exported": exported, "actions": actions})

    services = []
    for el in root.iter("service"):
        name = el.get(f"{NS}name", "")
        exported = el.get(f"{NS}exported", "")
        short_name = name.split(".")[-1] if name else ""
        services.append({"name": short_name, "full_name": name, "exported": exported})

    # Collect all intent actions
    all_actions = set()
    for r in receivers:
        all_actions.update(r["actions"])

    return {
        "receivers": receivers,
        "services": services,
        "intent_actions": sorted(all_actions),
    }


def main():
    # Load ground truth
    import csv

    gt = {}
    with open(GROUND_TRUTH) as f:
        for row in csv.DictReader(f):
            gt[row["sha256"].lower()] = row["family"]

    # Load gap features cache
    with open(GAP_CACHE) as f:
        samples = json.load(f)

    print(f"Loaded {len(samples)} samples from gap cache, {len(gt)} ground truth entries")

    manifest_cache = {}
    stats = {"total": 0, "with_intent_actions": 0, "with_components": 0, "with_manifest": 0}

    for sha, entry in samples.items():
        stats["total"] += 1
        strings = entry.get("strings", []) or []

        # Extract from DEX strings
        intent_actions = extract_intent_actions_from_strings(strings)
        component_names = extract_component_names_from_strings(strings)

        # Try to parse manifest from apktool if available
        manifest_data = None
        for subdir in VALIDATION_DIR.iterdir():
            if subdir.is_dir() and sha.startswith(subdir.name[:16]):
                manifest_path = subdir / "apktool" / "AndroidManifest.xml"
                if manifest_path.exists():
                    manifest_data = parse_manifest_components(str(manifest_path))
                    break

        # Merge: prefer manifest data over DEX string extraction
        all_intent_actions = set(intent_actions)
        all_component_names = set(component_names)

        if manifest_data:
            all_intent_actions.update(manifest_data["intent_actions"])
            all_component_names.update(r["name"] for r in manifest_data["receivers"])
            all_component_names.update(s["name"] for s in manifest_data["services"])
            stats["with_manifest"] += 1

        entry_data = {
            "intent_actions": sorted(all_intent_actions),
            "component_names": sorted(all_component_names),
            "source": "manifest" if manifest_data else "dex_strings",
        }

        if entry_data["intent_actions"]:
            stats["with_intent_actions"] += 1
        if entry_data["component_names"]:
            stats["with_components"] += 1

        manifest_cache[sha] = entry_data

    # Save
    with open(OUTPUT, "w") as f:
        json.dump(manifest_cache, f, indent=1)

    print(f"\nSaved manifest cache: {len(manifest_cache)} samples")
    print(f"Stats: {stats}")

    # Profile by family
    family_profiles = defaultdict(lambda: {"intent_actions": defaultdict(int), "component_names": defaultdict(int), "count": 0})
    for sha, entry in manifest_cache.items():
        family = gt.get(sha, "Unknown")
        family_profiles[family]["count"] += 1
        for action in entry["intent_actions"]:
            family_profiles[family]["intent_actions"][action] += 1
        for comp in entry["component_names"]:
            family_profiles[family]["component_names"][comp] += 1

    # Find discriminating intent actions for FP families
    fp_families = ["FakeInst", "Opfake", "Plankton", "NGate", "GinMaster", "BaseBridge", "Kmin", "BankBot", "SendPay", "SpyMax", "Jiagu"]
    print("\n=== FP FAMILY INTENT ACTION PROFILES ===")
    for family in sorted(fp_families):
        profile = family_profiles.get(family)
        if not profile:
            continue
        count = profile["count"]
        actions = dict(sorted(profile["intent_actions"].items(), key=lambda x: -x[1]))
        comps = dict(sorted(profile["component_names"].items(), key=lambda x: -x[1])[:5])
        print(f"\n{family} ({count} samples):")
        print(f"  Actions: {actions}")
        print(f"  Components: {comps}")


if __name__ == "__main__":
    main()
