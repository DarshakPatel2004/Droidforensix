"""Parse AndroidManifest.xml files from validation_359 samples and analyze intent actions."""
import os
import json
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
import csv

BASE = r"D:\DroidForensix"
VAL_DIR = os.path.join(BASE, "evaluation", "validation_359")
GT_CSV = os.path.join(BASE, "ground_truth_all.csv")
CACHE_JSON = os.path.join(BASE, "analysis", "gap_features_cache.json")

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def load_ground_truth():
    """Return dict: sha256 -> family."""
    gt = {}
    with open(GT_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sha = row["sha256"]
            family = row["family"]
            prefix = sha[:8]  # use first 8 chars as key for readability
            gt[prefix] = {"sha256": sha, "family": family}
    return gt


def parse_manifest(manifest_path):
    """Parse an AndroidManifest.xml and extract receivers, services, intent actions."""
    result = {"receivers": [], "services": [], "intent_actions": []}
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as e:
        result["parse_error"] = str(e)
        return result

    # Walk all elements
    for elem in root.iter():
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

        if tag == "receiver":
            name = elem.get(f"{{{ANDROID_NS}}}name", "")
            # Short name = after last dot
            short_name = name.rsplit(".", 1)[-1] if "." in name else name
            result["receivers"].append({"full": name, "short": short_name})

            # Get intent-filters under this receiver
            for child in elem:
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag == "intent-filter":
                    for action in child.iter():
                        a_tag = action.tag.split("}")[-1] if "}" in action.tag else action.tag
                        if a_tag == "action":
                            action_name = action.get(f"{{{ANDROID_NS}}}name", "")
                            if action_name:
                                result["intent_actions"].append(action_name)

        elif tag == "service":
            name = elem.get(f"{{{ANDROID_NS}}}name", "")
            short_name = name.rsplit(".", 1)[-1] if "." in name else name
            result["services"].append({"full": name, "short": short_name})

            for child in elem:
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag == "intent-filter":
                    for action in child.iter():
                        a_tag = action.tag.split("}")[-1] if "}" in action.tag else action.tag
                        if a_tag == "action":
                            action_name = action.get(f"{{{ANDROID_NS}}}name", "")
                            if action_name:
                                result["intent_actions"].append(action_name)

    # Deduplicate
    result["intent_actions"] = sorted(set(result["intent_actions"]))
    result["receivers"] = [r["short"] for r in result["receivers"]]
    result["services"] = [s["short"] for s in result["services"]]
    return result


def check_gap_cache():
    """Check which intent action strings appear in gap_features_cache.json strings."""
    intent_keywords = [
        "BOOT_COMPLETED",
        "SMS_RECEIVED",
        "PACKAGE_ADDED",
        "PACKAGE_REMOVED",
        "CONNECTIVITY_CHANGE",
        "USER_PRESENT",
        "SCREEN_ON",
        "SCREEN_OFF",
        "BATTERY_LOW",
        "SHUTDOWN",
        "NEW_OUTGOING_CALL",
        "SIM_STATE_CHANGED",
        "ACTION_BOOT_COMPLETED",
        "android.intent.action.BOOT_COMPLETED",
        "android.provider.Telephony.SMS_RECEIVED",
        "android.intent.action.PACKAGE_ADDED",
        "android.intent.action.PACKAGE_REMOVED",
        "android.net.conn.CONNECTIVITY_CHANGE",
        "android.intent.action.USER_PRESENT",
        "android.intent.action.NEW_OUTGOING_CALL",
        "android.intent.action.SIM_STATE_CHANGED",
        "android.intent.action.ACTION_SHUTDOWN",
    ]

    with open(CACHE_JSON, "r", encoding="utf-8") as f:
        cache = json.load(f)

    print(f"\nTotal samples in gap_features_cache.json: {len(cache)}")

    # Count how many samples have each keyword in their strings
    keyword_counts = Counter()
    samples_with_any = set()

    for sha, data in cache.items():
        strings = data.get("strings", [])
        strings_text = "\n".join(str(s) for s in strings)
        for kw in intent_keywords:
            if kw in strings_text:
                keyword_counts[kw] += 1
                samples_with_any.add(sha)

    print(f"\n=== Intent Action Strings in gap_features_cache.json ===")
    print(f"Samples with at least one intent action string: {len(samples_with_any)} / {len(cache)}")
    print()
    for kw, count in keyword_counts.most_common():
        print(f"  {kw}: {count} samples")

    return keyword_counts, samples_with_any


def main():
    print("=" * 80)
    print("ANDROID MANIFEST ANALYSIS - validation_359")
    print("=" * 80)

    # Load ground truth
    gt = load_ground_truth()
    print(f"Loaded {len(gt)} samples from ground_truth_all.csv")

    # Family distribution
    family_counts = Counter(v["family"] for v in gt.values())
    print(f"Total unique families: {len(family_counts)}")

    # Find sample directories
    sample_dirs = [d for d in os.listdir(VAL_DIR) if os.path.isdir(os.path.join(VAL_DIR, d))]
    sample_dirs = [d for d in sample_dirs if len(d) == 64]  # sha256 dirs only
    print(f"Sample directories found: {len(sample_dirs)}")

    # Parse all manifests
    all_data = {}
    parse_errors = []
    family_manifests = defaultdict(lambda: {"receivers": [], "services": [], "intent_actions": []})

    for sha_dir in sorted(sample_dirs):
        manifest_path = os.path.join(VAL_DIR, sha_dir, "apktool", "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            continue

        prefix = sha_dir[:8]
        info = gt.get(prefix, {"sha256": sha_dir, "family": "UNKNOWN"})
        family = info["family"]

        parsed = parse_manifest(manifest_path)
        if "parse_error" in parsed:
            parse_errors.append((sha_dir, parsed["parse_error"]))

        all_data[prefix] = {
            "family": family,
            "receivers": parsed["receivers"],
            "services": parsed["services"],
            "intent_actions": parsed["intent_actions"],
        }

        # Aggregate by family
        family_manifests[family]["receivers"].extend(parsed["receivers"])
        family_manifests[family]["services"].extend(parsed["services"])
        family_manifests[family]["intent_actions"].extend(parsed["intent_actions"])

    print(f"\nSuccessfully parsed manifests: {len(all_data)}")
    if parse_errors:
        print(f"Parse errors: {len(parse_errors)}")
        for sha, err in parse_errors[:5]:
            print(f"  {sha[:16]}...: {err}")

    # === Per-family analysis ===
    print("\n" + "=" * 80)
    print("FAMILY-LEVEL MANIFEST ANALYSIS")
    print("=" * 80)

    # Sort families by count
    family_list = sorted(family_manifests.items(), key=lambda x: -len(set(x[0] + "_agg")))

    # Print families with their intent actions
    for family, data in sorted(family_manifests.items(), key=lambda x: family_counts.get(x[0], 0), reverse=True):
        count = family_counts.get(family, 0)
        unique_receivers = sorted(set(data["receivers"]))
        unique_services = sorted(set(data["services"]))
        unique_actions = sorted(set(data["intent_actions"]))

        print(f"\n{'-' * 60}")
        print(f"FAMILY: {family} ({count} samples in GT)")
        print(f"  Receivers ({len(unique_receivers)} unique): {', '.join(unique_receivers[:15])}{'...' if len(unique_receivers) > 15 else ''}")
        print(f"  Services  ({len(unique_services)} unique): {', '.join(unique_services[:15])}{'...' if len(unique_services) > 15 else ''}")
        print(f"  Actions   ({len(unique_actions)} unique): {', '.join(unique_actions[:20])}{'...' if len(unique_actions) > 20 else ''}")

    # === Global intent action frequency ===
    print("\n" + "=" * 80)
    print("GLOBAL INTENT ACTION FREQUENCY (across all samples)")
    print("=" * 80)

    all_actions = []
    for d in all_data.values():
        all_actions.extend(d["intent_actions"])

    action_counts = Counter(all_actions)
    for action, count in action_counts.most_common(30):
        pct = count / len(all_data) * 100
        print(f"  {action}: {count} ({pct:.1f}%)")

    # === Check gap_features_cache.json ===
    print("\n" + "=" * 80)
    print("GAP FEATURES CACHE - INTENT ACTION STRING SEARCH")
    print("=" * 80)
    check_gap_cache()

    # === Save raw data ===
    output_path = os.path.join(BASE, "analysis", "manifest_component_data.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=2, ensure_ascii=False)
    print(f"\nRaw data saved to: {output_path}")

    # Save family summary
    family_summary = {}
    for family, data in family_manifests.items():
        family_summary[family] = {
            "count": family_counts.get(family, 0),
            "unique_receivers": sorted(set(data["receivers"])),
            "unique_services": sorted(set(data["services"])),
            "unique_intent_actions": sorted(set(data["intent_actions"])),
        }
    summary_path = os.path.join(BASE, "analysis", "family_manifest_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(family_summary, f, indent=2, ensure_ascii=False)
    print(f"Family summary saved to: {summary_path}")


if __name__ == "__main__":
    main()
