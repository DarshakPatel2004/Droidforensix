#!/usr/bin/env python3
"""A/B: old dropper_shape_signals (pre-fix) vs the logic as-run, over the
same rows as the matrix run. Evidence for FULL_KNOWLEDGE_TRANSFER section 15:
the FCM action-scan + parse-guard fixes must add evidence, not change verdicts.

Usage:
    .venv/Scripts/python.exe scripts/triage_matrix.py   # prerequisite
    .venv/Scripts/python.exe scripts/ab_fcm_fix.py

Old = no parse guard + FCM from component names (get_receivers/get_services).
New = package-empty guard + FCM from intent-filter <action> scan (triage.py).

Writes analysis/ac4/ab_fcm_fix.json (gitignored): signal-level and
verdict-level differences. Expectation: verdict differences == 0.
"""

import json
import logging
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

logging.disable(logging.CRITICAL)
from loguru import logger
logger.remove()  # loguru bypasses logging.disable

from androguard.core.apk import APK

from scripts.triage import escalate_indeterminate

MATRIX = REPO / "analysis" / "ac4" / "triage_matrix.json"
OUT = REPO / "analysis" / "ac4" / "ab_fcm_fix.json"


def old_signals(path):
    """Pre-fix dropper_shape_signals, verbatim logic."""
    signals = []
    try:
        a = APK(str(path))
        if not a.get_main_activity():
            signals.append("no_launcher_activity")
        filt = " ".join(a.get_receivers()) + " " + " ".join(a.get_services())
        if "MESSAGING_EVENT" in filt or "c2dm.intent.RECEIVE" in filt:
            signals.append("fcm_receiver")
        perms = " ".join(a.get_permissions())
        if "REQUEST_INSTALL_PACKAGES" in perms:
            signals.append("self_install")
        if "INSTALL_SHORTCUT" in perms and "READ_PHONE_STATE" in perms:
            signals.append("shortcut_sms_combo")
    except Exception as e:
        return ["manifest_parse_error:" + str(e)[:60]]
    return signals


def base_verdict(verdict):
    """Strip escalation + allowlist suffixes to recover build_verdict's output
    (old pipeline order: build_verdict -> escalate -> append allowlist)."""
    v = verdict
    if v.endswith("(allowlisted-benign)"):
        v = v[: -len("(allowlisted-benign)")]
    if v.startswith("indeterminate(suspect:dropper-shape)"):
        v = "indeterminate"
    return v


def main():
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    rows = matrix["rows"]
    stats = {"fcm_new_only": 0, "fcm_old_only": 0, "fcm_same": 0,
             "guard_changed": 0, "verdict_changed": 0}
    verdict_diffs, fcm_diffs, guard_diffs = [], [], []

    for i, row in enumerate(rows, 1):
        path = REPO / row["path"] if not pathlib.Path(row["path"]).is_absolute() \
            else pathlib.Path(row["path"])
        old = old_signals(path)
        new = row["suspect_reasons"]

        old_fcm = "fcm_receiver" in old
        new_fcm = "fcm_receiver" in new
        if new_fcm and not old_fcm:
            stats["fcm_new_only"] += 1
            fcm_diffs.append((row["verdict"], row["path"]))
        elif old_fcm and not new_fcm:
            stats["fcm_old_only"] += 1
            fcm_diffs.append((row["verdict"], row["path"]))
        else:
            stats["fcm_same"] += 1

        old_parse_err = any(s.startswith("manifest_parse_error") for s in old)
        new_parse_err = any(s.startswith("manifest_parse_error") for s in new)
        if old_parse_err != new_parse_err or (
                old_parse_err and new_parse_err and old != new):
            stats["guard_changed"] += 1
            guard_diffs.append((row["verdict"], old, new))

        base = base_verdict(row["verdict"])
        conf = row["confidence"]
        old_verdict, _ = escalate_indeterminate(base, conf, old)
        if "(allowlisted-benign)" in row["verdict"]:
            old_verdict += "(allowlisted-benign)"
        if old_verdict != row["verdict"]:
            stats["verdict_changed"] += 1
            verdict_diffs.append({
                "path": row["path"],
                "class": row["verdict_class"],
                "old": old_verdict,
                "new": row["verdict"],
                "old_signals": old,
                "new_signals": new,
            })
        print("[%d/%d] %s" % (i, len(rows),
                              row["path"].encode("ascii", "replace").decode("ascii")))

    print("\n=== A/B RESULT (old component-name FCM vs new action-scan) ===")
    print("fcm_receiver: same=%d  new-only=%d  old-only=%d"
          % (stats["fcm_same"], stats["fcm_new_only"], stats["fcm_old_only"]))
    print("parse-guard differences: %d" % stats["guard_changed"])
    print("verdict differences:     %d" % stats["verdict_changed"])
    for v in verdict_diffs:
        print("  %-10s %s\n     old=%s %s\n     new=%s %s"
              % (v["class"], v["path"], v["old"], v["old_signals"],
                 v["new"], v["new_signals"]))
    OUT.write_text(json.dumps({"stats": stats,
                               "verdict_diffs": verdict_diffs,
                               "fcm_diffs": fcm_diffs,
                               "guard_diffs": guard_diffs}, indent=2))
    print("json -> %s" % OUT)


if __name__ == "__main__":
    main()
