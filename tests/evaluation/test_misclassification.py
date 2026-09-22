"""Unit tests for misclassification_analysis bucket classification."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

from evaluation.misclassification_analysis import family_root_causes


def _gt(family: str, source: str = "abusech") -> dict:
    return {"sha256": f"{source}-{family}", "family": family, "source": source}


def _pred(sha: str, family: str) -> dict:
    return {"sha256": sha, "prediction": family}


def test_catchall_gt_is_unresolvable():
    gt = [_gt("AndroidOS"), _gt("GenericKD"), _gt("GinMaster")]
    preds = [
        _pred("abusech-AndroidOS", "GinMaster"),
        _pred("abusech-GenericKD", "unknown"),
        _pred("abusech-GinMaster", "GinMaster"),
    ]
    report = family_root_causes(gt, preds)
    assert report["label_unresolvable"]["count"] == 2
    assert report["label_unresolvable"]["by_source"] == {"abusech": 2}
    assert "wrong_family" not in report


def test_specific_gt_wrong_family_bucketed():
    gt = [_gt("GinMaster"), _gt("Hqwar")]
    preds = [_pred("abusech-GinMaster", "Opfake"), _pred("abusech-Hqwar", "Ermac")]
    report = family_root_causes(gt, preds)
    assert report["wrong_family"]["count"] == 2


def test_specific_gt_under_matched_when_pred_generic():
    gt = [_gt("BankBot")]
    preds = [_pred("abusech-BankBot", "AndroidOS")]
    report = family_root_causes(gt, preds)
    assert report["under_matched"]["count"] == 1


def test_correct_preds_excluded():
    gt = [_gt("GinMaster")]
    preds = [_pred("abusech-GinMaster", "ginmaster")]
    report = family_root_causes(gt, preds)
    assert sum(v["count"] for v in report.values()) == 0
