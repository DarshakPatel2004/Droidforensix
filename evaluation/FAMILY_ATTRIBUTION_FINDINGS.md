# Family attribution: what the dev numbers were hiding (2026-11-24)

Dev split only (`evaluation/holdout_split_v1.csv`, 227 evaluated rows). The holdout was not read or scored.
Reproduce: `python evaluation/rerun_family_dev.py` (signature and knowledge-base layers; LLM, cache and
ground-truth override off).

## 1. About half the dev rows cannot be scored

108 of 227 rows have a catch-all vendor token as ground truth (`AndroidOS`, `GenericKD`, `Agent`, `Gen`,
`Banker`, ...; see `analysis/labels.py:is_catch_all`). No family name can match them, so the 35.5% headline
mixes unscoreable rows with real ones. The `abusech` source scores 1 of 85 mainly for this reason.
Quote family accuracy on the 119 **scoreable** rows, and say how many rows were excluded.

## 2. A recalibration regression, now fixed

Commit `77e39b9` (17 Nov) stopped counting "native:no" toward `min_matches` and left every threshold as
calibrated. Signatures with a real discriminator (a known C2, a distinctive string) lost their fourth
signal and stopped matching: `FakeInst` (C2 `depositmobi.com`), `Opfake`, `GinMaster` (string `soft_id`).
It aimed at one false positive, `PixRevolution`, whose permissions (`INTERNET`, `ACCESS_NETWORK_STATE`) are
on nearly every app. The later discriminator gate already blocks shape-only matches, so the change cost
recall without helping precision. A side effect: with `GinMaster` no longer matching, `PixRevolution`
named 8 `GinMaster` samples.

Fix (`backend/family_id.py`): count native-lib shape toward `min_matches` again, and make `PixRevolution`
`require_string`. Tests: `tests/test_family_shape_gate.py`.

## 3. Result on the 119 scoreable dev rows (no LLM layer in the current rows)

| | correct | wrong name | abstain | precision when naming | coverage |
|---|---:|---:|---:|---:|---:|
| 18 Oct baseline (with LLM) | 75 | 30 | 14 | 0.714 | 0.882 |
| Current code before the fix | 48 | 22 | 49 | 0.686 | 0.588 |
| Current code after the fix | 72 | 14 | 33 | 0.837 | 0.723 |

Rows where the system names a specific family although ground truth is a catch-all token: 87 (baseline),
47 (now). Whether those names are right is unknowable from this ground truth.

## 4. What this does not show

- **No LLM layer** in the "current" rows. In production the LLM fills some abstentions; coverage there is higher.
- **Dev only.** The fix was designed from dev rows. A holdout look is needed before claiming it generalises.
  `HOLDOUT_SPLIT.md` makes that a declared milestone, aggregate-only.
- **Knowledge-base rows are in-sample** (mined from the same ground truth); see `lamda_fetch/CAVEATS.md`.
  The open-set check (`score_kb.py`) needs `eval_features.json`, which is not tracked, so it was not re-run.
- `pendrive` (packed samples) still scores 0 of 12; that is a packer-recovery limit, not a matcher one.

## 5. Next

1. Declare a holdout milestone and score it once, aggregate-only.
2. Audit signatures whose permissions are all ubiquitous or whose `min_matches` is 2 with no `require_*`.
3. Fix the ground truth: replace catch-all tokens with a real family where VirusTotal consensus allows it.
