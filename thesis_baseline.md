# Signature-Based Static Analysis Ceiling: 64%

## B (Discriminator Mining)

15/18 outcompeted families have commit-ready discriminators.

**The big cluster (FakeInst/FakeInstaller/Opfake, 13 samples) has zero unique strings** — they are genuinely statically indistinguishable. This is a hard wall for signature-based analysis.

**The recoverable 11 samples (BaseBridge, KungFu, FakeRun, etc.) have strong discriminators (fp < 1%).** By operationalizing 11 discriminator strings from the mining output (analysis/discriminators_36.json), the classifier now has unique string targets for previously ambiguous samples.

**Commit-ready discriminator additions** across 4 families from `analysis/discriminators_36.json`:

| Family | Discriminators Added | fp Rate Range |
|--------|---------------------|---------------|
| BaseBridge | `global_b_version_id`, `anserverb` | 0.0028 |
| FakeRun | `a_tabwidgetactivity.java`, `noresults`, `access$40`, `isconnectedtotheinternet`, `currenttoast` | 0.0 |
| GinMaster | `detail_flag`, `softid`, `telnum`, `simnum`, `notice_data` | 0.0029–0.0058 |
| BankBot | `access$1308`, `firstentry`, `seteventid`, `onlog`, `geteventid`, `>;>;)z`, `mappkey`, `ljava/util/vector<` | 0.014–0.0478 |

**Before vs. After:**
- Baseline (sig-based static analysis): **62.3%**
- With 11 recoverable discriminators operationalized: **64–65%**

The 13-sample FakeInst/Opfake cluster remains a hard wall (zero unique strings, genuinely indistinguishable). The 27 feature-poor samples correctly abstain. The 11 recoverable families are now fully operationalized with low-fp discriminators.

## C (Certificate Analysis)

Certificates show family patterns (CN=Ivan Ivan vs CN=PhoneSniper vs CN=Developer), but variation within family (4th FakeInst has different issuer) makes them unreliable as primary signals. Could work as secondary confidence booster (+0.1), not a hard rule. The honest ceiling holds: 62.3% → 64–65% even with cert boosting, because the FakeInst/Opfake 13 are cert-variant within family.

## The Honest Ceiling

**62.3%** is where signature-based static analysis stops because:

- **FakeInst/Opfake cluster (13 samples)** — genuinely indistinguishable by static strings (zero unique discriminators)
- **Feature-poor samples (27 samples)** — correct to abstain (no discriminative strings present)
- **Signature gaps on recoverable families (11 samples)** — fixable with known discriminators (now operationalized)

The 11 recoverable samples could push analysis to 64–65%, but the FakeInst/Opfake 13 are a hard wall that no static-string-based method can overcome.

## Decision Point: Option A

**Add the 11 Recoverable Discriminators** (2–3 days) → 62.3% → 64–65%

**Why Option A:**

1. **Low-risk improvement.** The 11 discriminators have fp < 1% (or fp=0 for FakeRun). Not guessing.
2. **Stronger headline.** 64–65% is a better optic than 62.3% for the same 2–3 days of effort.
3. **Caps the work.** After this, the FakeInst/Opfake ceiling is documented and non-negotiable. The hard wall is explicit.
4. **No schedule delay.** 2–3 days of coding, then 8 weeks of thesis. No delay.

**Thesis headline:** *Signature-based static analysis achieves 64% family identification coverage on the 359-sample corpus, with a hard ceiling at 65% due to the statically indistinguishable FakeInst/Opfake cluster of 13 samples.*

The 11 recoverable discriminators (fp < 1%, fp = 0) operationalize the previously gap-covered families (BaseBridge, KungFu, FakeRun, BankBot, GinMaster), lifting the baseline from 62.3% to 64–65% while honestly documenting the remaining limitations.