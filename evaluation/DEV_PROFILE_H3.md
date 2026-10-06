# Dev Profile-Coverage Audit H3

Status: **audit complete; no profile change accepted** (24-Sep-2026).

## Aggregate result

Using the canonical dev membership and `is_catch_all()` definition:

- Scorable dev rows: **136**.
- Rows with an exact `FamilyConfidenceScorer` profile: **115**.
- Profile-gap rows: **21** across **15** family labels.
- Profile gaps by source: **13 pendrive**, 4 modern_eval, 3 androzoo_drebin,
  1 abusech.

Largest gap:

- `FraudDropper`: **7 rows**, all from pendrive.

The remaining gap labels are singleton or very small families, including
`Airpush`, `Nisev`, `FakeApp`, `CraxsRAT`, `Andr/Xgen2-AYJ`,
`Andr/NGate-G`, `Mirax`, `UKP`, and six pendrive families.

## Decision

Do not mine and evaluate a new profile on these same rows. The largest group
has only seven samples, all from one manually labeled source, and the other
groups are singletons. That would be an in-sample profile experiment with a
high overfit risk.

H1 remains the only accepted family milestone, and it is evaluator-only. H2's
production unknown-fallback integration was rejected with zero newly answered
rows. The next safe family step requires either:

1. a separately predeclared discovery/validation split inside a larger,
   independently labeled profile corpus; or
2. new source-documented family samples.

The 113-row holdout remains sealed. No signatures, profiles, knowledge-base
thresholds, or production defaults were changed by this audit.
