# Dev Tuning Milestone H2 — Production-Path Confidence Fusion

Status: **rejected after dev evaluation; no production code landed** (24-Sep-2026).

## Hypothesis

The H1 scorer calibration can safely fill production `unknown` outcomes
without replacing concrete signature, certificate, knowledge-base, or LLM
family decisions.

Enable the post-processing only when:

```text
FAMILY_CONFIDENCE_FUSION=1
```

The fixed bar is `0.60`. No other bar is tested in H2.

## Frozen policy

- Apply fusion only when the existing family outcome is `unknown`, `none`, or
  empty.
- Never override a concrete existing family outcome.
- If the scorer abstains, preserve the existing outcome unchanged.
- Keep the current default (`FAMILY_CONFIDENCE_FUSION` absent or `0`) unchanged.
- Do not change signatures, profiles, knowledge-base thresholds, or LLM prompts.

## Dev protocol

Use only the 136 canonical scorable rows in the `dev` side of
`evaluation/holdout_split_v1.csv`. Apply the post-processing to the completed
`evaluation/validation_359/` pipeline results, comparing the stored production
outcome with the fused outcome. Do not inspect or score the 113-row holdout.

## Acceptance rule

Accept H2 only if all conditions hold:

1. at least three net additional correct scorable dev rows;
2. precision among newly answered rows is at least the current answered
   precision;
3. no source loses more than one currently-correct scorable row;
4. no new wrong-family cluster is concentrated in a previously abstained
   family;
5. the default path remains unchanged when the flag is absent.

## Result

The counterfactual dev run evaluated all 136 scorable rows:

- Current production outcome: 85 correct (62.50%).
- Fusion-filled outcome: 85 correct (62.50%).
- Newly answered rows: **0**.
- Net gain: **0**.

The first acceptance condition failed, so H2 was rejected. The experimental
post-processing hook was removed; the default production path remains exactly
as it was before H2. Do not retry this same fallback policy without a new
predeclared hypothesis.
