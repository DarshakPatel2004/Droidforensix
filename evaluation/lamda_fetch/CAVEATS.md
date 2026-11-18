# Family-matcher evaluation caveats

- **Open-set eval (eval group, 51 samples):** every family in this group is absent from the shipped knowledge base. Any attribution is a false positive. Current count: 3 (all SmsSend, family 35wave).
- **In-KB recall (kb group, 51 samples):** optimistic. `kb_knowledge_base.json` was mined from these same samples, so this measures fit, not generalisation.
- **`eval_features.json` (about 74 MB) is not tracked in git.** Without it, `score_kb.py` runs on zero features and reports misleading numbers. Regenerate it with `build_eval_features.py`, or obtain it from the data owner.
- **Thresholds were tuned on the open-set eval.** A held-out split does not exist yet, so the tuned values (`_KB_STRONG_STRING_HITS = 12`, `_KB_TIE_RATIO = 0.8`) are fitted to this set.
