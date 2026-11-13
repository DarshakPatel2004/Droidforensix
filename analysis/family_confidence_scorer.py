"""Multi-signal family confidence scoring (additive evaluator, offline).

Implements the ensemble idea discussed in docs/accuracy-improvement-plan.md:
instead of winner-take-all exact signature/KB matching, score every candidate
family as a weighted fusion of independent signals and return the argmax fused
confidence, abstaining to ``unknown`` when nothing clears the bar.

Signals (weights mirror the thesis proposal:
signature 0.40 + c2_alignment 0.25 + profile 0.20 + metadata 0.15):

  1. signature        - hand-written string patterns (FAMILY_SIGNATURES) hit ratio
  2. c2_alignment     - C2 domain pool overlap (signature C2Pattern + KB domains)
  3. profile          - KB mined token overlap + permission signature overlap
                        (stands in for the proposed obfuscation-style signal:
                        no per-family obfuscation profile exists offline, so the
                        0.20 weight; family-agnostic obfuscation is not fused)
  4. metadata         - class_count band + native-lib requirement consistency

Pool sources are STATIC knowledge only (family_id.FAMILY_SIGNATURES + mined
family_knowledge_base.json). No ground-truth labels are used to build the pools.

This module is intentionally additive: it never mutates
``backend.family_id.identify_family()``. Use ``evaluation/family_ensemble_eval.py``
to compare it head-to-head with the production engine.

Usage:
    from analysis.family_confidence_scorer import FamilyConfidenceScorer
    scorer = FamilyConfidenceScorer()
    sample = SampleSignals.from_cache(entry)          # gap_features_cache entry
    ranked = scorer.score(sample)                     # fuses all known families
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB_PATH = ROOT / "analysis" / "family_knowledge_base.json"

# Relative contribution of each signal to the fused confidence. Calibrated so a
# single very strong signal alone (c2_alignment == 1.0 works out to ~0.6) cannot
# reach the ``CONFIDENCE_BAR``: agreement across at least two signals is required.
SIGNAL_WEIGHTS = {
    "signature": 0.40,
    "c2_alignment": 0.25,
    "profile": 0.20,
    "metadata": 0.15,
}
CONFIDENCE_BAR = 0.75

# Magic-number normalization for KB mined scores. Production KB "score 1.08
# from 2 tokens" for a strong GinMaster hit means ~0.5-1.0 weight per matched
# token; 3 weighted tokens of signal should saturate the profile signal (this
# keeps the profile signal discriminative instead of saturating on any hit).
KB_SCORE_SATURATION = 3.0


@dataclass
class SampleSignals:
    """Per-sample evidence a scorer fuses against family profiles."""

    strings: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    class_count: int = 0
    native_libs: bool = False

    # Guard separator: single Python-level pass over the string corpus per
    # pattern via one substring lookup on a joined blob, instead of a per-string
    # Python loop (orders of magnitude faster on the 3k+ string samples).
    _SEP = "\x01"

    @property
    def text_blob(self) -> str:
        return self._SEP.join(self.strings) if self.strings else ""

    @property
    def domain_blob(self) -> str:
        return self._SEP.join(self.domains) if self.domains else ""

    @classmethod
    def from_cache(cls, entry: dict) -> SampleSignals:
        """Build from a gap_features_cache.json entry."""
        return cls(
            strings=[s.lower() for s in (entry.get("strings") or []) if isinstance(s, str)],
            domains=[d.lower() for d in (entry.get("domains") or []) if isinstance(d, str)],
            permissions=[p.split(".")[-1] for p in (entry.get("permissions") or [])],
            class_count=entry.get("class_count") or 0,
            native_libs=bool(entry.get("native_libs")),
        )

    @classmethod
    def from_pipeline_result(cls, result: dict) -> SampleSignals:
        """Adapt a pipeline result dict (same shape reeval_families passes)."""
        extraction = result.get("extraction", {}) or {}
        manifest = result.get("manifest", {}) or {}
        # Pipeline keeps strings under result["strings"]["string_literals"], not under extraction (L15).
        raw_strings = ((result.get("strings", {}) or {}).get("string_literals", [])
                       or extraction.get("string_literals", []) or [])
        values: list[str] = []
        for s in raw_strings:
            values.append(s.get("value") if isinstance(s, dict) else s)
        perms = manifest.get("uses_permissions", []) or []
        domains = [
            (c.get("domain") or "").lower()
            for c in (result.get("c2_infrastructure") or [])
            if c.get("domain")
        ]
        native = extraction.get("native_libs_found", []) or []
        return cls(
            strings=[str(v).lower() for v in values if v],
            domains=[d for d in domains if d],
            permissions=[p.split(".")[-1] for p in perms],
            class_count=extraction.get("decompiled_classes") or 0,
            native_libs=bool(native),
        )


@dataclass
class SignalProfile:
    """Static per-family discriminator pool (built once, never GT-derived)."""

    family: str
    string_patterns: list[str] = field(default_factory=list)
    c2_patterns: list[str] = field(default_factory=list)
    kb_tokens: dict[str, float] = field(default_factory=dict)
    permission_sigs: dict[str, float] = field(default_factory=dict)
    class_count_min: int | None = None
    class_count_max: int | None = None
    has_native_libs: bool | None = None
    conf_scale: float = 1.0


class FamilyConfidenceScorer:
    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or dict(SIGNAL_WEIGHTS)
        self._profiles: dict[str, SignalProfile] = {}
        self._load_profiles()

    # ------------------------------------------------------------------ pools
    def _load_profiles(self) -> None:
        from backend.family_id import FAMILY_SIGNATURES

        for sig in FAMILY_SIGNATURES:
            profile = SignalProfile(
                family=sig.family_name,
                string_patterns=[p.lower() for p in sig.string_patterns],
                c2_patterns=[p.pattern.lower() for p in sig.c2_patterns],
                permission_sigs={p.short_name().lower(): p.weight for p in sig.permission_sigs},
                class_count_min=sig.class_count_min,
                class_count_max=sig.class_count_max,
                has_native_libs=sig.has_native_libs,
                conf_scale=sig.confidence,
            )
            self._profiles.setdefault(sig.family_name, profile)

        if KB_PATH.exists():
            import json

            kb = json.loads(KB_PATH.read_text(encoding="utf-8"))
            for family, spec in kb.items():
                profile = self._profiles.setdefault(family, SignalProfile(family=family))
                for tok in spec.get("strings") or []:
                    token = (tok.get("token") or "").lower()
                    if len(token) >= 4:
                        profile.kb_tokens[token] = (tok.get("coverage") or 0.0) * (
                            1.0 - (tok.get("fp") or 0.0)
                        )
                for dom in spec.get("domains") or []:
                    token = dom.get("token") if isinstance(dom, dict) else dom
                    if token:
                        profile.c2_patterns.append(token.lower())
                for perm in spec.get("permissions") or []:
                    token = perm.get("token") if isinstance(perm, dict) else perm
                    if token:
                        profile.permission_sigs[token.lower().split(".")[-1]] = 1.0

    @property
    def families(self) -> list[str]:
        return sorted(self._profiles)

    # ---------------------------------------------------------------- signals
    def _signature_signal(self, sample: SampleSignals, profile: SignalProfile) -> float:
        if not profile.string_patterns:
            return 0.0
        blob = sample.text_blob
        if not blob:
            return 0.0
        matched = sum(1 for pat in profile.string_patterns if pat in blob)
        ratio = matched / len(profile.string_patterns)
        return min(1.0, ratio) * profile.conf_scale

    def _c2_alignment(self, sample: SampleSignals, profile: SignalProfile) -> float:
        pools = [p for p in profile.c2_patterns if p]
        if not pools:
            return 0.0
        blob = sample.domain_blob
        if not blob:
            return 0.0
        matched = sum(1 for pattern in pools if pattern in blob)
        return min(1.0, matched / len(pools))

    def _profile_signal(self, sample: SampleSignals, profile: SignalProfile) -> float:
        blob = sample.text_blob
        kb_score = sum(weight for token, weight in profile.kb_tokens.items() if token in blob)
        kb_signal = min(1.0, kb_score / KB_SCORE_SATURATION)
        if profile.permission_sigs:
            total_weight = sum(profile.permission_sigs.values())
            matched_weight = sum(
                w for perm, w in profile.permission_sigs.items() if perm in sample.permissions
            )
            perm_signal = matched_weight / total_weight if total_weight else 0.0
        else:
            perm_signal = 0.5  # neutral: no permission signal declared
        return 0.6 * kb_signal + 0.4 * perm_signal

    def _metadata_signal(self, sample: SampleSignals, profile: SignalProfile) -> float:
        class_signal = 1.0
        has_band = profile.class_count_min is not None or profile.class_count_max is not None
        if has_band and sample.class_count:
            lo, hi = profile.class_count_min, profile.class_count_max
            if not (lo is None or sample.class_count >= lo) or not (
                hi is None or sample.class_count <= hi
            ):
                class_signal = 0.25
        native_signal = 1.0
        if profile.has_native_libs is not None:
            native_signal = 1.0 if sample.native_libs == profile.has_native_libs else 0.25
        return (class_signal + native_signal) / 2.0

    # -------------------------------------------------------- public scoring
    def score_family(self, sample: SampleSignals, family: str) -> dict:
        profile = self._profiles.get(family)
        if profile is None:
            return {"family": family, "confidence": 0.0, "signals": {}}
        signals = {
            "signature": self._signature_signal(sample, profile),
            "c2_alignment": self._c2_alignment(sample, profile),
            "profile": self._profile_signal(sample, profile),
            "metadata": self._metadata_signal(sample, profile),
        }
        confidence = sum(signals[k] * self.weights[k] for k in self.weights)
        return {
            "family": family,
            "confidence": round(confidence, 4),
            "signals": {k: round(v, 4) for k, v in signals.items()},
        }

    def score(self, sample: SampleSignals, top_n: int = 5, bar: float = CONFIDENCE_BAR) -> dict:
        if not sample.strings and not sample.domains:
            return {"family": "unknown", "confidence": 0.0, "signals": {}, "candidates": []}
        ranked = sorted(
            (self.score_family(sample, fam) for fam in self._profiles),
            key=lambda item: -item["confidence"],
        )[:top_n]
        top = ranked[0] if ranked else None
        if top is None or top["confidence"] < bar:
            return {
                "family": "unknown",
                "confidence": top["confidence"] if top else 0.0,
                "signals": top["signals"] if top else {},
                "candidates": ranked,
            }
        return {**top, "candidates": [c["family"] for c in ranked[1:]]}


def iter_scorable(entries: dict[str, dict]) -> Iterable[tuple[str, SampleSignals]]:
    """Yield (sha, signals) for cache entries usable by the scorer."""
    for sha, entry in entries.items():
        if entry.get("parse_error"):
            continue
        if "strings" not in entry and "domains" not in entry:
            continue
        yield sha, SampleSignals.from_cache(entry)
