"""Acceptance test: stage-3 bytecode replay regenerates the recorded strings.

Replay must be byte-identical to `installer_deobfuscated_strings.json` for
every non-null seed (175/180 exact). The 5 residual mismatches are the
documented ground-truth artifacts (seed/value swap, shifted label,
source-literal escapes) -- see rto_analysis/hole1_czrr_definitive.md.
"""

import json

from stage3_replay import (
    PROJECT_ROOT,
    decode_string,
    load_pool,
    run_replay,
)

DOCUMENTED_ARTIFACT_SEEDS = {
    -17516911999494,      # key/value swapped: label 'more_info' recorded as value
    -16962861218310,      # swapped: 'bug_fixes' label recorded as value
    -16030853315078,      # shifted row: label 'Novedades' -> 'last_update'
    -15987903642118,      # shifted row: label 'whats_new' -> 'Novedades'
    -12917002025478,      # source-literal escapes recorded, clean 128-char text
}

# -1629827971590 ('\A') is NOT an artifact: it matches once JSON-unescaped.


def _load_expected():
    data = json.loads((PROJECT_ROOT / "rto_analysis" / "phase2"
                       / "installer_deobfuscated_strings.json").read_text(encoding="utf-8"))
    return {int(k): v for k, v in data.items() if v is not None}


def test_replay_matches_recorded_fixture():
    pool = load_pool()
    expected = _load_expected()
    matches, mismatches, _ = run_replay(pool, expected)
    assert matches == 175
    assert mismatches == 5


def test_selective_spot_check():
    pool = load_pool()
    assert decode_string(-9154610674182, pool) == "app_installation"


def test_residual_mismatches_are_documented_artifacts():
    pool = load_pool()
    matches, _, detail = run_replay(pool, _load_expected())
    assert matches == 175  # guard: expect exactly the 5 documented seeds below
    mismatch_seeds = {int(line.split()[1]) for line in detail if line.startswith("MISMATCH")}
    assert mismatch_seeds == DOCUMENTED_ARTIFACT_SEEDS


def test_resolved_a_seed_matches():
    pool = load_pool()
    assert decode_string(-1629827971590, pool) == "\\A"