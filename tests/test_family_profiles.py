from backend.family_profiles import FAMILY_PROFILES, describe_family, evidence_lines


def test_describe_family_returns_profile_for_known_family():
    profile = describe_family("SpyNote")
    assert profile is not None
    assert "remote-access trojan" in profile["what"]
    assert profile["typical_behaviour"]


def test_describe_family_returns_none_when_no_profile_written():
    assert describe_family("NotARealFamily") is None
    assert describe_family(None) is None
    assert describe_family("") is None


def test_every_profile_has_description_and_behaviour():
    for name, profile in FAMILY_PROFILES.items():
        assert profile["what"].strip(), name
        assert profile["typical_behaviour"], name


def test_evidence_lines_strips_knowledge_base_preamble():
    reasoning = (
        "KB score 22.16 from 53 discriminating tokens: screenhight; solvegraph; getdrawheight"
    )
    assert evidence_lines(reasoning) == ["screenhight", "solvegraph", "getdrawheight"]


def test_evidence_lines_keeps_plain_sentence_as_one_item():
    assert evidence_lines("signing certificate matches known-bad DB entry for SpyNote") == [
        "signing certificate matches known-bad DB entry for SpyNote"
    ]


def test_evidence_lines_empty_reasoning():
    assert evidence_lines("") == []
    assert evidence_lines(None) == []
