"""String-pattern signatures match whole tokens, not substrings.

Regression for "tea" (TeaBot) firing on any word containing those letters, e.g.
"steady", which put AndroidOS samples under TeaBot on the validation set.
"""

from backend.family_id import _string_pattern_matches


def test_pattern_inside_a_longer_word_does_not_match():
    assert not _string_pattern_matches("tea", "steady state create config")


def test_standalone_token_matches():
    assert _string_pattern_matches("tea", "other tea value")


def test_dotted_package_segment_matches():
    assert _string_pattern_matches("kmin", "com.kmin.receiver")
