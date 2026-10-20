from analysis.step5_allowlists import is_tier3


def test_www_prefix_is_stripped_but_other_leading_letters_are_kept():
    # lstrip("www.") removed any leading "w" or "." characters, so "wgoogle.com"
    # used to be treated as "google.com" and allowlisted.
    assert is_tier3("www.google.com") is True
    assert is_tier3("wgoogle.com") is False
