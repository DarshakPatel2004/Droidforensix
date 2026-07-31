"""Unit tests for the forum scraper's pure logic (linker + dedup)."""

import json

import pytest

from forum_scraper.dedup import canonical_indicator, content_hash, deduplicate
from forum_scraper.linker import (
    C2Indicator,
    classify_indicator,
    extract_domains,
    extract_ips,
    find_matches,
    is_bot_content,
    make_snippet,
    match_indicator,
)
from forum_scraper.main import cap_links_per_repo, load_c2_indicators, repo_of


def indicator(value: str, confidence: float = 1.0) -> C2Indicator:
    parsed = classify_indicator(value)
    assert parsed is not None
    parsed.confidence = confidence
    return parsed


class TestClassify:
    @pytest.mark.parametrize(
        "raw,kind",
        [
            ("evil-c2.example.com", "domain"),
            ("c2.telegram.org", "domain"),
            ("192.168.1.10", "ip"),
            ("8.8.8.8", "ip"),
            ("", None),
            ("not a domain", None),
        ],
    )
    def test_classify(self, raw, kind):
        parsed = classify_indicator(raw)
        assert (parsed.kind if parsed else None) == kind


class TestExtraction:
    def test_extract_domains_deduplicates(self):
        assert extract_domains("see a.b.com and a.b.com again") == ["a.b.com"]

    def test_extract_ips_rejects_octets_out_of_range(self):
        assert extract_ips("999.1.2.3") == []

    def test_extract_ips_finds_normalized(self):
        assert extract_ips("hits 1.2.3.4:8080 here") == ["1.2.3.4"]


class TestMatchIndicator:
    def test_exact_domain_match(self):
        match = match_indicator(indicator("c2.example.com"), "the panel lives at c2.example.com")
        assert match is not None
        assert match.match_type == "exact"
        assert match.confidence == 1.0

    def test_exact_domain_not_matched_inside_subdomain(self):
        # "c2.example.com" must not match as a substring of "cdn.c2.example.com"
        match = match_indicator(indicator("c2.example.com"), "cdn.c2.example.com is the beacon")
        assert match is not None
        assert match.match_type == "subdomain"
        assert match.confidence == 0.8

    def test_subdomain_match(self):
        match = match_indicator(indicator("example.com"), "cdn.example.com/api is the C2")
        assert match is not None
        assert match.match_type == "subdomain"
        assert match.confidence == 0.8

    def test_www_domain_equivalence_is_exact(self):
        match = match_indicator(indicator("example.com"), "we see www.example.com in traffic")
        assert match is not None
        assert match.match_type == "exact"
        assert match.confidence == 1.0

    def test_ip_match(self):
        match = match_indicator(indicator("5.6.7.8"), "beaconing to 5.6.7.8")
        assert match is not None
        assert match.match_type == "ip"
        assert match.confidence == 0.9

    def test_no_match(self):
        assert match_indicator(indicator("example.com"), "nothing here") is None

    def test_parent_domain_mention_does_not_match_subdomain_c2(self):
        # Mentioning "example.com" is not a mention of C2 "c2.example.com"
        assert match_indicator(indicator("c2.example.com"), "example.com is down") is None

    def test_exclude_domain_returns_none(self):
        assert match_indicator(indicator("github.com"), "posting code to github.com") is None
        assert (
            match_indicator(indicator("github.com"), "posting code to github.com", exclude_domains=["github.com"])
            is None
        )

    def test_typosquat_flagged_for_review(self):
        match = match_indicator(indicator("malware-c2.com"), "beacon to malware-c3.com")
        assert match is not None
        assert match.match_type == "typosquat"
        assert match.confidence == 0.5
        assert match.needs_review


class TestSnippet:
    def test_snippet_contains_match(self):
        text = "prefix " * 30 + "c2.example.com" + " suffix " * 30
        match = match_indicator(indicator("c2.example.com"), text)
        assert match is not None
        snippet = make_snippet(text, match.match_start, match.match_end)
        assert "c2.example.com" in snippet
        assert len(snippet) < 250

    def test_snippet_ellipsis_on_long_text(self):
        text = "x" * 1000 + " target.example.com " + "y" * 1000
        match = match_indicator(indicator("target.example.com"), text)
        snippet = make_snippet(text, match.match_start, match.match_end)
        assert snippet.startswith("...")
        assert snippet.endswith("...")


class TestBotFilter:
    @pytest.mark.parametrize(
        "username,body",
        [
            ("AutoModerator", "removed post"),
            ("defender_bot", "I am a bot, this post has been removed"),
            ("", ""),
        ],
    )
    def test_bot_content_flagged(self, username, body):
        assert is_bot_content(username, body)

    def test_empty_username_not_bot(self):
        assert not is_bot_content("", "the C2 is at c2.example.com")


class TestFindMatches:
    def test_filters_by_confidence(self):
        from forum_scraper.linker import score_filter

        match = match_indicator(indicator("5.6.7.8"), "beacon to 5.6.7.8")
        assert match is not None
        assert score_filter(match, min_confidence=0.7)
        assert not score_filter(
            match_indicator(indicator("malware-c2.com"), "beacon to malware-c3.com"),
            min_confidence=0.7,
        )

    def test_find_matches_empty_for_none(self):
        assert find_matches(indicator("example.com"), "no mention here") == []


class TestDedup:
    def test_canonical_domain_strips_www(self):
        assert canonical_indicator(indicator("www.example.com")) == "example.com"

    def test_canonical_ip_compressed(self):
        assert canonical_indicator(indicator("192.168.001.001")) == "192.168.1.1"

    def test_content_hash_normalizes_whitespace(self):
        assert content_hash("A  B\nC") == content_hash("a b c")

    def test_deduplicate_keeps_first(self):
        links = [
            {"c2_indicator": "example.com", "snippet": "beacon at example.com here", "source": "reddit"},
            {"c2_indicator": "example.com", "snippet": "beacon at example.com here", "source": "github"},
        ]
        result = deduplicate(links, resolve_ips=False)
        assert len(result) == 1
        assert result[0]["source"] == "reddit"

    def test_deduplicate_keeps_distinct_content(self):
        links = [
            {"c2_indicator": "example.com", "snippet": "first mention of example.com", "source": "reddit"},
            {"c2_indicator": "example.com", "snippet": "second distinct mention example.com", "source": "reddit"},
        ]
        assert len(deduplicate(links, resolve_ips=False)) == 2


class TestLoadC2Indicators:
    def test_aggregates_pipeline_result_directory(self, tmp_path):
        for sample_id, records in {
            "sample_a": [
                {"c2_id": "c2_000", "domain": "evil.io", "ip": None, "raw_url": "evil.io", "confidence": 0.8},
                {"c2_id": "c2_001", "domain": None, "ip": "5.6.7.8", "raw_url": "http://5.6.7.8/", "confidence": 0.9},
            ],
            "sample_b": [
                {"c2_id": "c2_000", "domain": "evil.io", "ip": None, "raw_url": "evil.io", "confidence": 0.95},
            ],
        }.items():
            sample_dir = tmp_path / sample_id
            sample_dir.mkdir()
            (sample_dir / "pipeline_result.json").write_text(
                json.dumps({"sample_id": sample_id, "c2_infrastructure": records}),
                encoding="utf-8",
            )

        indicators = load_c2_indicators(str(tmp_path))
        values = {(i.kind, i.value): i for i in indicators}

        # Same domain in two samples collapses to one, keeping max confidence
        assert values[("domain", "evil.io")].confidence == 0.95
        # IP records are picked up from the "ip" key
        assert ("ip", "5.6.7.8") in values
        assert len(indicators) == 2

    def test_confidence_floor_filters_indicators(self, tmp_path):
        c2_file = tmp_path / "c2s.json"
        c2_file.write_text(
            json.dumps(
                {"c2_infrastructure": [
                    {"domain": "a.example.com", "confidence": 0.9},
                    {"domain": "b.example.com", "confidence": 0.5},
                ]}
            ),
            encoding="utf-8",
        )
        assert len(load_c2_indicators(str(c2_file), min_confidence=0.8)) == 1

    def test_pipeline_json_with_null_confidence_defaults(self, tmp_path):
        c2_file = tmp_path / "c2s.json"
        c2_file.write_text(
            json.dumps({"c2_infrastructure": [{"domain": "a.example.com", "confidence": None}]}),
            encoding="utf-8",
        )
        indicators = load_c2_indicators(str(c2_file))
        assert indicators[0].confidence == 1.0


class TestPerRepoCap:
    def test_repo_of_extracts_owner_repo(self):
        url = "https://github.com/bhpiamnothing/AndroTruth-Dataset/blob/abc/path.py#L5"
        assert repo_of(url) == "bhpiamnothing/AndroTruth-Dataset"

    def test_repo_of_none_for_non_github(self):
        assert repo_of("https://www.reddit.com/r/malware/comments/1a/") is None

    def test_cap_limits_github_links_per_repo(self):
        links = [
            {"forum_url": "https://github.com/a/repo/blob/x#L1", "c2_indicator": "c2-a.example.com"},
            {"forum_url": "https://github.com/a/repo/blob/x#L2", "c2_indicator": "c2-a.example.com"},
            {"forum_url": "https://github.com/a/repo/blob/x#L3", "c2_indicator": "c2-a.example.com"},
            {"forum_url": "https://github.com/a/repo/blob/x#L4", "c2_indicator": "c2-a.example.com"},
            {"forum_url": "https://www.reddit.com/r/malware/comments/1a/", "c2_indicator": "c2-a.example.com"},
        ]
        capped = cap_links_per_repo(links, max_per_repo=3)
        assert len(capped) == 4  # 3 from the repo + 1 reddit
        assert all(link["forum_url"].startswith("https://github.com") for link in capped[:3])

    def test_cap_rescues_c2s_that_lose_all_links(self):
        # Three C2s, each ONLY present in the same repo: the cap must not
        # strip any C2 of its only evidence.
        links = []
        for c2 in ("c2-a.example.com", "c2-b.example.com", "c2-c.example.com"):
            for i in range(3):
                links.append(
                    {"forum_url": f"https://github.com/dataset/repo/blob/x#L{i}", "c2_indicator": c2}
                )
        capped = cap_links_per_repo(links, max_per_repo=1)
        assert len(capped) == 3  # one link per C2, all rescued
        assert {link["c2_indicator"] for link in capped} == {
            "c2-a.example.com",
            "c2-b.example.com",
            "c2-c.example.com",
        }

    def test_cap_zero_is_unlimited(self):
        links = [{"forum_url": f"https://github.com/a/repo/blob/x#L{i}"} for i in range(5)]
        assert len(cap_links_per_repo(links, max_per_repo=0)) == 5

    def test_cap_keeps_first_occurrences(self):
        links = [
            {"forum_url": "https://github.com/a/repo/blob/x#L1", "c2_indicator": "first.example.com"},
            {"forum_url": "https://github.com/a/repo/blob/x#L2", "c2_indicator": "second.example.com"},
        ]
        capped = cap_links_per_repo(links, max_per_repo=1)
        assert capped[0]["c2_indicator"] == "first.example.com"
