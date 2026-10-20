"""Unit tests for campaign clustering (synthetic vectors, no APKs)."""

import pytest

from analysis.campaign_clustering import (
    build_campaign_graph,
    campaign_evidence,
    campaign_hosts,
    cluster_purity,
    detect_campaigns,
    edge_weight,
    extract_sample_features,
    is_campaign_host,
    strict_tier_summary,
)


def _features(sample_id, cert=None, hosts=(), perms=(), minhash=(), cert_subject=None):
    return {
        "sample_id": sample_id,
        "apk_path": f"{sample_id}.apk",
        "permissions": list(perms),
        "cert_fp": cert,
        "cert_subject": cert_subject,
        "c2_hosts": list(hosts),
        "minhash_values": list(minhash),
        "method_count": len(minhash),
        "error": None,
    }


class TestCampaignHosts:
    def test_shared_kept_boilerplate_dropped(self):
        sets = [
            {"evil.com", "common-sdk.com"},
            {"evil.com", "common-sdk.com"},
            {"other.com", "common-sdk.com"},
            {"common-sdk.com"},
        ]
        kept = campaign_hosts(sets)
        assert "evil.com" in kept  # 2/4, campaign infra
        assert "common-sdk.com" not in kept  # 4/4, boilerplate
        assert "other.com" not in kept  # unique


class TestCampaignHostHygiene:
    def test_routable_host_and_ip_kept(self):
        assert is_campaign_host("c2-panel.eviltest12345.com") is True
        assert is_campaign_host("8.8.8.8") is True

    def test_private_and_loopback_dropped(self):
        assert is_campaign_host("10.0.0.172") is False
        assert is_campaign_host("127.0.0.1") is False
        assert is_campaign_host("0.0.0.0") is False

    def test_sdk_boilerplate_dropped(self):
        assert is_campaign_host("schemas.android.com") is False

    def test_ad_sdk_hosts_dropped(self):
        assert is_campaign_host("api.airpush.com") is False
        assert is_campaign_host("alog.umeng.com") is False
        assert is_campaign_host("www.w3.org") is False

    def test_junk_fragments_dropped(self):
        assert is_campaign_host("\x00") is False
        assert is_campaign_host("nodot") is False
        assert is_campaign_host("") is False


class TestEdgeWeight:
    def test_shared_cert_links(self):
        left = _features("a", cert="FP")
        right = _features("b", cert="FP")
        weight, reasons = edge_weight(left, right, set())
        # Cert alone (weight 3) no longer forms edge with LINK_MIN_WEIGHT=4
        # Need at least 2 signals
        assert weight == 3
        assert any("shared_cert" in r for r in reasons)

    def test_shared_testkey_cert_does_not_link(self):
        subject = "CN=Android,OU=Android,O=Android,L=Mountain View,ST=California,C=US"
        left = _features("a", cert="FP", cert_subject=subject)
        right = _features("b", cert="FP", cert_subject=subject)
        weight, _ = edge_weight(left, right, set())
        assert weight == 0

    def test_shared_c2_links(self):
        left = _features("a", hosts=["evil.com"])
        right = _features("b", hosts=["evil.com"])
        weight, _ = edge_weight(left, right, {"evil.com"}, kinds=frozenset({"c2"}))
        assert weight >= 2

    def test_boilerplate_host_does_not_link(self):
        left = _features("a", hosts=["common-sdk.com"])
        right = _features("b", hosts=["common-sdk.com"])
        weight, _ = edge_weight(left, right, set())
        assert weight < 2

    def test_permission_overlap_alone_never_links(self):
        perms = ["p1", "p2", "p3", "p4"]
        weight, _ = edge_weight(_features("a", perms=perms), _features("b", perms=perms), set())
        assert weight < 2

    def test_no_signals_no_edge(self):
        weight, _ = edge_weight(_features("a"), _features("b"), set())
        assert weight == 0

    def test_kinds_filter_disables_cert(self):
        left = _features("a", cert="FP")
        right = _features("b", cert="FP")
        weight, _ = edge_weight(left, right, set(), kinds=frozenset({"c2", "code"}))
        assert weight == 0

    def test_shared_c2_links_only_with_explicit_kind(self):
        left = _features("a", hosts=["c2.eviltest12345.com"])
        right = _features("b", hosts=["c2.eviltest12345.com"])
        kept = {"c2.eviltest12345.com"}
        assert edge_weight(left, right, kept)[0] < 2  # default: annotation-only
        assert edge_weight(left, right, kept, kinds=frozenset({"c2"}))[0] >= 2


class TestGraphAndCampaigns:
    def test_cert_pairs_form_two_campaigns(self):
        # Need 2 signals to form edge (LINK_MIN_WEIGHT=4)
        # Use cert (3) + code (2) = 5
        mh = [11, 22, 33]
        feats = [
            _features("a1", cert="FP1", minhash=mh),
            _features("a2", cert="FP1", minhash=mh),
            _features("b1", cert="FP2", minhash=mh),
            _features("b2", cert="FP2", minhash=mh),
            _features("lonely"),
        ]
        graph = build_campaign_graph(feats)
        assert graph.number_of_nodes() == 5
        assert graph.number_of_edges() == 2
        campaigns = detect_campaigns(graph)
        assert len(campaigns) == 3
        assert sorted(len(c) for c in campaigns) == [1, 2, 2]


class TestPurity:
    GT = {
        "a1": {"family": "GinMaster", "confidence": "high"},
        "a2": {"family": "GinMaster", "confidence": "high"},
        "b1": {"family": "Opfake", "confidence": "high"},
        "b2": {"family": "GinMaster", "confidence": "high"},  # mixed campaign
        "c1": {"family": "unknown", "confidence": "low"},  # catch-all noise
    }

    def test_mixed_campaign_purity(self):
        result = cluster_purity([{"a1", "a2"}, {"b1", "b2"}], self.GT)
        assert result["purity"] == pytest.approx(0.75)
        assert result["non_singleton_purity"] == pytest.approx(0.75)
        assert result["coverage"] == 1.0

    def test_singletons_excluded_from_headline(self):
        result = cluster_purity([{"a1", "a2"}, {"c1"}], self.GT)
        assert result["non_singleton_purity"] == 1.0
        assert result["coverage"] == pytest.approx(2 / 3, abs=1e-3)

    def test_high_confidence_filter_drops_catchalls(self):
        result = cluster_purity([{"a1"}, {"c1"}], self.GT, high_confidence_only=True)
        assert result["labeled_samples"] == 1
        assert result["purity"] == 1.0


class TestExtractionErrors:
    def test_missing_file_returns_error_without_raising(self):
        features = extract_sample_features("does-not-exist.apk")
        assert features["error"] is not None
        assert features["sample_id"] == ""


class TestCampaignEvidence:
    def test_shared_c2_and_cert_annotated(self):
        feats = [
            _features("a1", cert="FP", hosts=["c2.eviltest12345.com", "solo.example.org"]),
            _features("a2", cert="FP", hosts=["c2.eviltest12345.com"]),
        ]
        annotated = campaign_evidence([{"a1", "a2"}], feats)
        assert len(annotated) == 1
        assert annotated[0]["shared_c2_hosts"] == ["c2.eviltest12345.com"]
        assert annotated[0]["shared_certs"] == ["FP"]

    def test_singletons_carry_no_shared_evidence(self):
        annotated = campaign_evidence([{"a1"}], [_features("a1", hosts=["h.example.org"])])
        assert annotated[0]["shared_c2_hosts"] == []
        assert annotated[0]["shared_certs"] == []


class TestStrictTier:
    def test_two_signal_edge_kept_single_signal_dropped(self):
        # Same cert alone (weight 3) must not survive the strict bar;
        # cert + code agreement (weight 5) must.
        solo = [
            _features("a1", cert="FP"),
            _features("a2", cert="FP"),
        ]
        assert strict_tier_summary(solo, {})["edges"] == 0
        mh = [11, 22, 33]
        both = [
            _features("b1", cert="FP", minhash=mh),
            _features("b2", cert="FP", minhash=mh),
        ]
        assert strict_tier_summary(both, {})["edges"] == 1

    def test_strict_summary_reports_bar_and_coverage(self):
        mh = [11, 22, 33]
        feats = [
            _features("b1", cert="FP", minhash=mh),
            _features("b2", cert="FP", minhash=mh),
            _features("lonely"),
        ]
        gt = {
            "b1": {"family": "Opfake", "confidence": "high"},
            "b2": {"family": "Opfake", "confidence": "high"},
        }
        summary = strict_tier_summary(feats, gt)
        assert summary["min_edge_weight"] == 5
        assert summary["purity_all"]["purity"] == 1.0
        assert summary["purity_all"]["coverage"] == 1.0
