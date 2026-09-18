import pytest
from analysis.step11_string_clustering import (
    cluster_high_entropy_strings,
    string_similarity,
    classify_obfuscation_type,
    shannon_entropy,
)


class TestClusterHighEntropyStrings:
    def test_empty(self):
        result = cluster_high_entropy_strings([])
        assert result["clusters"] == []
        assert result["total_clusters"] == 0

    def test_with_data(self):
        samples = [
            "aWQ9MSZ1cmw9aHR0cDovL2V2aWwuY29tL3BheWxvYWQ=",
            "cGFzc3dvcmQ9YWRtaW4xMjM=",
            "dXNlcj1hZG1pbiZwYXNzPXNlY3JldA==",
            "open", "close", "save", "load",
        ]
        result = cluster_high_entropy_strings(samples)
        assert result["total_clusters"] >= 0
        assert "high_entropy_strings" in result
        for s in result["high_entropy_strings"]:
            assert s["entropy"] >= 0.0
            assert s["entropy"] <= 8.0

    def test_none_input(self):
        result = cluster_high_entropy_strings(None)
        assert result["clusters"] == []
        assert result["total_clusters"] == 0


class TestStringSimilarity:
    def test_similar(self):
        sim = string_similarity("base64datahere", "base64dataalso")
        assert 0.0 <= sim <= 1.0

    def test_identical(self):
        assert string_similarity("abc", "abc") == 1.0

    def test_disjoint(self):
        assert string_similarity("abc", "xyz") == 0.0

    def test_empty(self):
        assert string_similarity("", "abc") == 0.0
        assert string_similarity("abc", "") == 0.0


class TestClassifyObfuscationType:
    def test_base64(self):
        assert classify_obfuscation_type("QUJDMTIzKy9kZWY0NTY9PQ==") == "base64"

    def test_hex(self):
        assert classify_obfuscation_type("deadbeefcafebabe") == "hex"

    def test_plaintext(self):
        assert classify_obfuscation_type("hello world") == "plaintext"

    def test_encrypted_or_packed(self):
        result = classify_obfuscation_type("".join(chr(i) for i in range(256)))
        assert result in ("encrypted_or_packed", "binary")


class TestShannonEntropy:
    def test_uniform(self):
        assert shannon_entropy("".join(chr(i) for i in range(256))) == pytest.approx(8.0, abs=0.5)

    def test_constant(self):
        assert shannon_entropy("aaaaaa") == 0.0

    def test_empty(self):
        assert shannon_entropy("") == 0.0
