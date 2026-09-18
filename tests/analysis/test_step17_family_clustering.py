import hashlib
import pytest
from analysis.step17_family_clustering import (
    hash_method_signature,
    build_sample_signature,
    match_against_index,
    jaccard_similarity,
    load_or_build_index,
    MinHash,
    NUM_PERMUTATIONS,
)


class TestHashMethodSignature:
    def test_valid(self):
        sig = hash_method_signature("Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V")
        assert len(sig) == 64
        assert isinstance(sig, str)

    def test_empty(self):
        sig = hash_method_signature("")
        assert len(sig) == 64
        assert isinstance(sig, str)

    def test_deterministic(self):
        sig1 = hash_method_signature("test")
        sig2 = hash_method_signature("test")
        assert sig1 == sig2


class TestMinHash:
    def test_identical(self):
        mh1 = MinHash()
        mh2 = MinHash()
        mh1.update("Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V")
        mh2.update("Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V")
        assert mh1.jaccard(mh2) == 1.0

    def test_different(self):
        mh1 = MinHash()
        mh2 = MinHash()
        mh1.update("abc")
        mh2.update("xyz")
        sim = mh1.jaccard(mh2)
        assert sim == 0.0

    def test_num_perm_default(self):
        mh = MinHash()
        assert len(mh.hash_values) == NUM_PERMUTATIONS
        assert mh.num_perm == NUM_PERMUTATIONS

    def test_deterministic_seeds(self):
        mh1 = MinHash(seed=42)
        mh2 = MinHash(seed=42)
        assert mh1.seeds == mh2.seeds

    def test_different_seeds_different_hashes(self):
        mh1 = MinHash(seed=1)
        mh2 = MinHash(seed=2)
        assert mh1.seeds != mh2.seeds

    def test_multiple_updates_take_min(self):
        mh = MinHash()
        mh.update("abc")
        first = list(mh.hash_values)
        mh.update("abc")
        assert mh.hash_values == first

    def test_jaccard_raises_on_mismatch(self):
        mh1 = MinHash(num_perm=64)
        mh2 = MinHash(num_perm=128)
        with pytest.raises(ValueError):
            mh1.jaccard(mh2)

    def test_empty_update(self):
        mh = MinHash()
        mh.update("")
        assert all(v != 1 << 256 for v in mh.hash_values)


class TestBuildSampleSignature:
    def test_empty(self):
        result = build_sample_signature([])
        assert result["total_methods"] == 0
        assert result["minhash_values"] == []

    def test_with_methods(self):
        result = build_sample_signature([
            {"class": "com.example.Main", "method": "onCreate", "descriptor": "(Landroid/os/Bundle;)V"},
            {"class": "com.example.Main", "method": "onResume", "descriptor": "()V"},
        ])
        assert result["total_methods"] == 2
        assert len(result["method_signatures"]) == 2
        assert len(result["minhash_values"]) == NUM_PERMUTATIONS

    def test_deterministic(self):
        methods = [
            {"class": "com.example.Main", "method": "onCreate", "descriptor": "(Landroid/os/Bundle;)V"},
        ]
        r1 = build_sample_signature(methods)
        r2 = build_sample_signature(methods)
        assert r1["minhash_values"] == r2["minhash_values"]

    def test_similar_methods_higher_similarity(self):
        shared = {"class": "com.example.Main", "method": "onCreate", "descriptor": "()V"}
        r1 = build_sample_signature([shared])
        r2 = build_sample_signature([shared])
        assert jaccard_similarity(r1["minhash_values"], r2["minhash_values"]) == 1.0


class TestMatchAgainstIndex:
    def test_empty(self):
        result = match_against_index({"minhash_values": []}, {})
        assert result["matches"] == []
        assert result["best_match"] is None

    def test_with_data(self):
        methods = [{"class": "c", "method": "m", "descriptor": "()V"}]
        query_sigs = build_sample_signature(methods)
        index_sigs = build_sample_signature(methods)
        index = {
            "samples": {
                "sample_A": {
                    "family": "Joker",
                    "method_signatures": index_sigs["method_signatures"],
                    "minhash_values": index_sigs["minhash_values"],
                    "signature_count": index_sigs["total_methods"],
                }
            }
        }
        result = match_against_index(query_sigs, index)
        assert len(result["matches"]) > 0
        assert result["matches"][0]["similarity"] == 1.0

    def test_empty_index(self):
        result = match_against_index({"minhash_values": [1, 2, 3]}, {"samples": {}})
        assert result["matches"] == []

    def test_old_format_graceful(self):
        query_sigs = build_sample_signature([{"class": "c", "method": "m", "descriptor": "()V"}])
        index = {
            "samples": {
                "sample_A": {
                    "family": "Joker",
                    "method_signatures": [],
                    "expanded_signature_hashes": ["abc"],
                    "signature_count": 1,
                }
            }
        }
        result = match_against_index(query_sigs, index)
        assert result["matches"] == []
        assert result["best_match"] is None


class TestJaccardSimilarity:
    def test_identical(self):
        assert jaccard_similarity([1, 2, 3], [1, 2, 3]) == 1.0

    def test_disjoint(self):
        assert jaccard_similarity([1, 2], [3, 4]) == 0.0

    def test_partial(self):
        sim = jaccard_similarity([1, 2, 3], [1, 4, 5])
        assert sim == pytest.approx(1.0 / 3.0)

    def test_empty(self):
        assert jaccard_similarity([], [1]) == 0.0


class TestLoadOrBuildIndex:
    def test_default(self):
        index = load_or_build_index()
        assert isinstance(index, dict)
        assert "samples" in index


class TestBackwardCompatibility:
    def test_load_index_old_version(self, tmp_path, monkeypatch):
        import json
        from analysis.cross_sample_index import load_index

        old_index = {
            "version": 1,
            "samples": {
                "old_sample": {
                    "family": "Joker",
                    "method_signatures": [],
                    "expanded_signature_hashes": ["abc"],
                    "signature_count": 0,
                }
            },
        }
        index_file = tmp_path / "cross_sample_index.json"
        index_file.write_text(json.dumps(old_index))
        monkeypatch.setattr("analysis.cross_sample_index.INDEX_PATH", index_file)

        result = load_index()
        assert result == {"samples": {}, "version": 2}

    def test_load_index_current_version(self, tmp_path, monkeypatch):
        import json
        from analysis.cross_sample_index import load_index

        current_index = {
            "version": 2,
            "samples": {
                "sample_A": {
                    "family": "Joker",
                    "method_signatures": [],
                    "minhash_values": [1, 2, 3],
                    "signature_count": 0,
                }
            },
        }
        index_file = tmp_path / "cross_sample_index.json"
        index_file.write_text(json.dumps(current_index))
        monkeypatch.setattr("analysis.cross_sample_index.INDEX_PATH", index_file)

        result = load_index()
        assert result["version"] == 2
        assert "sample_A" in result["samples"]
