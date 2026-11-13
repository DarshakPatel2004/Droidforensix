"""Unit tests for payload/string decoders, the manifest parser and community search (T-10).

step20 and step21 are exercised on synthetic ciphertext and bytes built in the
test. community_intel is tested with its HTTP client replaced, so nothing
touches the network.
"""

import hashlib
import textwrap
from types import SimpleNamespace

import pytest
from Cryptodome.Cipher import AES

import analysis.step20_payload_kdf_crack as step20
import analysis.step21_string_deobfuscation as step21
from analysis.manifest_analysis import ANDROID_NS, parse_manifest
from backend import community_intel

# ---------------------------------------------------------------------------
# step20: Zombinder-style payload KDF cracking
# ---------------------------------------------------------------------------


def _pkcs7_pad(pt: bytes) -> bytes:
    p = 16 - len(pt) % 16
    return pt + bytes([p]) * p


def _encrypt(pt: bytes, key: bytes, iv: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(_pkcs7_pad(pt))


def _gen1(seed: str):
    sb = seed.encode()
    return hashlib.sha1(sb).digest()[:16], hashlib.sha256(sb).digest()[:16]


def _gen2(seed: str):
    return hashlib.sha1(seed.encode()).digest()[:16], b"\x00" * 16


class TestStep20Kdf:
    def test_gen1_asset_round_trips_through_crack_asset(self):
        plaintext = b"PK\x03\x04" + b"A" * 40
        key, iv = _gen1("payload.bin2")
        blob = _encrypt(plaintext, key, iv)
        hit = step20.crack_asset(blob, "payload.bin")
        assert hit == {
            "seed": "payload.bin2",
            "kdf": "gen1_sha1key_sha256iv",
            "plaintext": plaintext,
            "kind": "zip",
        }

    def test_subdir_asset_uses_bare_basename_seed_with_zero_iv(self):
        plaintext = b"dex\n035\x00" + b"B" * 20
        key, iv = _gen2("inner.bin")
        blob = _encrypt(plaintext, key, iv)
        hit = step20.crack_asset(blob, "assets/inner.bin", subdir=True)
        assert hit["seed"] == "inner.bin"
        assert hit["kdf"] == "gen2_sha1key_zeroiv"
        assert hit["kind"] == "dex"
        assert hit["plaintext"] == plaintext

    def test_unrecognised_bytes_report_no_hit_with_full_matrix_count(self):
        result = step20.crack_asset(b"\x01" * 32, "junk.bin")
        assert result == {"error": "no_kdf_hit", "tried": 52}  # 13 seeds x 4 KDF variants

    def test_wrong_padding_is_not_a_hit(self):
        # Magic matches but the last byte is not a valid PKCS#7 pad.
        key, iv = _gen1("x2")
        blob = AES.new(key, AES.MODE_CBC, iv).encrypt(b"PK\x03\x04" + b"\x00" * 12)
        assert step20.decrypt_blob(blob, "x", "gen1_sha1key_sha256iv") is None

    def test_plaintext_without_known_magic_is_not_a_hit(self):
        key, iv = _gen1("y2")
        blob = _encrypt(b"just some text", key, iv)
        assert step20.decrypt_blob(blob, "y", "gen1_sha1key_sha256iv") is None

    def test_non_block_multiple_is_rejected(self):
        assert step20.decrypt_blob(b"\x00" * 17, "z", "gen1_sha1key_sha256iv") is None

    @pytest.mark.parametrize("pt, label", [
        (b"PK\x03\x04rest", "zip"),
        (b"dex\n035", "dex"),
        (b"\x7fELF...", "elf"),
        (b"\x1f\x8b\x08", "gzip"),
        (b'{"a": 1}', "json"),
        (b"\x00\x01\x00\x00", "ttf"),
        (b"plain", None),
    ])
    def test_magic_fingerprints(self, pt, label):
        assert step20._magic(pt) == label

    def test_pkcs7_strip_removes_full_valid_padding(self):
        assert step20._pkcs7_strip(b"hello" + bytes([11]) * 11) == b"hello"

    def test_pkcs7_strip_leaves_invalid_padding_alone(self):
        assert step20._pkcs7_strip(b"hello\x02") == b"hello\x02"
        assert step20._pkcs7_strip(b"") == b""


# ---------------------------------------------------------------------------
# step21: string deobfuscation helpers
# ---------------------------------------------------------------------------


class TestStep21Helpers:
    @pytest.mark.parametrize("raw, expected", [
        (b"abc", "abc"),
        ("é".encode("utf-8"), "é"),
        (b"\xc0\x80", "\x00"),                # MUTF-8 encodes NUL as two bytes
        ("€".encode("utf-8"), "€"),
    ])
    def test_mutf8_decodes_to_code_points(self, raw, expected):
        assert step21._mutf8_decode(raw) == expected

    def test_mutf8_rejects_continuation_byte_as_lead(self):
        with pytest.raises(ValueError, match="bad MUTF-8 byte"):
            step21._mutf8_decode(b"\x80")

    def test_printable_ratio(self):
        assert step21._printable_ratio(b"") == 0.0
        assert step21._printable_ratio(b"ab\x00\x01") == 0.5

    def test_npstringfog_decode_inverts_xor_with_repeating_key(self):
        secret = "com.example/gate"
        key = "k3y"
        raw = bytes(c ^ key.encode()[i % len(key)] for i, c in enumerate(secret.encode()))
        assert step21.npstringfog_decode(raw.hex(), key) == secret

    def test_mine_xor_callsites_recovers_printable_payload(self, tmp_path):
        sources = tmp_path / "sources" / "com" / "example"
        sources.mkdir(parents=True)
        plain = b"hello"
        data = [b ^ 7 for b in plain]
        (sources / "Strings.java").write_text(textwrap.dedent(f"""
            class Strings {{
                String a = Util.dec(new byte[]{{{", ".join(map(str, data))}}}, new byte[]{{7}});
                String b = Util.dec(new byte[]{{1, 2, 3}}, new byte[]{{0}});
            }}
        """), encoding="utf-8")
        found = step21.mine_xor_callsites(str(tmp_path / "sources"))
        assert found == {"hello": "Strings.java"}

    def test_mine_xor_callsites_missing_dir_is_empty(self, tmp_path):
        assert step21.mine_xor_callsites(str(tmp_path / "nope")) == {}


# ---------------------------------------------------------------------------
# manifest_analysis.parse_manifest
# ---------------------------------------------------------------------------


def _manifest(tmp_path, body: str):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.example">{body}</manifest>',
        encoding="utf-8",
    )
    return path


class TestParseManifest:
    def test_extracts_receivers_services_and_sorted_unique_actions(self, tmp_path):
        path = _manifest(tmp_path, """
            <application>
              <receiver android:name="com.example.BootReceiver">
                <intent-filter>
                  <action android:name="android.intent.action.BOOT_COMPLETED"/>
                  <action android:name="android.intent.action.SCREEN_ON"/>
                </intent-filter>
              </receiver>
              <service android:name="com.example.svc.SyncService">
                <intent-filter>
                  <action android:name="android.intent.action.BOOT_COMPLETED"/>
                </intent-filter>
              </service>
              <service android:name="PlainService"/>
            </application>
        """)
        parsed = parse_manifest(path)
        assert parsed["receivers"] == ["BootReceiver"]
        assert parsed["services"] == ["SyncService", "PlainService"]
        assert parsed["intent_actions"] == [
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.SCREEN_ON",
        ]

    def test_component_without_name_is_skipped_for_actions_only(self, tmp_path):
        path = _manifest(tmp_path, """
            <receiver>
              <intent-filter><action/></intent-filter>
            </receiver>
        """)
        parsed = parse_manifest(path)
        assert parsed["receivers"] == [""]
        assert parsed["intent_actions"] == []

    def test_malformed_xml_reports_parse_error(self, tmp_path):
        path = tmp_path / "AndroidManifest.xml"
        path.write_text("<manifest><receiver", encoding="utf-8")
        parsed = parse_manifest(path)
        assert "parse_error" in parsed
        assert parsed["receivers"] == [] and parsed["services"] == [] and parsed["intent_actions"] == []


# ---------------------------------------------------------------------------
# backend/community_intel.py
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, payload=None, text="", status=200):
        self._payload = payload
        self.text = text
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture
def fake_http(monkeypatch):
    """Route requests.get by URL. Tests fill `routes`; a missing route fails like a dead host."""
    routes = {}
    calls = []

    def get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        handler = routes.get(url)
        if handler is None:
            raise ConnectionError(f"no route for {url}")
        return handler(params)

    monkeypatch.setattr(community_intel, "requests", SimpleNamespace(get=get))
    monkeypatch.setattr(community_intel, "_CACHE", {})
    return SimpleNamespace(routes=routes, calls=calls)


class TestCommunityIntelQueries:
    def test_package_and_family_produce_four_queries(self):
        assert community_intel._build_queries("com.example.a", "Joker") == [
            '"com.example.a" malware',
            '"com.example.a" virus',
            '"Joker" android malware',
            '"Joker" apk trojan',
        ]

    @pytest.mark.parametrize("family", ["unknown", "NONE", "n/a", ""])
    def test_placeholder_family_is_not_searched(self, family):
        assert community_intel._build_queries("com.example.a", family) == [
            '"com.example.a" malware',
            '"com.example.a" virus',
        ]

    def test_no_package_and_no_family_falls_back_to_generic_query(self):
        assert community_intel._build_queries("", "unknown") == ["android malware apk forum"]


class TestCommunityIntelSources:
    def test_hacker_news_skips_untitled_and_falls_back_to_item_url(self, fake_http):
        fake_http.routes["https://hn.algolia.com/api/v1/search"] = lambda p: _Resp({
            "hits": [
                {"title": "Found a dropper", "objectID": "123", "points": 9, "author": "anon", "created_at": "2026-01-02T00:00:00Z"},
                {"title": "", "objectID": "999"},
            ],
        })
        posts = community_intel._search_hacker_news("q")
        assert len(posts) == 1
        assert posts[0]["url"] == "https://news.ycombinator.com/item?id=123"
        assert posts[0]["score"] == 9
        assert posts[0]["source"] == "Hacker News"

    def test_reddit_builds_permalink_urls_and_skips_incomplete_children(self, fake_http):
        fake_http.routes["https://www.reddit.com/search.json"] = lambda p: _Resp({
            "data": {"children": [
                {"data": {"title": "Trojan thread", "permalink": "/r/Malware/comments/abc/",
                          "subreddit": "Malware", "score": 4, "created_utc": 0}},
                {"data": {"title": "no link"}},
            ]},
        })
        posts = community_intel._search_reddit("q")
        assert len(posts) == 1
        assert posts[0]["url"] == "https://www.reddit.com/r/Malware/comments/abc/"
        assert posts[0]["subreddit"] == "Malware"
        assert posts[0]["published_at"] == ""  # created_utc 0 is treated as unknown

    def test_duckduckgo_html_is_scraped_and_protocol_relative_links_fixed(self, fake_http):
        html_body = (
            '<div class="result results_links">'
            '<a class="result__a" href="//example.org/post">Bad &amp; <b>sample</b></a>'
            '<a class="result__snippet" href="x">Thread about it</a>'
            "</div></div>"
        )
        fake_http.routes["https://html.duckduckgo.com/html/"] = lambda p: _Resp(text=html_body)
        posts = community_intel._search_duckduckgo("q")
        assert posts == [{
            "source": "DuckDuckGo",
            "title": "Bad & sample",
            "url": "https://example.org/post",
            "snippet": "Thread about it",
            "author": "",
            "score": 0,
            "published_at": "",
        }]


class TestSearchCommunityIntel:
    def test_all_sources_failing_is_reported_not_raised(self, fake_http):
        payload = community_intel.search_community_intel("com.example.a", "Joker")
        assert payload["posts"] == []
        assert payload["total_posts"] == 0
        assert payload["sources_failed"] == ["duckduckgo", "hacker_news", "reddit"]
        assert payload["family"] == "Joker"

    def test_duplicate_urls_keep_highest_scored_copy_and_sort_by_score(self, fake_http):
        def hn(params):
            return _Resp({"hits": [
                {"title": "Low", "url": "https://shared.example/x", "points": 1},
                {"title": "High", "url": "https://shared.example/x", "points": 50},
                {"title": "Other", "url": "https://other.example/y", "points": 10},
            ]})

        fake_http.routes["https://hn.algolia.com/api/v1/search"] = hn
        payload = community_intel.search_community_intel("com.example.a", "")
        urls = [p["url"] for p in payload["posts"]]
        assert urls == ["https://shared.example/x", "https://other.example/y"]
        assert payload["posts"][0]["title"] == "High"
        assert payload["family"] == "unknown"
        assert payload["package_name"] == "com.example.a"

    def test_cached_result_is_reused_for_same_key(self, fake_http, monkeypatch):
        calls = []

        def fake_search(package, family):
            calls.append((package, family))
            return {"posts": [], "package_name": package, "family": family}

        monkeypatch.setattr(community_intel, "search_community_intel", fake_search)
        first = community_intel.get_cached_community_intel("s" * 64, "com.a", "Joker")
        second = community_intel.get_cached_community_intel("s" * 64, "com.a", "Joker")
        assert first is second
        assert calls == [("com.a", "Joker")]
