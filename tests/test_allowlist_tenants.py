"""A1-03: abused shared-hosting parents must not allowlist attacker subdomains."""
import pytest

from analysis.step5_allowlists import is_tier3
from analysis.step5_c2_extraction import is_benign_url

ATTACKER_URLS = [
    "https://evil-bot-123.firebaseio.com/cmd.json",
    "https://myc2.appspot.com/p",
    "http://x.byethost3.com/panel",
    "http://ca.badpanel.ru/gate.php",
    "http://service.evil.top/api",
    "http://r.evil.xyz/x",
    "http://proxy.evil.top/x",
]


@pytest.mark.parametrize("url", ATTACKER_URLS)
def test_attacker_hosts_are_not_benign(url):
    assert not is_benign_url(url)


def test_s3_tenant_is_not_tier3():
    assert not is_tier3("evil.s3.amazonaws.com")


def test_exact_shared_host_still_allowed():
    assert is_tier3("cdn.jsdelivr.net")
