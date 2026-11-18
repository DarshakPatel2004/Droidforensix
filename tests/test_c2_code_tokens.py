"""Regression: code tokens and public resolvers must not become C2 records (samples 33d2ea97, a08f4f18)."""

import pytest

from analysis import step5_c2_extraction as c2


@pytest.mark.parametrize("token", [
    "console.log", "document.getElementsByClassName", "element.textContent",
    "data.fee", "data.to", "window.onload", "back.svg", "info.png", "0.25.sp", "Dispatchers.IO",
])
def test_code_tokens_are_rejected(token):
    assert c2._is_code_member_token(token)


@pytest.mark.parametrize("host", ["telegram.org", "poporo.com", "clipartmax.com"])
def test_real_hosts_are_kept(host):
    assert not c2._is_code_member_token(host)


def test_public_resolvers_are_excluded():
    assert {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"} <= c2.PUBLIC_RESOLVER_IPS
