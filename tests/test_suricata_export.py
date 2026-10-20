from backend.threat_intel import to_suricata

SAMPLE = "a" * 64


def _result(*c2s):
    return {"c2_infrastructure": list(c2s)}


def test_domain_and_ip_each_get_a_rule_with_unique_sid():
    text = to_suricata(_result(
        {"domain": "evil-c2.example.com", "classification": "malicious", "status": "active"},
        {"ip": "203.0.113.7", "classification": "suspicious", "status": "unknown"},
    ), SAMPLE)

    lines = text.strip().splitlines()
    assert len(lines) == 2
    assert 'dns.query; content:"evil-c2.example.com"' in lines[0]
    assert "alert ip $HOME_NET any -> 203.0.113.7 any" in lines[1]
    sids = [line.split("sid:")[1].split(";")[0] for line in lines]
    assert len(set(sids)) == 2
    assert all(int(s) >= 1000000 for s in sids)


def test_hostile_domain_is_dropped_not_interpolated():
    text = to_suricata(_result(
        {"domain": 'x"; sid:1; alert ip any any -> any any (msg:"pwned', "classification": "malicious"},
        {"ip": "198.51.100.9", "classification": "malicious"},
    ), SAMPLE)

    assert "pwned" not in text
    assert "198.51.100.9" in text
    assert text.count("alert ") == 1


def test_benign_and_invalid_addresses_are_skipped():
    text = to_suricata(_result(
        {"domain": "cdn.example.com", "classification": "benign"},
        {"ip": "999.1.1.1", "classification": "malicious"},
    ), SAMPLE)

    assert text.startswith("# DroidForensix: no malicious or suspicious C2 indicators")
