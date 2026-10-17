from __future__ import annotations

from scamsentry.url_checks import extract_urls, parse_url_candidate


def test_http_https_extraction() -> None:
    text = "See https://example.com/a and http://example.org/b please."
    urls = extract_urls(text)
    schemes = {item.scheme for item in urls}
    hosts = {item.host for item in urls}
    assert schemes == {"http", "https"}
    assert "example.com" in hosts
    assert "example.org" in hosts


def test_trailing_punctuation_stripped() -> None:
    text = "Visit https://example.com/path)."
    urls = extract_urls(text)
    assert len(urls) == 1
    assert urls[0].original_text == "https://example.com/path"
    assert urls[0].path == "/path"


def test_defanged_hxxp_and_bracket_dot() -> None:
    text = "Open hxxps[:]//evil.example[.]test/login"
    urls = extract_urls(text)
    assert urls
    item = urls[0]
    assert item.recognised_defanged
    assert "hxxp" in item.original_text.lower() or "[.]" in item.original_text
    assert item.host == "evil.example.test"


def test_defanged_host_only() -> None:
    text = "Do not visit example[.]com/help"
    urls = extract_urls(text)
    assert len(urls) == 1
    assert urls[0].recognised_defanged
    assert urls[0].host == "example.com"


def test_ip_host() -> None:
    text = "Go to http://192.0.2.10/login"
    urls = extract_urls(text)
    assert urls[0].host_is_ip
    assert urls[0].host == "192.0.2.10"
    assert not any("many labels" in note for note in urls[0].notes)


def test_userinfo() -> None:
    text = "http://paypal.com:secret@192.0.2.8/login"
    urls = extract_urls(text)
    assert urls[0].userinfo is not None
    assert "secret" not in (urls[0].userinfo or "")


def test_unusual_port() -> None:
    text = "https://example.com:8443/app"
    urls = extract_urls(text)
    assert urls[0].port == 8443


def test_malformed_url_does_not_crash() -> None:
    parsed = parse_url_candidate("http://", False)
    assert parsed.parse_ok is False
    extract_urls("See http:// and also https://")


def test_ordinary_email_not_treated_as_url() -> None:
    urls = extract_urls("Contact billing@example.com for the invoice.")
    assert urls == ()


def test_javascript_scheme_extracted() -> None:
    urls = extract_urls("Click javascript:alert(1)")
    assert urls
    assert urls[0].scheme == "javascript"


def test_ipv6_host() -> None:
    text = "Connect to http://[2001:db8::1]:8080/admin or http://[::1]"
    urls = extract_urls(text)
    assert len(urls) == 2
    assert urls[0].host_is_ip
    assert urls[0].host == "2001:db8::1"
    assert urls[0].port == 8080
    assert urls[1].host_is_ip
    assert urls[1].host == "::1"
    assert urls[1].original_text == "http://[::1]"


def test_balanced_parentheses_in_url() -> None:
    text = "Read https://en.wikipedia.org/wiki/Phishing_(disambiguation)."
    urls = extract_urls(text)
    assert len(urls) == 1
    assert urls[0].original_text == "https://en.wikipedia.org/wiki/Phishing_(disambiguation)"
    assert urls[0].path == "/wiki/Phishing_(disambiguation)"


def test_defanged_variations() -> None:
    text = "Links: hxxps[://]bad[.]com and hxxps(:)//worse(.)net and site(.)org"
    urls = extract_urls(text)
    assert len(urls) == 3
    assert all(item.recognised_defanged for item in urls)
    hosts = {item.host for item in urls}
    assert hosts == {"bad.com", "worse.net", "site.org"}


def test_misleading_brand_subdomain() -> None:
    from scamsentry.url_checks import findings_for_url
    bad_urls = extract_urls("Visit https://paypal.phishing-domain.com/login")
    assert len(bad_urls) == 1
    findings = findings_for_url(bad_urls[0])
    assert any(item.rule_id == "E_MISLEADING_HOST" for item in findings)

    good_urls = extract_urls("Visit https://www.paypal.com/signin")
    assert len(good_urls) == 1
    findings_good = findings_for_url(good_urls[0])
    assert not any(item.rule_id == "E_MISLEADING_HOST" for item in findings_good)


def test_invalid_port_handled_and_flagged() -> None:
    from scamsentry.url_checks import findings_for_url
    for url_str in ["http://example.com:invalid/path", "http://example.com:999999/path"]:
        urls = extract_urls(f"Check this link: {url_str}")
        assert len(urls) == 1
        item = urls[0]
        assert item.parse_ok is False
        assert item.parse_error == "malformed_port"
        findings = findings_for_url(item)
        assert any(f.rule_id == "E_MALFORMED_URL" for f in findings)


def test_malformed_bracketed_host() -> None:
    from scamsentry.url_checks import findings_for_url
    urls = extract_urls("Click here: http://[not_an_ip_host]/login")
    assert len(urls) == 1
    item = urls[0]
    assert item.parse_ok is False
    assert item.parse_error == "malformed_bracketed_host"
    findings = findings_for_url(item)
    assert any(f.rule_id == "E_MALFORMED_URL" for f in findings)


def test_malformed_ipv6_url() -> None:
    from scamsentry.url_checks import findings_for_url
    urls = extract_urls("Connect to http://[2001:xyz::1]/admin")
    assert len(urls) == 1
    item = urls[0]
    assert item.parse_ok is False
    assert item.parse_error == "malformed_bracketed_host"
    findings = findings_for_url(item)
    assert any(f.rule_id == "E_MALFORMED_URL" for f in findings)


