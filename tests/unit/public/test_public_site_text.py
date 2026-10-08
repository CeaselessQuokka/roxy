"""Site text rendering (`site_*` settings, owner decision D18): escaped text, paragraphs, https links only.

What this is
    Unit tests for `roxy.public.pages.render_site_text` and `is_https_url`.

Why it exists
    The `site_*` texts are typed by an admin and shown to every visitor. They must never become a way to put
    markup or a `javascript:` link on the public page (plan 9.16), and v1's plugin link (a label with nested
    parentheses) must still render as a link (plan 16.1, test_v1_home_links_survive).

How it works
    Calls the renderer directly with crafted inputs and compares the HTML.

What to read next
    `roxy/config/settings/public_site.py` (the format contract) and `roxy/public/pages.py`.
"""

from __future__ import annotations

from roxy.config.catalog import CATALOG
from roxy.public.pages import is_https_url, render_site_text

PLUGIN_URL = "https://devforum.roblox.com/t/bundle-and-characteroutfit-inserter-free-plugin/3972083"


def test_paragraphs_split_on_blank_lines() -> None:
    html = render_site_text("First line\nsame paragraph.\n\n\nSecond paragraph.\n \nThird.")
    assert str(html) == "<p>First line\nsame paragraph.</p><p>Second paragraph.</p><p>Third.</p>"


def test_html_is_escaped_never_rendered() -> None:
    html = str(render_site_text('<script>alert("x")</script> & <b>bold</b>'))
    assert "<script>" not in html
    assert "<b>" not in html
    assert "&lt;script&gt;" in html
    assert "&amp;" in html


def test_https_link_becomes_a_link_with_parentheses_in_label() -> None:
    text = f"Also by the author: [Bundle and Character/Outfit Inserter (shameful plug(in))]({PLUGIN_URL})"
    html = str(render_site_text(text))
    assert f'<a href="{PLUGIN_URL}">Bundle and Character/Outfit Inserter (shameful plug(in))</a>' in html


def test_non_https_links_stay_text() -> None:
    for url in ("http://example.com", "javascript:alert(1)", "data:text/html,x", "https://user:pw@example.com/"):
        html = str(render_site_text(f"[click]({url})"))
        assert "<a " not in html, url
        assert "[click]" in html


def test_link_label_and_url_are_escaped() -> None:
    html = str(render_site_text('[<i>x</i>](https://example.com/?a=1&b="2")'))
    # A quote ends the URL match, so this stays text; the label markup is escaped either way.
    assert "<i>" not in html
    html = str(render_site_text("[a<b](https://example.com/?a=1&b=2)"))
    assert '<a href="https://example.com/?a=1&amp;b=2">a&lt;b</a>' in html


def test_inline_mode_for_the_footer() -> None:
    assert str(render_site_text("Roxy Proxy 2025-Present", inline=True)) == "Roxy Proxy 2025-Present"
    assert str(render_site_text("one\n\ntwo", inline=True)) == "one<br>two"


def test_default_site_texts_render() -> None:
    support = str(render_site_text(CATALOG["site_support_links"].default))
    assert f'href="{PLUGIN_URL}"' in support
    assert str(render_site_text(CATALOG["site_footer_text"].default, inline=True)) == "Roxy Proxy 2025-Present"
    bounty = str(render_site_text(CATALOG["site_bug_bounty_text"].default))
    assert "$10-$250 USD" in bounty


def test_is_https_url() -> None:
    assert is_https_url("https://roxytheproxy.com/docs")
    assert not is_https_url("http://roxytheproxy.com/")
    assert not is_https_url("https://")
    assert not is_https_url("https://a:b@roxytheproxy.com/")
    assert not is_https_url("//roxytheproxy.com/")
