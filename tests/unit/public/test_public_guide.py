"""The user guide (plan 16.2): the outline, every header and status code, safe rendering, live values, finding it.

What this is
    Unit tests for `docs/USER_GUIDE.md` and the renderer in `roxy.public.pages` (`render_guide`, `load_guide`,
    `guide_values`, `slugify`, `find_user_guide`).

Why it exists
    The guide is the caller's contract: chapters in the plan's order, every `Roxy-*` header, the status code
    table, the Luau examples, and only statements that are true for the live settings (CORS, the place limit,
    the status page, singular and plural counts). Its rendering is also a security boundary (raw HTML in the file
    must stay text) and a CSP one (no inline `style` attributes, which markdown-it writes for aligned table
    columns). And the release must find the file: a non-editable install puts the package far from `docs/`.

How it works
    Renders the real file and small crafted documents, then inspects the HTML and the table of contents. The
    install layout test copies the package into a fake release (`<release>/.venv/lib/python3.12/site-packages`)
    and imports it in a separate interpreter, exactly where deploy/deploy.sh's `uv sync --no-editable` puts it.

What to read next
    `docs/USER_GUIDE.md`, then `roxy/public/pages.py` (section "the user guide").
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Callable
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

from roxy.config.catalog import CATALOG
from roxy.core.style_guard import assert_style_clean
from roxy.public import pages
from roxy.public.pages import GUIDE_VALUES, USER_GUIDE_PATH, guide_values, load_guide, render_guide, slugify

Getter = Callable[[str], Any]

OUTLINE = [
    "1. What Roxy does",
    "2. URL format",
    "3. Examples in Luau",
    "4. Limits",
    "5. Caching",
    "6. Response headers reference",
    "7. Status codes and what to do",
    "8. Good citizen checklist",
    "9. What Roxy will not do",
    "10. Privacy",
    "11. Security reports and bug bounty",
    "12. FAQ",
]

# Plan 4.1 row 8 (v1 headers plus the v2 additions), row 7 (Roxy-Refusal) and Retry-After.
ROXY_HEADERS = [
    "Roxy-Requests-Left",
    "Roxy-Throttle-Reset",
    "Roxy-Throttled",
    "Retry-After",
    "Roxy-Paused",
    "Roxy-Blocked",
    "Roxy-Endpoint-Limited",
    "Roxy-Global-Throttled",
    "Roxy-Client-Limited",
    "Roxy-Cache",
    "Roxy-Cache-Age",
    "Roxy-Cache-TTL",
    "Roxy-Upstream-Status",
    "Roxy-Upstream-Cooldown",
    "Roxy-Request-Id",
    "Roxy-Refusal",
]

# Plan 16.2 chapter 7, row by row (code, meaning).
STATUS_ROWS = [
    ("200 to 299", "Success (from Roblox or cache)"),
    ("400", "Bad request, or you sent authentication (not allowed)"),
    ("403", "Endpoint blocked by Roxy (`Roxy-Blocked`) or Roblox refused"),
    ("404", "Not found at Roblox, or not a supported Roblox URL"),
    ("413, 431", "Request too large"),
    ("429", "Rate limited by Roxy (your client) or Roblox is rate-limiting (`Roxy-Upstream-Cooldown`)"),
    ("500", "Unexpected Roxy error, or a Roblox 500 passed through (`Roxy-Upstream-Status: 500`)"),
    ("502", "Roxy could not connect to Roblox, or a Roblox 502 passed through"),
    ("504", "Roblox timed out, or the request hit Roxy's overall deadline"),
    ("503", "Roxy paused (`Roxy-Paused`), all upstream paths disabled, or too many identical requests were waiting"),
]


@pytest.fixture(scope="module")
def guide_text() -> str:
    return USER_GUIDE_PATH.read_text(encoding="utf-8")


def test_guide_follows_the_plan_outline(guide_text: str) -> None:
    chapters = re.findall(r"^## (.+)$", guide_text, flags=re.MULTILINE)
    assert chapters == OUTLINE
    guide = load_guide()
    assert guide is not None
    assert guide.title == "Roxy user guide"
    assert [entry.title for entry in guide.toc if entry.level == 2] == OUTLINE
    assert [entry.anchor for entry in guide.toc if entry.level == 2][:4] == [
        "1-what-roxy-does",
        "2-url-format",
        "3-examples-in-luau",
        "4-limits",
    ]


def test_guide_documents_every_roxy_header(guide_text: str) -> None:
    table = guide_text.split("## 6. Response headers reference", 1)[1].split("## 7.", 1)[0]
    for header in ROXY_HEADERS:
        assert f"| `{header}` |" in table, header


def test_guide_status_code_table_matches_the_plan(guide_text: str) -> None:
    for code, meaning in STATUS_ROWS:
        assert f"| {code} | {meaning}" in guide_text, code


def test_guide_has_the_luau_examples(guide_text: str) -> None:
    # The plan 16.2 example, rewritten as typed Luau (owner request 2026-10-07): RequestAsync inside pcall, and
    # Retry-After respected with a fallback and jitter.
    assert 'return HttpService:RequestAsync({ Url = url, Method = "GET" })' in guide_text
    assert 'tonumber(getHeader(headers, "Retry-After"))' in guide_text
    assert "math.random() * MAX_JITTER_SECONDS" in guide_text
    assert "HttpService:GetAsync(OUTFITS_URL)" in guide_text  # quick reads with GetAsync
    assert "HttpService:JSONEncode(request)" in guide_text  # POST batch lookup
    assert "HEADER_NAMES" in guide_text and '"Roxy-Requests-Left"' in guide_text  # reading Roxy headers
    assert "return RoxyClient" in guide_text  # the reusable module
    assert "require(ServerScriptService.RoxyClient)" in guide_text  # and how to use it
    assert guide_text.count("```luau\n--!strict\n") == 6
    assert "```lua\n" not in guide_text  # every Luau fence says luau, so it is highlighted as Luau


def test_guide_explains_strict_mode_and_const(guide_text: str) -> None:
    chapter = guide_text.split("## 3. Examples in Luau", 1)[1].split("### ", 1)[0]
    assert "`--!strict`" in chapter
    assert "`const`" in chapter and "can never be assigned again" in chapter
    assert "UPPER_SNAKE_CASE" in chapter
    assert "write `local` in its place" in chapter  # the way out for a Studio without const


def test_guide_says_every_request_counts_and_why(catalog_get: Callable[..., Getter]) -> None:
    """Owner change 2026-10-07 (D10 reversed): cache hits count toward the per-IP limit by default."""
    page = flat(rendered_guide(catalog_get()))
    limits = page.split('id="4-limits"', 1)[1].split('id="5-caching"', 1)[0]
    assert "Every request counts toward this limit, including requests Roxy answers from its cache" in limits
    assert "it still costs Roxy processing time and bandwidth" in limits
    assert "your own cache is the best way to stay under the limit" in limits
    assert "do not count" not in page


def test_guide_markers_are_all_known_and_settings_exist() -> None:
    guide = load_guide()
    assert guide is not None
    assert guide.unknown == ()
    assert set(guide.names) <= set(GUIDE_VALUES)
    # Every value computes from the real catalog (a renamed setting fails here, not on the live page).
    values = guide_values(lambda key: CATALOG[key].default)
    assert set(values) == set(GUIDE_VALUES)
    assert all(isinstance(value, str) and value for value in values.values())


def test_guide_renders_live_values(catalog_get: Callable[..., Callable[[str], Any]]) -> None:
    guide = load_guide()
    assert guide is not None
    get = catalog_get(allowed_requests_per_minute=25, throttle_reset_duration=75, flood_limit_per_minute=1234)
    page = str(guide.html(guide_values(get, guide.names)))
    assert "<strong>25 requests every 75 seconds</strong>" in page
    assert "one more request becomes available every 3 seconds" in page
    assert "flood limit of 1,234 requests per minute" in page
    assert "{{" not in page
    assert_style_clean(page, "rendered guide")


def test_guide_values_are_escaped(catalog_get: Callable[..., Callable[[str], Any]]) -> None:
    rendered = render_guide("Ask {{ contact_name }}.")
    page = str(rendered.html(guide_values(catalog_get(site_contact_name='<img src=x onerror="y">'))))
    assert "<img" not in page
    assert "&lt;img src=x onerror=&quot;y&quot;&gt;" in page


def test_raw_html_in_markdown_is_escaped() -> None:
    rendered = render_guide('# T\n\n<script>alert(1)</script>\n\n<div style="x">y</div>\n')
    body = rendered.html({})
    assert "<script>" not in body
    assert "&lt;script&gt;" in body
    assert "<div" not in body


def test_no_typographer_dashes_and_no_style_attributes() -> None:
    rendered = render_guide('# T\n\nA -- B --- C "quoted"\n\n| a | b | c |\n|:--|:-:|--:|\n| 1 | 2 | 3 |\n')
    body = str(rendered.html({}))
    assert "A -- B --- C" in body
    assert_style_clean(body, "typographer check")
    assert "style=" not in body
    assert '<th class="align-left">a</th>' in body
    assert '<td class="align-center">2</td>' in body
    assert '<td class="align-right">3</td>' in body


def test_luau_fences_are_highlighted_and_escaped() -> None:
    hostile = 'local x = "</code></pre><script>alert(1)</script>" -- <img src=x onerror=y>'
    rendered = render_guide(f"# T\n\n```luau\n{hostile}\n```\n\n```lua\nprint(1)\n```\n\n```text\nlocal y = 1\n```\n")
    body = str(rendered.html({}))
    assert '<pre><code class="language-luau hl"><span class="k">local</span> x <span class="o">=</span>' in body
    assert '<span class="s">"&lt;/code&gt;&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;"</span>' in body
    assert '<span class="c">-- &lt;img src=x onerror=y&gt;</span>' in body
    assert "<script>" not in body and "<img" not in body
    assert '<pre><code class="language-lua hl"><span class="b">print</span>(<span class="n">1</span>)' in body
    assert '<pre><code class="language-text">local y = 1\n</code></pre>' in body  # other fences stay plain
    assert_style_clean(body, "highlighted fences")


def test_every_guide_example_is_highlighted(catalog_get: Callable[..., Getter]) -> None:
    page = rendered_guide(catalog_get())
    assert page.count('<pre><code class="language-luau hl">') == 6
    assert '<span class="k">const</span> <span class="b">HttpService</span>' in page
    assert "style=" not in page


def test_headings_get_unique_ids_and_anchor_links() -> None:
    rendered = render_guide("# Title\n\n## Same\n\n### Same\n\n## Other `code`\n")
    body = str(rendered.html({}))
    assert '<h1 id="title">Title</h1>' in body  # the page title has no anchor link
    assert '<h2 id="same">Same</h2><a class="anchor" href="#same"' in body
    assert '<h3 id="same-2">Same</h3><a class="anchor" href="#same-2"' in body
    assert 'aria-label="Link to this section: Other code"' in body
    assert [(entry.level, entry.anchor) for entry in rendered.toc] == [(2, "same"), (3, "same-2"), (2, "other-code")]


class _HeadingNames(HTMLParser):
    """The text a screen reader announces for each h2 and h3, and any link found inside one."""

    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=True)
        self.names: list[str] = []
        self.links_inside: list[str] = []
        self._open: str | None = None
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("h2", "h3"):
            self._open = tag
            self.names.append("")
        elif tag == "a" and self._open:
            self.links_inside.append(dict(attrs).get("href") or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == self._open:
            self._open = None

    def handle_data(self, data: str) -> None:
        if self._open:
            self.names[-1] += data


def test_heading_names_are_just_their_titles(catalog_get: Callable[..., Getter]) -> None:
    """The section link sits next to the heading, so a screen reader hears "4. Limits", not the title twice."""
    page = rendered_guide(catalog_get())
    headings = _HeadingNames(page)
    assert headings.links_inside == []
    assert "4. Limits" in headings.names
    assert '</h2><a class="anchor" href="#4-limits" aria-label="Link to this section: 4. Limits">#</a>' in page


def test_unknown_markers_are_reported_and_left_visible() -> None:
    rendered = render_guide("Value {{ no_such_value }} and {{ contact_name }}.")
    assert rendered.unknown == ("no_such_value",)
    assert rendered.names == ("contact_name",)
    assert "{{ no_such_value }}" in str(rendered.html({"contact_name": "x"}))


def test_javascript_links_are_not_rendered() -> None:
    body = str(render_guide("[x](javascript:alert(1)) [y](https://example.com)").html({}))
    assert "javascript:" not in body.split("[x]")[0]
    assert 'href="javascript' not in body
    assert '<a href="https://example.com">y</a>' in body


def test_slugify() -> None:
    assert slugify("4. Limits") == "4-limits"
    assert slugify("12. FAQ") == "12-faq"
    assert slugify("Is Roxy free?") == "is-roxy-free"
    assert slugify("???") == "section"


def test_guide_source_passes_the_style_check(guide_text: str) -> None:
    assert_style_clean(guide_text, str(USER_GUIDE_PATH))


# --- statements that must follow the live settings (review findings 4, 11 and 12) ---------------------------------


def rendered_guide(get: Getter) -> str:
    guide = load_guide()
    assert guide is not None
    return str(guide.html(guide_values(get, guide.names)))


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_guide_follows_the_cors_setting(catalog_get: Callable[..., Getter]) -> None:
    closed = flat(rendered_guide(catalog_get()))
    opened = flat(rendered_guide(catalog_get(public_cors_allow_any_origin=1)))
    assert "Roxy sends no CORS headers" in closed
    assert "<strong>No browser use from other websites.</strong>" in closed
    assert "Roxy sends no CORS headers" not in opened
    assert "No browser use from other websites" not in opened
    assert "<code>Access-Control-Allow-Origin: *</code>" in opened


def test_guide_follows_the_place_limit_key(catalog_get: Callable[..., Getter]) -> None:
    per_network = flat(rendered_guide(catalog_get(place_limit_enabled=1)))  # place_prefix, the default
    shared = flat(rendered_guide(catalog_get(place_limit_enabled=1, place_limit_key="place")))
    assert "counted for each network its servers use" in per_network
    assert "counted for each network" not in shared
    assert "shared by all of its servers" in shared


def test_guide_counts_of_one_read_as_singular(catalog_get: Callable[..., Getter]) -> None:
    page = flat(
        rendered_guide(
            catalog_get(
                allowed_requests_per_minute=1,
                throttle_reset_duration=1,
                global_throttle_limit=1,
                global_throttle_period=1,
                throttle_strike_decay_seconds=60,
                cache_ttl_seconds=1,
                cache_stale_seconds=1,
                retention_client_minute_days=1,
                retention_events_days=1,
                request_sample_hours=1,
                capture_ttl_seconds=60,
            )
        )
    )
    assert not re.search(r"\b1 (requests|seconds|minutes|hours|days)\b", page), re.findall(r"\b1 \w+", page)
    assert "<strong>1 request every 1 second</strong>" in page
    assert "(1 request per 1 second per IP address while it is on)" in page
    # The default emergency limit is 1: the reviewer saw "1 requests per 60 seconds".
    assert "(1 request per 60 seconds per IP address" in flat(rendered_guide(catalog_get()))


def test_guide_says_when_strikes_never_fade(catalog_get: Callable[..., Getter]) -> None:
    fading = flat(rendered_guide(catalog_get(throttle_strike_decay_seconds=1800)))
    never = flat(rendered_guide(catalog_get(throttle_strike_decay_seconds=0)))
    assert "one strike fades after 30 minutes without a new one" in fading
    assert "fades after 0" not in never
    assert "Strikes do not fade on their own right now" in never


def test_guide_links_to_status_only_while_it_is_enabled(catalog_get: Callable[..., Getter]) -> None:
    enabled = rendered_guide(catalog_get())
    disabled = rendered_guide(catalog_get(public_status_page_enabled=0))
    assert enabled.count('href="/status"') == 2
    assert 'href="/status"' not in disabled
    assert "status page" not in disabled
    assert "<code>/health</code>" in disabled  # the monitor JSON stays the way to check


def test_guide_describes_refusal_bodies_as_json_strings(guide_text: str) -> None:
    # LEAD_NOTES decision 2: refusals are a JSON string plus a newline, sent as application/json.
    assert "plain text body" not in guide_text
    assert "a JSON string" in guide_text
    assert '`"Too many requests; please slow down."`' in guide_text


def test_guide_does_not_state_the_editable_cache_bust_list_as_fixed(guide_text: str) -> None:
    # The ignored parameters are an admin-editable table, so the guide names the built-in ones as defaults.
    paragraph = guide_text.split("Adding a random parameter", 1)[1].split("\n\n", 1)[0]
    assert "by default" in paragraph


# --- finding the guide wherever roxy is installed (review finding 1) ----------------------------------------------


def test_find_user_guide_takes_the_nearest_copy(tmp_path: Path) -> None:
    package = tmp_path / "release" / ".venv" / "lib" / "python3.12" / "site-packages" / "roxy"
    package.mkdir(parents=True)
    assert pages.find_user_guide(package) is None
    release_copy = tmp_path / "release" / "docs" / "USER_GUIDE.md"
    release_copy.parent.mkdir(parents=True)
    release_copy.write_text("# Guide\n", encoding="utf-8")
    assert pages.find_user_guide(package) == release_copy
    packaged = package / "docs" / "USER_GUIDE.md"  # a wheel that force-includes the guide wins
    packaged.parent.mkdir()
    packaged.write_text("# Guide\n", encoding="utf-8")
    assert pages.find_user_guide(package) == packaged


def test_find_user_guide_stops_above_the_release(tmp_path: Path) -> None:
    far = tmp_path / "docs" / "USER_GUIDE.md"
    far.parent.mkdir()
    far.write_text("# Not this one\n", encoding="utf-8")
    package = tmp_path / "a" / "b" / "c" / "d" / "e" / "f" / "roxy"
    package.mkdir(parents=True)
    assert pages.find_user_guide(package) is None


def test_guide_is_found_in_a_release_installed_without_editable_mode(tmp_path: Path) -> None:
    """deploy/deploy.sh runs `uv sync --no-editable`, so the package lives under .venv, far from docs/."""
    release = tmp_path / "release"
    site = release / ".venv" / "lib" / "python3.12" / "site-packages"
    source = Path(pages.__file__).resolve().parents[1]
    shutil.copytree(source, site / "roxy", ignore=shutil.ignore_patterns("__pycache__", "static"))
    (release / "docs").mkdir()
    shutil.copyfile(USER_GUIDE_PATH, release / "docs" / "USER_GUIDE.md")  # `git archive` ships docs/
    probe = textwrap.dedent(
        """
        import sys
        sys.path.insert(0, sys.argv[1])
        import roxy.public.pages as pages
        assert pages.__file__.startswith(sys.argv[1]), pages.__file__
        guide = pages.load_guide()
        print(pages.USER_GUIDE_PATH)
        print("rendered" if guide is not None and guide.toc else "missing")
        """
    )
    result = subprocess.run(  # a separate interpreter, so this test's own import of roxy cannot answer for it
        [sys.executable, "-I", "-c", probe, str(site)],
        cwd=release,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    path, state = result.stdout.split()[-2:]
    assert path == str(release / "docs" / "USER_GUIDE.md")
    assert state == "rendered"
