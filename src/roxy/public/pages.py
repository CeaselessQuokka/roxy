"""Public pages: the home page, the user guide, the status page, robots.txt, sitemap.xml and the favicon.

What this is
    `router`, with every public route except `/health` (`public/health.py`) and `/csp-report`
    (`public/csp_report.py`): `/` (home), `/docs` (`docs/USER_GUIDE.md` rendered to HTML), `/status` (coarse public
    state), `/robots.txt`, `/sitemap.xml` and `/favicon.ico` (plan 16.1, parity rows 12, 13 and 19). Each answers
    GET and HEAD. Also the small pure helpers the routes are built from, so tests can call them directly:
    `render_site_text`, `find_user_guide`, `render_guide`, `home_examples`, `code_block`, `live_limits`,
    `count_text`, `parse_pause_state`, `classify_hour`, `read_rate_limited` and `build_sitemap`.

Why it exists
    v1's home page hard-coded "10 requests every 50 seconds" and "made using Python and Flask", and both drifted
    from the truth. Here every limit a visitor reads is rendered from the live settings on each request, and the
    texts that name people, prices and hosting facts are `site_*` settings (owner decision D18). The SEO head of
    the home page (title, the three descriptions, keywords, canonical link, Open Graph and Twitter tags and the
    JSON-LD block) is kept exactly as v1 had it, because search engines and link previews already know it.
    The status page answers "is it Roxy or is it me?" for game developers while revealing nothing an attacker
    could use: four coarse states, a 24 hour bar of hourly states, and plain-language notes, with no counts and
    no IP addresses (plan 16.1).

How it works
    - Settings: each request takes one immutable snapshot of the runtime settings (`ctx.settings.snapshot()`),
      so every number on a page comes from the same moment; before the lifespan has built the context the
      catalog defaults are used. Counts are worded through `count_text`, so a limit of 1 reads "1 request".
    - Site text (`site_*`): plain text, blank lines separate paragraphs, and `[label](https://...)` becomes a
      link only for https URLs. Everything else is HTML-escaped, so an admin typing `<script>` sees it printed,
      never run (plan 9.16).
    - The guide: `find_user_guide` looks for `docs/USER_GUIDE.md` in the nearest directory at or above the roxy
      package, which covers a source checkout and a release installed with `uv sync --no-editable` (the package
      then sits in `<release>/.venv/lib/python3.12/site-packages`). The router's lifespan refuses to start a
      worker without it, so a release missing the guide fails the deploy health gate instead of answering 404.
      It is rendered once per file version with markdown-it (CommonMark plus tables, raw HTML disabled, so any
      HTML in the file is escaped, and "smart" typography disabled, so `--` can never turn into a dash character
      that rule C5 bans). Each h2 and h3 gets an id and, next to it (outside the heading, so a screen reader
      announces the title once), a section link; they also feed the sticky table of contents. Table alignment
      becomes CSS classes instead of inline `style` attributes (the CSP allows no inline styles). ```lua and
      ```luau fences are colored on the server by `roxy/public/luau_highlight.py` (escaped text in spans with
      one-letter classes; no script and no inline style needed). Live values are
      written in the file as `{{ name }}`; the rendered HTML is split at those markers once, and each request only
      joins the parts with values from `GUIDE_VALUES`: plain values are escaped, and the few sentences that need a
      link or code formatting are `Markup` built here with every setting value escaped inside.
    - Home examples: the Luau snippets on `/` live in `templates/public/examples/*.luau` (the guide repeats each one
      word for word, and tests type check them with luau-analyze); `home_examples` highlights them once per
      process, at startup.
    - Status: pause and scheduled maintenance come from control.db `service_state` (key `pause`), parsed by
      `roxy.abuse.pause.PauseState`, the same rule the proxy's pause check uses; recent failures and the hourly
      bar from the metrics rollups; and "Roblox is rate limiting" from active hot.db `cooldown` rows that Roblox's
      429 answers opened on a caller path (direct or rotator), matched with `roxy.upstream.cooldowns`' own key
      builders. Shared state that cannot be read shows as degraded (plan C7). The result is cached per worker for
      `STATUS_CACHE_S` seconds, so a crowd refreshing `/status` costs one set of reads.
    - Visits: GET requests to a page call `ctx.recorder.record_visit(page, user_agent)` when the recorder has
      that method; the recorder classifies the visitor itself (`roxy/metrics/visitors.py`, parity row 19).
      robots.txt and sitemap.xml also call `record_crawl(client_ip, path, user_agent)` (the v1 crawl log). HEAD
      requests are not visits (monitors use them). A recorder that raises never breaks a page.
    - robots.txt is served byte for byte from v1 (kept as `templates/public/robots.txt`); sitemap.xml keeps
      v1's bytes for `/` and adds `/docs` and `/status` (only while that page is enabled), with `lastmod` set to
      the build date: the newest modification time of the public templates, assets, this module and the guide,
      which is the install time of a release.

What to read next
    `roxy/templates/public/base.html` (the page shell and its nonce script tag), `docs/USER_GUIDE.md`,
    `roxy/public/luau_highlight.py`, `roxy/public/csp_report.py`, then `roxy/core/templating.py` and
    `roxy/core/security_headers.py`.
"""

from __future__ import annotations

import asyncio
import functools
import html
import inspect
import json
import logging
import re
import sqlite3
import threading
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response
from markdown_it import MarkdownIt
from markdown_it.renderer import RendererHTML
from markdown_it.token import Token
from markupsafe import Markup

from roxy.abuse.pause import PauseState
from roxy.core.reasons import Egress
from roxy.core.scope import catalog_default
from roxy.core.templating import STATIC_DIR, TEMPLATES_DIR, Templates
from roxy.public.luau_highlight import SCOPE_CLASS, highlight
from roxy.upstream.cooldowns import CooldownSource, egress_key, endpoint_key, host_key

log = logging.getLogger("roxy.public.pages")

# --- where things are ---------------------------------------------------------------------------------------------

PACKAGE_DIR: Final = Path(__file__).resolve().parents[1]
"""The installed `roxy` package: `<repo>/src/roxy` in a checkout, `.../site-packages/roxy` in a release."""
GUIDE_RELATIVE_PATH: Final = Path("docs") / "USER_GUIDE.md"
GUIDE_SEARCH_PARENTS: Final = 5
"""How far above the package `find_user_guide` looks: far enough for `<release>/.venv/lib/python3.12/
site-packages/roxy` (the release is the 5th parent), and no further, so an unrelated file higher up is never used."""


def find_user_guide(package_dir: Path = PACKAGE_DIR) -> Path | None:
    """`docs/USER_GUIDE.md` in the nearest directory at or above the roxy package, or None when there is none.

    The nearest copy wins: a copy packaged inside the wheel (`roxy/docs/USER_GUIDE.md`, if a build ever adds one),
    then `<repo>/docs` for a source checkout or editable install (2 levels up), then `<release>/docs` for a release
    that deploy/deploy.sh installed with `uv sync --no-editable` (5 levels up; `git archive` ships `docs/`).
    """
    for directory in (package_dir, *package_dir.parents[:GUIDE_SEARCH_PARENTS]):
        candidate = directory / GUIDE_RELATIVE_PATH
        if candidate.is_file():
            return candidate
    return None


USER_GUIDE_PATH: Final = find_user_guide() or PACKAGE_DIR.parents[1] / GUIDE_RELATIVE_PATH
"""The guide this process serves. When no copy exists it names where a checkout would keep it, and
`require_user_guide` refuses to start the worker."""
PUBLIC_TEMPLATES_DIR: Final = TEMPLATES_DIR / "public"
PUBLIC_STATIC_DIR: Final = STATIC_DIR / "public"
FAVICON_PATH: Final = PUBLIC_STATIC_DIR / "roxy_favicon.png"
ROBOTS_PATH: Final = PUBLIC_TEMPLATES_DIR / "robots.txt"
HOME_EXAMPLES_DIR: Final = PUBLIC_TEMPLATES_DIR / "examples"
"""The home page's Luau snippets, one `.luau` file each, so they can be type checked as they are (the guide repeats
each one word for word; tests/unit/public/test_luau_examples.py checks both)."""
HOME_EXAMPLE_NAMES: Final = ("get_async", "request_async", "post_batch")

CANONICAL_ORIGIN: Final = "https://roxytheproxy.com"
"""The production origin in canonical links, Open Graph URLs and the sitemap. Fixed on purpose (SEO parity): a
staging copy must still point search engines at the real site, never at itself."""

# Page names given to the metrics recorder (`record_visit(page, user_agent)`; `roxy.metrics.visitors.PAGES`).
PAGE_HOME: Final = "home"
PAGE_DOCS: Final = "docs"
PAGE_STATUS: Final = "status"
PAGE_ROBOTS: Final = "robots"
PAGE_SITEMAP: Final = "sitemap"

# HTML pages carry live values, so browsers revalidate instead of showing yesterday's limits.
PAGE_CACHE_CONTROL: Final = "no-cache"
# The favicon changes once in years; a day of browser caching saves a download on every visit.
FAVICON_CACHE_CONTROL: Final = "public, max-age=86400"

MAX_RECORDED_UA: Final = 512
"""Characters of User-Agent passed to the recorder (bounds memory per visit, plan P9)."""

Getter = Callable[[str], Any]


# --- settings -----------------------------------------------------------------------------------------------------


def settings_getter(request: Request) -> Getter:
    """A lookup over ONE settings snapshot for this request, falling back to the catalog defaults.

    The snapshot is immutable, so a page never mixes values from before and after a settings change. Before the
    lifespan has built the context (or in a bare test app) every key reads as its catalog default.
    """
    ctx = getattr(request.app.state, "ctx", None)
    settings = getattr(ctx, "settings", None)
    snapshot: Mapping[str, Any] | None = None
    if settings is not None:
        try:
            snapshot = settings.snapshot()
        except Exception:  # a settings store in trouble must not take the public pages down with it
            log.warning("public_settings_snapshot_failed", exc_info=True)

    def get(key: str) -> Any:
        if snapshot is not None and key in snapshot:
            return snapshot[key]
        value = catalog_default(key)
        if value is None:
            raise KeyError(key)
        return value

    return get


def _int(value: Any) -> int:
    return int(value)


def fmt_int(value: Any) -> str:
    """`12345` -> `12,345` (thousands separators read better on a page)."""
    return f"{_int(value):,}"


def fmt_number(value: float) -> str:
    """A short decimal without trailing zeros: 5.0 -> `5`, 2.5 -> `2.5`, 0.25 -> `0.25`."""
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return text or "0"


def with_unit(number: str, singular: str, plural: str | None = None) -> str:
    """`"1", "second"` -> `1 second`; any other number takes the plural (`0 seconds`, `2.5 seconds`)."""
    return f"{number} {singular if number == '1' else (plural or singular + 's')}"


def count_text(value: Any, singular: str, plural: str | None = None) -> str:
    """A whole number with its noun: `count_text(1, "request")` -> `1 request`, 1500 -> `1,500 requests`."""
    return with_unit(fmt_int(value), singular, plural)


@dataclass(frozen=True, slots=True)
class LiveLimits:
    """The caller limits as a visitor should read them, built from one settings snapshot."""

    requests_per_window: int
    window_seconds: int
    flood_per_minute: int
    smooth_pacing: bool
    cache_hits_count: bool
    place_limit_enabled: bool
    place_limit_per_minute: int
    place_limit_per_network: bool
    ipv6_prefix: int

    @property
    def requests_text(self) -> str:
        return count_text(self.requests_per_window, "request")

    @property
    def window_text(self) -> str:
        return count_text(self.window_seconds, "second")

    @property
    def flood_text(self) -> str:
        return count_text(self.flood_per_minute, "request")

    @property
    def place_text(self) -> str:
        return count_text(self.place_limit_per_minute, "request")

    @property
    def pace_seconds(self) -> str:
        """Seconds between new requests after a burst, in smooth pacing (gcra) mode: window / limit."""
        return fmt_number(self.window_seconds / max(1, self.requests_per_window))

    @property
    def pacing_rule(self) -> str:
        """One sentence explaining how the window refills, for the active `throttle_window_mode`."""
        if self.smooth_pacing:
            return (
                "You can send them all at once; after that, one more request becomes available every "
                f"{with_unit(self.pace_seconds, 'second')}."
            )
        return (
            f"The window opens on your first request and closes {self.window_text} later, "
            "and then your full allowance starts over."
        )

    @property
    def cache_hits_rule(self) -> str:
        """Whether cache hits use up the per-IP allowance (`throttle_count_cache_hits`, owner decision D10).

        The owner changed the default to "count" on 2026-10-07: a cached answer costs Roblox nothing, but serving
        it still costs Roxy, so the sentence says why. The other wording stays for an admin who turns it off.
        """
        if self.cache_hits_count:
            return (
                "Every request counts toward this limit, including requests Roxy answers from its cache: a cached "
                "answer costs Roblox nothing, but it still costs Roxy processing time and bandwidth."
            )
        return (
            "Requests Roxy answers from its cache do not count toward this limit right now, because they cost "
            "Roblox nothing; they still count toward the flood limit."
        )

    @property
    def place_limit_scope(self) -> str:
        """Who shares one experience's budget, for the active `place_limit_key`."""
        if self.place_limit_per_network:  # place_prefix: one budget per place id and caller network
            return "counted for each network its servers use"
        return "shared by all of its servers"  # place: one budget per place id

    @property
    def place_limit_rule(self) -> str:
        """One sentence about the per-experience limit (owner decision D11: measured, enforced only when on)."""
        if self.place_limit_enabled:
            return (
                f"Each experience may also send at most {self.place_text} per minute through Roxy, "
                f"{self.place_limit_scope}."
            )
        return (
            "Roxy also measures traffic per experience, but the per-experience limit is currently off, so only the "
            "per-IP limits apply."
        )

    @property
    def ipv6_rule(self) -> str:
        """One sentence about how IPv6 addresses are grouped into one client (`ipv6_limit_prefix`)."""
        if self.ipv6_prefix >= 128:
            return "Each IPv6 address counts as its own client."
        return (
            f"IPv6 addresses that share their first {self.ipv6_prefix} bits count as one client, because one "
            "connection usually owns a whole block of addresses."
        )


def live_limits(get: Getter) -> LiveLimits:
    """The caller limits from the live settings (plan 16.1 "limits at a glance", 16.2 chapter 4)."""
    return LiveLimits(
        requests_per_window=_int(get("allowed_requests_per_minute")),
        window_seconds=_int(get("throttle_reset_duration")),
        flood_per_minute=_int(get("flood_limit_per_minute")),
        smooth_pacing=str(get("throttle_window_mode")) == "gcra",
        cache_hits_count=bool(get("throttle_count_cache_hits")),
        place_limit_enabled=bool(get("place_limit_enabled")),
        place_limit_per_minute=_int(get("place_limit_per_minute")),
        place_limit_per_network=str(get("place_limit_key")) == "place_prefix",
        ipv6_prefix=_int(get("ipv6_limit_prefix")),
    )


def _on_off(value: Any) -> str:
    return "on" if bool(value) else "off"


def _minutes_text(seconds: Any) -> str:
    return with_unit(fmt_number(_int(seconds) / 60), "minute")


def strike_decay_rule(get: Getter) -> str:
    """How strikes fade (`throttle_strike_decay_seconds`; 0 means they never fade on their own)."""
    seconds = _int(get("throttle_strike_decay_seconds"))
    if seconds <= 0:
        return "Strikes do not fade on their own right now; only Roxy's admin can forgive them."
    return f"Good behavior forgives strikes: one strike fades after {_minutes_text(seconds)} without a new one."


def cors_rule_item(get: Getter) -> str:
    """Chapter 9's CORS bullet (`public_cors_allow_any_origin`, owner decision D20)."""
    if bool(get("public_cors_allow_any_origin")):
        return Markup(
            "<strong>Browser use from other websites is allowed for now.</strong> Roxy currently sends "
            "<code>Access-Control-Allow-Origin: *</code> on answers to <code>GET</code> and <code>HEAD</code>, so "
            "web pages on any site can read them from their visitors' browsers. Each visitor counts as its own "
            "client against the limits in chapter 4."
        )
    return Markup(
        "<strong>No browser use from other websites.</strong> Roxy sends no CORS headers, so web pages on other "
        "sites cannot read its answers. Game servers and server-side scripts are not affected."
    )


def cors_faq(get: Getter) -> str:
    """The answer to "Can I call Roxy from a website?" for the current CORS setting."""
    if bool(get("public_cors_allow_any_origin")):
        return Markup(
            "Yes, for <code>GET</code> and <code>HEAD</code> requests, while Roxy sends "
            "<code>Access-Control-Allow-Origin: *</code> (it does right now). A server you run can always call it "
            "like a game server does."
        )
    return Markup(
        "Not from a visitor's browser: Roxy sends no CORS headers. A server you run can call it like a game server "
        "does."
    )


def status_tip(get: Getter) -> str:
    """The good citizen checklist's last bullet: points at /status only while that page exists."""
    if bool(get("public_status_page_enabled")):
        return Markup('Check the <a href="/status">status page</a> before assuming your script is broken.')
    return Markup(
        "Before assuming your script is broken, check whether <code>/health</code> answers and whether other games "
        "see the same errors."
    )


def status_faq(get: Getter) -> str:
    """The answer to "How do I know whether Roxy is down?"."""
    health = "Monitors can poll <code>/health</code>, which answers with JSON."
    if bool(get("public_status_page_enabled")):
        return Markup(f'Open the <a href="/status">status page</a>. {health}')  # noqa: S704 (constant text only)
    return Markup(health)  # noqa: S704 (constant text only)


GUIDE_VALUES: Final[dict[str, Callable[[Getter], str]]] = {
    # Limits (chapter 4).
    "window_requests": lambda g: count_text(g("allowed_requests_per_minute"), "request"),
    "window_length": lambda g: count_text(g("throttle_reset_duration"), "second"),
    "pacing_rule": lambda g: live_limits(g).pacing_rule,
    "cache_hits_rule": lambda g: live_limits(g).cache_hits_rule,
    "flood_requests": lambda g: count_text(g("flood_limit_per_minute"), "request"),
    "ipv6_rule": lambda g: live_limits(g).ipv6_rule,
    "place_limit_rule": lambda g: live_limits(g).place_limit_rule,
    "strike_decay_rule": strike_decay_rule,
    "emergency_requests": lambda g: count_text(g("global_throttle_limit"), "request"),
    "emergency_period": lambda g: count_text(g("global_throttle_period"), "second"),
    # Caching (chapter 5).
    "cache_state": lambda g: _on_off(g("cache_enabled")),
    "cache_ttl": lambda g: count_text(g("cache_ttl_seconds"), "second"),
    "cache_stale": lambda g: count_text(g("cache_stale_seconds"), "second"),
    # Requests (chapters 2 and 7).
    "max_body_kib": lambda g: fmt_int(_int(g("max_body_bytes")) // 1024),
    "request_deadline": lambda g: count_text(g("request_deadline_s"), "second"),
    # What Roxy will not do and the checklist (chapters 8 and 9).
    "cors_rule_item": cors_rule_item,
    "status_tip": status_tip,
    # Privacy (chapter 10).
    "client_minute_retention": lambda g: count_text(g("retention_client_minute_days"), "day"),
    "client_hour_retention": lambda g: count_text(g("retention_client_hour_days"), "day"),
    "client_day_retention": lambda g: count_text(g("retention_client_day_days"), "day"),
    "events_retention": lambda g: count_text(g("retention_events_days"), "day"),
    "request_sample_retention": lambda g: count_text(g("request_sample_hours"), "hour"),
    "capture_state": lambda g: _on_off(g("capture_enabled")),
    "capture_retention": lambda g: _minutes_text(g("capture_ttl_seconds")),
    "capture_sample_pct": lambda g: fmt_number(float(g("capture_sample_served_pct"))),
    # Contact and FAQ (chapters 11 and 12).
    "contact_name": lambda g: str(g("site_contact_name")),
    "cors_faq": cors_faq,
    "status_faq": status_faq,
}
"""Every `{{ name }}` the user guide may use, and how to compute it from the settings. Plain values are escaped
when inserted, so a setting can never inject markup into the page; the few values that need a link or code
formatting return `Markup` built from constant text in this module (no setting value goes into them unescaped)."""


# --- visitors -----------------------------------------------------------------------------------------------------

_recorder_warned: set[str] = set()


async def _call_recorder(method_name: str, request: Request, arguments: tuple[Any, ...]) -> None:
    """Call `ctx.recorder.<method_name>(*arguments)` if the recorder has it; never let it break the page.

    Until the recorder exists, or if it does not offer the method, nothing happens. Its methods may be plain or
    async; any exception is logged once per method and swallowed, because counting a visit is never worth
    failing the visit.
    """
    ctx = getattr(request.app.state, "ctx", None)
    recorder = getattr(ctx, "recorder", None)
    method = getattr(recorder, method_name, None) if recorder is not None else None
    if method is None:
        return
    try:
        result = method(*arguments)
        if inspect.isawaitable(result):
            await result
    except Exception:
        if method_name not in _recorder_warned:
            _recorder_warned.add(method_name)
            log.warning("public_recorder_call_failed", extra={"fields": {"method": method_name}}, exc_info=True)


def _client_ip(request: Request) -> str:
    ip = getattr(request.state, "client_ip", None)
    if isinstance(ip, str) and ip:
        return ip
    return request.client.host if request.client else "unknown"


def _user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:MAX_RECORDED_UA]


async def record_visit(request: Request, page: str) -> None:
    """Count a page visit (GET only: HEAD is a monitor checking the page, not a visit). The recorder classifies
    the visitor from the User-Agent (human, crawler, or unknown for an empty one; parity row 19)."""
    if request.method != "GET":
        return
    await _call_recorder("record_visit", request, (page, _user_agent(request)))


async def record_crawl(request: Request) -> None:
    """Log a crawler file fetch per client IP, like v1's `log_crawl`: `record_crawl(ip, path, user_agent)`."""
    if request.method != "GET":
        return
    await _call_recorder("record_crawl", request, (_client_ip(request), request.url.path, _user_agent(request)))


# --- site text (site_* settings) ----------------------------------------------------------------------------------

_PARAGRAPH_BREAK = re.compile(r"\n[ \t]*\n+")
# `[label](https://...)`: the label may contain parentheses (v1's plugin link does), never brackets or newlines.
_SITE_LINK = re.compile(r"\[([^\[\]\n]{1,300})\]\(([^\s()<>\[\]\"']{1,2000})\)")


def is_https_url(url: str) -> bool:
    """True for an absolute https URL with a host and no `user:password@` part."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme == "https" and bool(parts.hostname) and "@" not in parts.netloc


def _render_inline_site_text(text: str) -> str:
    out: list[str] = []
    position = 0
    for match in _SITE_LINK.finditer(text):
        out.append(html.escape(text[position : match.start()], quote=False))
        label, url = match.group(1), match.group(2)
        if is_https_url(url):
            out.append(f'<a href="{html.escape(url, quote=True)}">{html.escape(label, quote=False)}</a>')
        else:
            out.append(html.escape(match.group(0), quote=False))  # not https: shown as typed, never a link
        position = match.end()
    out.append(html.escape(text[position:], quote=False))
    return "".join(out)


def render_site_text(text: str, *, inline: bool = False) -> Markup:
    """Render a `site_*` value: escaped text, paragraphs at blank lines, https `[label](url)` links.

    `inline=True` joins paragraphs with line breaks instead of `<p>` elements (for the footer line).
    """
    normalized = str(text).replace("\r\n", "\n").replace("\r", "\n")
    paragraphs = [part.strip() for part in _PARAGRAPH_BREAK.split(normalized)]
    rendered = [_render_inline_site_text(part) for part in paragraphs if part]
    if inline:
        return Markup("<br>".join(rendered))  # noqa: S704 (every piece was escaped by _render_inline_site_text)
    return Markup("".join(f"<p>{part}</p>" for part in rendered))  # noqa: S704 (escaped above)


# --- the user guide -----------------------------------------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\{\{\s*([a-z][a-z0-9_]*)\s*\}\}")
_SLUG_DROP = re.compile(r"[^a-z0-9\s-]")
_SLUG_SPACE = re.compile(r"[\s-]+")
_ALIGN_STYLE = re.compile(r"^text-align:\s*(left|center|right)$")


@dataclass(frozen=True, slots=True)
class TocEntry:
    """One line of the table of contents: heading level (2 or 3), anchor id and plain title."""

    level: int
    anchor: str
    title: str


@dataclass(frozen=True, slots=True)
class RenderedGuide:
    """The guide rendered once: static HTML parts around `{{ name }}` markers, plus its contents table."""

    title: str
    parts: tuple[str, ...]
    names: tuple[str, ...]
    toc: tuple[TocEntry, ...]
    unknown: tuple[str, ...]  # markers with no entry in GUIDE_VALUES (left as text; a test keeps this empty)

    def html(self, values: Mapping[str, str]) -> Markup:
        """The page body with every marker replaced by its live value: plain text escaped, `Markup` as built."""
        out = [self.parts[0]]
        for name, part in zip(self.names, self.parts[1:], strict=True):
            value = values.get(name, "")
            # Markup only comes from the GUIDE_VALUES functions in this module (constant markup, escaped values).
            out.append(str(value) if isinstance(value, Markup) else html.escape(value, quote=True))
            out.append(part)
        return Markup("".join(out))  # noqa: S704 (markdown-it escaped the file; values escaped above)


def slugify(text: str) -> str:
    """`4. Limits` -> `4-limits`: lowercase ASCII letters, digits and single hyphens."""
    slug = _SLUG_SPACE.sub("-", _SLUG_DROP.sub("", text.lower())).strip("-")
    return slug or "section"


def _plain_text(inline: Token) -> str:
    return "".join(child.content for child in (inline.children or []) if child.type in ("text", "code_inline"))


HIGHLIGHTED_LANGUAGES: Final = frozenset({"lua", "luau"})
"""Fence languages rendered with Luau highlighting (```lua and ```luau); every other fence stays plain text."""


def code_block(code: str, language: str) -> Markup:
    """A highlighted Luau block: `<pre><code class="language-luau hl">` around `luau_highlight.highlight`.

    `language` must be one of `HIGHLIGHTED_LANGUAGES` (a constant, so it needs no escaping); the code is escaped
    by the highlighter piece by piece.
    """
    if language not in HIGHLIGHTED_LANGUAGES:
        raise ValueError(f"not a highlighted language: {language!r}")
    return Markup(  # noqa: S704 (constant markup around highlight(), which escapes every piece of the code)
        f'<pre><code class="language-{language} {SCOPE_CLASS}">{highlight(code)}</code></pre>'
    )


def _render_fence(self: RendererHTML, tokens: Sequence[Token], idx: int, options: Any, env: Any) -> str:
    """markdown-it's fence rule with Luau highlighting for ```lua and ```luau; other fences render as before."""
    token = tokens[idx]
    words = token.info.split()
    language = words[0].lower() if words else ""
    if language in HIGHLIGHTED_LANGUAGES:
        return f"{code_block(token.content, language)}\n"
    return RendererHTML.fence(self, tokens, idx, options, env)


def _markdown() -> MarkdownIt:
    # html=False: raw HTML in the file is escaped, never rendered. typographer=False: no "smart" dashes or quotes
    # (rule C5 bans the dash characters it would produce). linkify=False: only explicit links become links.
    md = MarkdownIt("commonmark", {"html": False, "typographer": False, "linkify": False}).enable("table")
    md.add_render_rule("fence", _render_fence)
    return md


@functools.cache
def home_examples() -> dict[str, Markup]:
    """The home page's Luau snippets as highlighted `<pre>` blocks, keyed by name (`HOME_EXAMPLE_NAMES`).

    Read and highlighted once per process: the files change only with a release. The router's lifespan calls
    this at startup, so a release missing a snippet fails its health gate instead of answering 500 on `/`.
    """
    return {
        name: code_block((HOME_EXAMPLES_DIR / f"{name}.luau").read_text(encoding="utf-8"), "luau")
        for name in HOME_EXAMPLE_NAMES
    }


def render_guide(text: str, known: frozenset[str] | None = None) -> RenderedGuide:
    """Render Markdown to HTML with heading anchors and a table of contents, split at `{{ name }}` markers."""
    known_names = frozenset(GUIDE_VALUES) if known is None else known
    md = _markdown()
    tokens = md.parse(text)
    toc: list[TocEntry] = []
    used: dict[str, int] = {}
    title = "Roxy user guide"
    for index, token in enumerate(tokens):
        if token.type == "heading_open":
            inline = tokens[index + 1]
            plain = _plain_text(inline).strip()
            base = slugify(plain)
            used[base] = used.get(base, 0) + 1
            anchor = base if used[base] == 1 else f"{base}-{used[base]}"
            token.meta["anchor"] = anchor
            token.meta["title"] = plain
            level = int(token.tag[1])
            if level == 1 and index == 0:
                title = plain
            elif level in (2, 3):
                toc.append(TocEntry(level, anchor, plain))
        elif token.type in ("th_open", "td_open"):
            # markdown-it writes column alignment as an inline style; the CSP forbids those, so use a class.
            style = token.attrGet("style")
            if style is not None:
                token.attrs.pop("style", None)
                match = _ALIGN_STYLE.match(str(style).strip())
                if match:
                    token.attrSet("class", f"align-{match.group(1)}")

    def heading_open(self: Any, tokens: Sequence[Token], idx: int, options: Any, env: Any) -> str:
        token = tokens[idx]
        anchor = html.escape(str(token.meta.get("anchor", "")), quote=True)
        if token.tag == "h1":
            return f'<h1 id="{anchor}">'
        # The wrapper holds the heading and its section link side by side; the link stays OUTSIDE the heading,
        # so a screen reader announces "4. Limits", not "4. Limits Link to this section: 4. Limits".
        return f'<div class="heading heading-{token.tag}"><{token.tag} id="{anchor}">'

    def heading_close(self: Any, tokens: Sequence[Token], idx: int, options: Any, env: Any) -> str:
        # The matching heading_open is two tokens back (open, inline, close). h1 is the page title: no link.
        token, opening = tokens[idx], tokens[idx - 2]
        if token.tag == "h1":
            return "</h1>\n"
        anchor = html.escape(str(opening.meta.get("anchor", "")), quote=True)
        label = html.escape(f"Link to this section: {opening.meta.get('title', '')}", quote=True)
        return f'</{token.tag}><a class="anchor" href="#{anchor}" aria-label="{label}">#</a></div>\n'

    md.add_render_rule("heading_open", heading_open)
    md.add_render_rule("heading_close", heading_close)
    body = md.renderer.render(tokens, md.options, {})

    parts: list[str] = []
    names: list[str] = []
    unknown: list[str] = []
    position = 0
    for match in _PLACEHOLDER.finditer(body):
        name = match.group(1)
        if name not in known_names:
            unknown.append(name)
            continue  # left in the page as typed, so the mistake is visible instead of silently blank
        parts.append(body[position : match.start()])
        names.append(name)
        position = match.end()
    parts.append(body[position:])
    return RenderedGuide(title, tuple(parts), tuple(names), tuple(toc), tuple(unknown))


_guide_lock = threading.Lock()
_guide_cache: dict[Path, tuple[int, int, RenderedGuide]] = {}


def load_guide(path: Path | None = None) -> RenderedGuide | None:
    """The rendered guide (`USER_GUIDE_PATH` by default), re-rendered only when the file changes (cached per
    path; one entry per file). None when the file cannot be read."""
    path = USER_GUIDE_PATH if path is None else path
    try:
        stat = path.stat()
    except OSError:
        return None
    cached = _guide_cache.get(path)
    if cached is not None and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        log.warning("user_guide_unreadable", extra={"fields": {"path": str(path)}}, exc_info=True)
        return None
    rendered = render_guide(text)
    if rendered.unknown:
        log.warning("user_guide_unknown_values", extra={"fields": {"names": sorted(set(rendered.unknown))}})
    with _guide_lock:
        if len(_guide_cache) >= 4 and path not in _guide_cache:
            _guide_cache.clear()  # bounded (plan P9); only tests ever render more than one file
        _guide_cache[path] = (stat.st_mtime_ns, stat.st_size, rendered)
    return rendered


def guide_values(get: Getter, names: Sequence[str] | None = None) -> dict[str, str]:
    """Live values for the guide's markers (all of them, or only `names`)."""
    wanted = GUIDE_VALUES if names is None else {name: GUIDE_VALUES[name] for name in set(names)}
    return {name: compute(get) for name, compute in wanted.items()}


# --- build date (sitemap lastmod) ---------------------------------------------------------------------------------


@functools.cache
def build_time() -> float:
    """When this release's public content was built: the newest mtime among the public templates and assets,
    this module and the user guide. A release is a fresh checkout, so that is its build time; in development it
    is the last edit of public content. Computed once per process."""
    candidates: list[Path] = [Path(__file__), USER_GUIDE_PATH]
    for directory in (PUBLIC_TEMPLATES_DIR, PUBLIC_STATIC_DIR):
        if directory.is_dir():
            candidates.extend(path for path in directory.rglob("*") if path.is_file())
    newest = 0.0
    for path in candidates:
        try:
            newest = max(newest, path.stat().st_mtime)
        except OSError:
            continue
    return newest or time.time()


def build_date() -> str:
    """The build date as the sitemap writes it (W3C date, UTC): `YYYY-MM-DD`."""
    return datetime.fromtimestamp(build_time(), UTC).strftime("%Y-%m-%d")


# --- robots.txt and sitemap.xml -----------------------------------------------------------------------------------


@functools.cache
def robots_bytes() -> bytes:
    """robots.txt exactly as v1 served it (120 bytes; read once per process)."""
    return ROBOTS_PATH.read_bytes()


@dataclass(frozen=True, slots=True)
class SitemapEntry:
    path: str
    changefreq: str
    priority: str


SITEMAP_HOME: Final = SitemapEntry("/", "weekly", "1.0")  # v1's only entry, unchanged
SITEMAP_DOCS: Final = SitemapEntry("/docs", "weekly", "0.8")
SITEMAP_STATUS: Final = SitemapEntry("/status", "hourly", "0.3")


def build_sitemap(lastmod: str, *, include_status: bool = True) -> bytes:
    """sitemap.xml in v1's exact layout (tab indented, final newline), plus `/docs` and `/status` (plan row 13)."""
    entries = [SITEMAP_HOME, SITEMAP_DOCS] + ([SITEMAP_STATUS] if include_status else [])
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for entry in entries:
        lines += [
            "\t<url>",
            f"\t\t<loc>{CANONICAL_ORIGIN}{entry.path}</loc>",
            f"\t\t<lastmod>{lastmod}</lastmod>",
            f"\t\t<changefreq>{entry.changefreq}</changefreq>",
            f"\t\t<priority>{entry.priority}</priority>",
            "\t</url>",
        ]
    lines.append("</urlset>")
    return ("\n".join(lines) + "\n").encode("utf-8")


# --- status -------------------------------------------------------------------------------------------------------


class SiteState(StrEnum):
    """The only four things `/status` ever says about Roxy as a whole (plan 16.1)."""

    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    PAUSED = "paused"
    MAINTENANCE = "maintenance"


HOUR_NO_DATA: Final = "none"
"""Hour cell state when no request was recorded in that hour (Roxy idle, or not running)."""

STATE_TEXT: Final[dict[str, tuple[str, str]]] = {
    SiteState.OPERATIONAL: ("Operational", "Roxy is working normally."),
    SiteState.DEGRADED: (
        "Degraded",
        "Roxy is up, but some requests are failing or being refused more than usual. Retry with backoff and "
        "respect Retry-After.",
    ),
    SiteState.PAUSED: ("Paused", "Roxy is paused by its admin. Requests get 503 with Retry-After until it resumes."),
    SiteState.MAINTENANCE: (
        "Maintenance",
        "Roxy is down for scheduled maintenance. Requests get 503 with Retry-After until it is over.",
    ),
    HOUR_NO_DATA: ("No data", "No requests were recorded in this hour."),
}

PAUSE_STATE_KEY: Final = "pause"
"""control.db `service_state` key holding the pause record written by `roxy.abuse.pause` (`PauseState`: paused,
reason, since, scheduled_start, scheduled_end, scheduled_reason, scheduled_by)."""

STATUS_CACHE_S: Final = 10.0
"""Seconds one worker reuses a computed status. Reason: a crowd refreshing /status costs one set of reads."""
RECENT_WINDOW_S: Final = 600
"""How far back "right now" looks for failures: the last 10 minutes of minute rollups."""
DEGRADED_FAILURE_SHARE: Final = 0.10
"""Share of answered requests (served or failed, refusals excluded) that failed, from which a period is degraded.
Reason: a coarse public signal with a deliberately high bar; individual upstream errors are normal."""
MIN_ANSWERED_FOR_JUDGMENT: Final = 20
"""Fewer answered requests than this are too few to call a period degraded (one failure out of 3 is noise)."""
PAUSED_SHARE: Final = 0.5
"""An hour is shown as paused when at least half of its requests were refused because Roxy was paused."""
HOURS_SHOWN: Final = 24

CALLER_EGRESSES: Final = (Egress.DIRECT, Egress.ROTATOR)
"""The paths callers' requests take to Roblox. The credential is only for Roxy's own probes (owner decision D1),
so a credential cooldown says nothing about what callers get."""
ROBLOX_COOLDOWN_SOURCES: Final = (CooldownSource.RETRY_AFTER, CooldownSource.RATELIMIT_RESET, CooldownSource.DEFAULT)
"""Cooldowns opened by a Roblox 429 (with Retry-After, with x-ratelimit-reset, or neither). `breaker` rows are Roxy
resting a failing path (an open breaker, a parked rotator), which is not Roblox asking to slow down."""


def parse_pause_state(value_json: str | None, now_s: float) -> SiteState | None:
    """PAUSED, MAINTENANCE or None (running) from the `service_state` pause record.

    Parsed by `PauseState`, the type the pause control writes and the proxy's pause check reads, so this page
    says paused exactly when the proxy refuses with 503 (`PauseState.active`). The manual switch wins over a
    scheduled window, as it does for the 503 message; a scheduled window alone is maintenance. A record that
    cannot be read counts as running here (the proxy's own check is what refuses requests).
    """
    if not value_json:
        return None
    try:
        state = PauseState.from_json(json.loads(value_json))
    except (ValueError, TypeError, RecursionError):
        return None
    if state.paused:
        return SiteState.PAUSED
    if state.in_scheduled_window(now_s):
        return SiteState.MAINTENANCE
    return None


@dataclass(frozen=True, slots=True)
class Tally:
    """Request counts for one period, by the outcome classes the status page needs. Never shown to visitors."""

    total: int = 0
    refused: int = 0
    failed: int = 0
    paused: int = 0

    def __add__(self, other: Tally) -> Tally:
        return Tally(
            self.total + other.total,
            self.refused + other.refused,
            self.failed + other.failed,
            self.paused + other.paused,
        )


def is_degraded(tally: Tally) -> bool:
    """True when enough answered requests failed (refusals are Roxy doing its job, so they do not count)."""
    answered = tally.total - tally.refused
    return answered >= MIN_ANSWERED_FOR_JUDGMENT and tally.failed >= DEGRADED_FAILURE_SHARE * answered


def classify_hour(tally: Tally | None) -> str:
    """The state of one hour cell: "none", "paused", "degraded" or "operational"."""
    if tally is None or tally.total <= 0:
        return HOUR_NO_DATA
    if tally.paused >= PAUSED_SHARE * tally.total:
        return SiteState.PAUSED.value
    if is_degraded(tally):
        return SiteState.DEGRADED.value
    return SiteState.OPERATIONAL.value


# The rollup tables and the dims table are the plan 6.2 metrics schema; `outcome` and `reason_code` hold the
# core/reasons.py enum values ("refused", "failed", "paused").
_TALLY_COLUMNS = (
    "SUM(r.requests), "
    "SUM(CASE WHEN d.outcome = 'refused' THEN r.requests ELSE 0 END), "
    "SUM(CASE WHEN d.outcome = 'failed' THEN r.requests ELSE 0 END), "
    "SUM(CASE WHEN d.reason_code = 'paused' THEN r.requests ELSE 0 END)"
)
_HOURLY_SQL = {
    table: (
        f"SELECT (r.bucket_start / 3600) * 3600 AS hour, {_TALLY_COLUMNS} "  # noqa: S608 (constant table names)
        f"FROM {table} AS r JOIN dims AS d ON d.dim_hash = r.dim_hash "
        "WHERE r.bucket_start >= ? AND r.bucket_start < ? GROUP BY hour"
    )
    for table in ("rollup_hour", "rollup_minute")
}
_RECENT_SQL = (
    f"SELECT {_TALLY_COLUMNS} FROM rollup_minute AS r JOIN dims AS d ON d.dim_hash = r.dim_hash "  # noqa: S608
    "WHERE r.bucket_start >= ?"
)


def _tally(row: Sequence[Any]) -> Tally:
    return Tally(*(int(value or 0) for value in row))


def read_metrics(conn: sqlite3.Connection, now_s: float) -> tuple[dict[int, Tally], Tally]:
    """Hourly tallies for the last 24 hours and the tally of the last `RECENT_WINDOW_S` seconds.

    Hours already compacted into `rollup_hour` are read from there; later hours from `rollup_minute`. The leader
    compacts whole hours in time order and recomputes the newest ones to pick up late writes (`metrics/rollups.py`),
    so the hour table is complete up to its newest row: an hour before that with no row was idle. The minute
    table is therefore scanned only after the newest compacted hour (the metrics queries' "watermark" rule), never
    from an idle hour early in the window, which used to cost a scan of almost a day of minute rows.
    """
    current_hour = int(now_s // 3600) * 3600
    since = current_hour - (HOURS_SHOWN - 1) * 3600
    until = current_hour + 3600
    hours = {int(row[0]): _tally(row[1:]) for row in conn.execute(_HOURLY_SQL["rollup_hour"], (since, until))}
    minute_from = max(hours) + 3600 if hours else since
    if minute_from < until:
        for row in conn.execute(_HOURLY_SQL["rollup_minute"], (minute_from, until)):
            hours.setdefault(int(row[0]), _tally(row[1:]))
    recent_row = conn.execute(_RECENT_SQL, (int(now_s) - RECENT_WINDOW_S,)).fetchone()
    return hours, _tally(recent_row) if recent_row is not None else Tally()


def read_pause_value(conn: sqlite3.Connection) -> str | None:
    """The raw pause record from control.db, or None when there is none."""
    row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (PAUSE_STATE_KEY,)).fetchone()
    return None if row is None else str(row[0])


_KEY_WILDCARD: Final = "\x00"


def _like_pattern(key: str) -> str:
    """A cooldown key with `_KEY_WILDCARD` where any text may stand, as a LIKE pattern (`ESCAPE '\\'`)."""
    escaped = key.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace(_KEY_WILDCARD, "%")


# Every key a Roblox 429 can cool down on a caller path: `endpoint:<template>:<egress>`, `host:<host>:<egress>` and
# `egress:<egress>`, built with the upstream package's own key functions so the format has one owner.
_CALLER_COOLDOWN_PATTERNS: Final = tuple(
    _like_pattern(key)
    for egress in CALLER_EGRESSES
    for key in (endpoint_key(_KEY_WILDCARD, egress), host_key(_KEY_WILDCARD, egress), egress_key(egress))
)
_LIKE_KEY: Final = "key LIKE ? ESCAPE '\\'"  # SQL: key LIKE ? ESCAPE '\' (a backslash escapes % and _)
_RATE_LIMITED_SQL: Final = (
    "SELECT 1 FROM cooldown WHERE until_ms > ? "  # noqa: S608 (only constant "?" placeholders are interpolated)
    f"AND source IN ({', '.join('?' for _ in ROBLOX_COOLDOWN_SOURCES)}) "
    f"AND ({' OR '.join(_LIKE_KEY for _ in _CALLER_COOLDOWN_PATTERNS)}) LIMIT 1"
)


def read_rate_limited(conn: sqlite3.Connection, now_s: float) -> bool:
    """True while Roblox has asked Roxy to slow down on a path callers use (an active 429 cooldown).

    Counted: cooldowns whose source is a Roblox 429 (`ROBLOX_COOLDOWN_SOURCES`) on an endpoint, host or whole
    egress of the direct or rotator path. Not counted: the credential's cooldowns (owner decision D1) and
    `breaker` rows (an open breaker or a parked rotator after failures; the status state covers failures).
    """
    params = (int(now_s * 1000), *(str(source) for source in ROBLOX_COOLDOWN_SOURCES), *_CALLER_COOLDOWN_PATTERNS)
    return conn.execute(_RATE_LIMITED_SQL, params).fetchone() is not None


@dataclass(frozen=True, slots=True)
class HourCell:
    """One hour of the 24 hour bar: its start (Unix seconds, UTC) and its state."""

    start: int
    state: str

    @property
    def label(self) -> str:
        return f"{datetime.fromtimestamp(self.start, UTC).strftime('%H:%M')} UTC"

    @property
    def text(self) -> str:
        return STATE_TEXT[self.state][0]


@dataclass(frozen=True, slots=True)
class StatusView:
    """Everything the status page shows. Deliberately coarse: states and booleans, never counts or addresses."""

    state: SiteState
    hours: tuple[HourCell, ...]
    rate_limited: bool | None  # None when hot.db could not be read
    computed_at: float

    @property
    def label(self) -> str:
        return STATE_TEXT[self.state][0]

    @property
    def message(self) -> str:
        return STATE_TEXT[self.state][1]

    @property
    def updated(self) -> str:
        return datetime.fromtimestamp(self.computed_at, UTC).strftime("%Y-%m-%d %H:%M UTC")

    @property
    def updated_iso(self) -> str:
        return datetime.fromtimestamp(self.computed_at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _egress_unavailable(ctx: Any) -> bool:
    """True when the egress clients exist and report that NO path to Roblox is enabled (7.13 `egress_disabled`)."""
    egress = getattr(ctx, "egress", None)
    is_enabled = getattr(egress, "is_enabled", None)
    if is_enabled is None:
        return False
    try:
        return not any(bool(is_enabled(path)[0]) for path in (Egress.DIRECT, Egress.ROTATOR))
    except Exception:
        log.warning("public_status_egress_check_failed", exc_info=True)
        return False


async def compute_status(ctx: Any, now_s: float) -> StatusView:
    """Read pause state, recent failures, hourly history and cooldowns, and boil them down to a `StatusView`."""
    current_hour = int(now_s // 3600) * 3600
    starts = [current_hour - (HOURS_SHOWN - 1 - offset) * 3600 for offset in range(HOURS_SHOWN)]
    dbs = getattr(ctx, "dbs", None)
    degraded = ctx is None or dbs is None or not bool(getattr(ctx, "ready", True))
    pause_state: SiteState | None = None
    hours: dict[int, Tally] = {}
    recent = Tally()
    rate_limited: bool | None = None
    if dbs is not None:
        try:
            pause_state = parse_pause_state(await dbs.control.read(read_pause_value), now_s)
        except Exception:
            degraded = True  # control.db unreadable: shared state is in trouble (plan C7)
            log.warning("public_status_control_read_failed", exc_info=True)
        try:
            hours, recent = await dbs.metrics.read(lambda conn: read_metrics(conn, now_s))
        except Exception:
            log.warning("public_status_metrics_read_failed", exc_info=True)  # metrics may degrade open (C7)
        try:
            rate_limited = await dbs.hot.read(lambda conn: read_rate_limited(conn, now_s))
        except Exception:
            degraded = True  # hot.db unreadable: limiters run on their in-memory fallback (plan C7)
            log.warning("public_status_hot_read_failed", exc_info=True)
    if is_degraded(recent) or _egress_unavailable(ctx):
        degraded = True
    state = pause_state or (SiteState.DEGRADED if degraded else SiteState.OPERATIONAL)
    cells = tuple(HourCell(start, classify_hour(hours.get(start))) for start in starts)
    return StatusView(state=state, hours=cells, rate_limited=rate_limited, computed_at=now_s)


class StatusCache:
    """One cached `StatusView` per app (per worker), recomputed at most every `STATUS_CACHE_S` seconds."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._view: StatusView | None = None
        self._at = 0.0

    async def get(self, ctx: Any) -> StatusView:
        clock = getattr(ctx, "clock", None)
        monotonic = clock.monotonic() if clock is not None else time.monotonic()
        if self._view is not None and 0 <= monotonic - self._at < STATUS_CACHE_S:
            return self._view
        async with self._lock:  # concurrent visitors wait for one computation instead of each running one
            if self._view is not None and 0 <= monotonic - self._at < STATUS_CACHE_S:
                return self._view
            now_s = clock.now() if clock is not None else time.time()
            self._view = await compute_status(ctx, now_s)
            self._at = monotonic
            return self._view


def status_cache(request: Request) -> StatusCache:
    """The status cache stored on this app (created on first use)."""
    cache = getattr(request.app.state, "public_status_cache", None)
    if not isinstance(cache, StatusCache):
        cache = StatusCache()
        request.app.state.public_status_cache = cache
    return cache


# --- rendering helpers --------------------------------------------------------------------------------------------

_fallback_templates: Templates | None = None


def templates_for(request: Request) -> Templates:
    """The app's `Templates` (built by `create_app`), or a default one for a bare test app."""
    found = getattr(request.app.state, "templates", None)
    if isinstance(found, Templates):
        return found
    global _fallback_templates
    if _fallback_templates is None:
        _fallback_templates = Templates()
    return _fallback_templates


def common_context(get: Getter, page: str) -> dict[str, Any]:
    """Values every public page uses: the footer, the navigation and the current page name."""
    return {
        "page": page,
        "status_enabled": bool(get("public_status_page_enabled")),
        "footer_html": render_site_text(str(get("site_footer_text")), inline=True),
        "canonical_origin": CANONICAL_ORIGIN,
    }


def _page(request: Request, template: str, context: Mapping[str, Any]) -> Response:
    response = templates_for(request).render(request, template, context)
    response.headers["cache-control"] = PAGE_CACHE_CONTROL
    return response


# --- startup check and routes -------------------------------------------------------------------------------------


class UserGuideMissing(RuntimeError):
    """The worker cannot serve `/docs`: `docs/USER_GUIDE.md` was not found next to the installed package."""


@asynccontextmanager
async def require_user_guide(app: Any) -> AsyncIterator[None]:
    """Router lifespan: refuse to start a worker that cannot serve the user guide.

    FastAPI runs a router's lifespan inside the application's own (after `roxy/lifespan.py` has started the
    worker). Raising here fails the worker's startup, so a release without its guide never passes the deploy
    health gate and is rolled back, instead of answering 404 on `/docs` (logged as a probe) for its whole life.
    Rendering the guide here also warms the cache, so the first visitor does not pay for it. The home page's
    highlighted Luau snippets are built here too, for the same two reasons (a missing file raises OSError).
    """
    if load_guide() is None:
        log.critical("user_guide_missing", extra={"fields": {"path": str(USER_GUIDE_PATH)}})
        raise UserGuideMissing(
            f"{GUIDE_RELATIVE_PATH.as_posix()} was not found in {PACKAGE_DIR} or the {GUIDE_SEARCH_PARENTS} "
            "directories above it, so /docs cannot be served. A release must include docs/ (deploy/deploy.sh "
            "exports the whole tree with git archive)."
        )
    home_examples()
    yield


router = APIRouter(lifespan=require_user_guide)

_guide_missing_logged = False


@router.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def home(request: Request) -> Response:
    """The home page: what Roxy is, a quick start, live limits, and the `site_*` texts (plan 16.1)."""
    get = settings_getter(request)
    context = {
        **common_context(get, PAGE_HOME),
        "limits": live_limits(get),
        "examples": home_examples(),
        "contact_name": str(get("site_contact_name")),
        "white_hats_html": render_site_text(str(get("site_white_hats_text"))),
        "bug_bounty_html": render_site_text(str(get("site_bug_bounty_text"))),
        "hosting_html": render_site_text(str(get("site_hosting_note"))),
        "support_html": render_site_text(str(get("site_support_links"))),
    }
    response = _page(request, "public/home.html", context)
    await record_visit(request, PAGE_HOME)
    return response


@router.api_route("/docs", methods=["GET", "HEAD"], include_in_schema=False)
async def docs(request: Request) -> Response:
    """The user guide (`docs/USER_GUIDE.md`) with live values, a table of contents and heading anchors."""
    global _guide_missing_logged
    guide = load_guide()
    if guide is None:
        # Startup checked the file, so it vanished since. 503 (Roxy's fault, never logged as a probe the way a
        # 404 is), and one ERROR line per process instead of one per visit.
        if not _guide_missing_logged:
            _guide_missing_logged = True
            log.error("user_guide_missing", extra={"fields": {"path": str(USER_GUIDE_PATH)}})
        raise HTTPException(status_code=503, detail="Service Unavailable")
    get = settings_getter(request)
    context = {
        **common_context(get, PAGE_DOCS),
        "guide_title": guide.title,
        "toc": guide.toc,
        "guide_html": guide.html(guide_values(get, guide.names)),
    }
    response = _page(request, "public/docs.html", context)
    await record_visit(request, PAGE_DOCS)
    return response


@router.api_route("/status", methods=["GET", "HEAD"], include_in_schema=False)
async def status(request: Request) -> Response:
    """Coarse public status, or 404 while `public_status_page_enabled` is 0 (plan 15.3 K)."""
    get = settings_getter(request)
    if not bool(get("public_status_page_enabled")):
        raise HTTPException(status_code=404, detail="Not Found")
    ctx = getattr(request.app.state, "ctx", None)
    view = await status_cache(request).get(ctx)
    context = {
        **common_context(get, PAGE_STATUS),
        "view": view,
        "limits": live_limits(get),
        "cache_enabled": bool(get("cache_enabled")),
        "cache_ttl_text": count_text(get("cache_ttl_seconds"), "second"),
        "legend": [(state, STATE_TEXT[state][0]) for state in ("operational", "degraded", "paused", HOUR_NO_DATA)],
    }
    response = _page(request, "public/status.html", context)
    await record_visit(request, PAGE_STATUS)
    return response


@router.api_route("/robots.txt", methods=["GET", "HEAD"], include_in_schema=False)
async def robots_txt(request: Request) -> Response:
    """v1's robots.txt, byte for byte; logs the crawl and counts the visit like v1."""
    response = Response(content=robots_bytes(), media_type="text/plain; charset=utf-8")
    await record_crawl(request)
    await record_visit(request, PAGE_ROBOTS)
    return response


@router.api_route("/sitemap.xml", methods=["GET", "HEAD"], include_in_schema=False)
async def sitemap_xml(request: Request) -> Response:
    """The sitemap with `/`, `/docs` and (while enabled) `/status`, `lastmod` from the build date."""
    get = settings_getter(request)
    body = build_sitemap(build_date(), include_status=bool(get("public_status_page_enabled")))
    response = Response(content=body, media_type="application/xml; charset=utf-8")
    await record_crawl(request)
    await record_visit(request, PAGE_SITEMAP)
    return response


@router.api_route("/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
async def favicon(request: Request) -> Response:
    """The PNG favicon at the path browsers ask for by default (v1 served the same PNG; no logging, like v1)."""
    return FileResponse(FAVICON_PATH, media_type="image/png", headers={"cache-control": FAVICON_CACHE_CONTROL})
