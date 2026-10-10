"""Shared helpers of the Upstream, Egress and Credential pages (the g3 page group): words, numbers and partials.

What this is
    Small pure helpers the three page modules (`upstream.py`, `egress.py`, `credential.py`) share:
      * plain words for egress paths, egress states and the reasons an egress is off (`EGRESS_LABELS`,
        `egress_state`, `reason_words`), and for the precision of a "last seen" time (`precision_words`);
      * number text that the Jinja format macros do not cover (`pct_text`, `per_min_text`, `ms_text`,
        `decimal_bytes`) and the tone of a fill level (`fill_tone`);
      * `quoted_key(key)`: a bucket key as ONE percent-encoded URL path segment, so a key that holds caller text (an
        endpoint template) can never add path segments to an admin API URL (`..` included);
      * `render_partial(...)`: the HTML of a small page-local route (a tester result, a drawer) with the page's
        time range, rendered from a template, where a known API refusal becomes its message instead of an error.

Why it exists
    The three pages show the same egress paths and the same kinds of numbers; one wording keeps them consistent
    (plan 14.7: help in plain language) and one place keeps the URL rule that makes caller text safe in a form URL.

How it works
    Pure functions plus one async helper that uses the kit's `Page.view` (the same time range, preferences and
    guard as a card fragment) and `kit.templates_of`. Nothing here reads a database.

What to read next
    `roxy/admin/pages/upstream.py`, `roxy/admin/pages/egress.py`, `roxy/admin/pages/credential.py`.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Final
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.admin.api import common
from roxy.admin.auth.deps import AdminPrincipal
from roxy.admin.pages.kit import Page, PageView, templates_of

log = logging.getLogger("roxy.admin.pages")

EGRESS_LABELS: Final[dict[str, str]] = {
    "direct": "Direct",
    "rotator": "Rotator",
    "credential": "Credential",
}
"""The display name of each egress path (`core/reasons.py Egress`)."""

EGRESS_ABOUT: Final[dict[str, str]] = {
    "direct": "Anonymous calls from the server's own address. Most traffic leaves this way.",
    "rotator": "Anonymous calls through the DataImpulse rotator, from changing exit addresses. Costs money per byte.",
    "credential": "Calls that carry the one Roblox account. Only Roxy's own probes use it unless the allowlist "
    "names an endpoint (owner decision D1).",
}

REASON_WORDS: Final[dict[str, str]] = {
    "leak_guard_tripped": "the leak guard stopped it",
    "direct_disabled": "switched off (direct_enabled is 0)",
    "rotator_disabled": "switched off (rotator_enabled is 0)",
    "rotator_not_configured": "no rotator URL is set",
    "rotator_parked": "parked after a failure streak",
    "rotator_budget": "the monthly budget stop was reached",
    "rotator_quota_hard_stop": "the monthly budget stop was reached",
    "rotator_daily_cap": "the daily byte cap was reached",
    "encryption_key_missing": "the stored rotator URL cannot be read (no encryption key)",
    "ui_value_unreadable": "the stored rotator URL cannot be read",
    "invalid_url": "the rotator URL is not valid",
    "credential_absent": "no credential is loaded",
    "credential_rejected": "Roblox rejected the credential",
    "credential_cooling_down": "the credential is cooling down",
    "credential_unknown": "the credential has not been checked yet",
    "credential_disabled": "switched off (credential_enabled is 0)",
}
"""Plain words for the reasons `EgressClients.is_enabled` and `RotatorPool.availability` give."""

PRECISION_WORDS: Final[dict[str, str]] = {
    "minute": "to the minute",
    "hour": "to the hour",
    "day": "to the day",
    "month": "to the month",
}

FILL_WARN_PCT: Final = 70.0
FILL_BAD_PCT: Final = 95.0
"""A bucket fill from 70 percent is busy, from 95 percent the next call waits (v1's budget gauge used the same)."""


def reason_words(reason: Any) -> str:
    """Plain words for an off reason (the raw code when it is new)."""
    text = str(reason or "")
    return REASON_WORDS.get(text, text.replace("_", " "))


def precision_words(precision: Any) -> str:
    return PRECISION_WORDS.get(str(precision or ""), "")


def pct_text(value: Any, digits: int = 1) -> str:
    """`12.5%` for a percent value (0 to 100), "n/a" when unknown."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "n/a"
    return f"{float(value):,.{digits}f}%"


def per_min_text(value: Any) -> str:
    """`120 a minute` (decimals kept for an adaptive rate such as 43.4)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "n/a"
    number = float(value)
    shown = f"{number:,.0f}" if number == int(number) else f"{number:,.1f}"
    return f"{shown} a minute"


def ms_text(value: Any) -> str:
    """`42 ms` (one decimal below 10 ms), "n/a" when unknown."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "n/a"
    number = float(value)
    return f"{number:,.1f} ms" if number < 10 else f"{number:,.0f} ms"


def decimal_bytes(value: Any) -> str:
    """Bytes in decimal units (1 GB = 10^9 bytes, the unit DataImpulse bills in), "n/a" when unknown."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "n/a"
    number = float(value)
    for size, unit in ((1e12, "TB"), (1e9, "GB"), (1e6, "MB"), (1e3, "kB")):
        if abs(number) >= size:
            return f"{number / size:,.2f} {unit}"
    return f"{number:,.0f} B"


def fill_tone(pct: Any) -> str:
    """`ok`, `warn` or `bad` for a fill level in percent (`neutral` when unknown)."""
    if isinstance(pct, bool) or not isinstance(pct, int | float):
        return "neutral"
    if pct >= FILL_BAD_PCT:
        return "bad"
    if pct >= FILL_WARN_PCT:
        return "warn"
    return "ok"


def gauge(label: str, pct: Any, *, detail: str = "", key: str = "") -> dict[str, Any]:
    """The context of one fill gauge (`upstream/_macros.html gauge`): a native <meter> with words beside it."""
    value = float(pct) if isinstance(pct, int | float) and not isinstance(pct, bool) else None
    shown = min(100.0, max(0.0, value)) if value is not None else 0.0
    tone = fill_tone(value)
    words = {"ok": "room to spare", "warn": "busy", "bad": "full: the next call waits", "neutral": "no data"}[tone]
    return {
        "label": label,
        "value": round(shown, 1),
        "pct_text": pct_text(value),
        "tone": tone,
        "words": words,
        "detail": detail,
        "key": key,
    }


def egress_state(item: Mapping[str, Any]) -> tuple[str, str, str]:
    """`(tone, word, detail)` of one egress health card: the leak guard first, then off, then trouble, then
    working. The word is short (it sits in a badge); the detail says why in a sentence."""
    if item.get("leak_guard_tripped"):
        return "bad", "Stopped", "The leak guard stopped it: an anonymous call would have carried the credential."
    if not item.get("enabled"):
        why = reason_words(item.get("disabled_reason"))
        return "neutral", "Off", f"Not in use: {why}." if why else "Not in use."
    if int(item.get("breakers_open") or 0):
        return "warn", "Partly paused", "Some endpoints are paused because their circuit breaker is open."
    if int(item.get("cooldowns") or 0):
        return "warn", "Cooling down", "Roblox asked Roxy to slow down on some endpoints; they rest until it ends."
    if not int(item.get("calls") or 0):
        return "neutral", "Idle", "Ready, but no call went out this way in this range."
    return "ok", "Working", "Calls go out and Roblox answers."


def quoted_key(key: str) -> str:
    """A bucket key as one URL path segment: every byte but letters, digits and `_.-~` percent-encoded, slashes
    included, so `endpoint:host/../x` stays one segment (`..` is never a segment of its own) and the admin API's
    `{bucket_key:path}` route receives the key unchanged."""
    return quote(str(key), safe="")


DEFERRED: Final[dict[str, Any]] = {"deferred": True}
"""The context of a deferred card's first paint (`admin/pages/upstream/_deferred.html`)."""


def deferred(view: PageView) -> bool:
    """True on the page's first paint for a card that loads its body as its own fragment right after the page.

    Heavy cards (many settings, tables) are not rendered into the first paint, so the page stays small on the 1 GB
    server. They load at once (`hx-trigger="load"`), not when scrolled into view: the kit's lazy cards load on
    `revealed`, which only fires for cards in the final scroll position, so a page with many lazy cards far apart
    never finished loading for a reader who jumps around (and the browser test harness's settle step, which
    scrolls every lazy card into view in one pass, never saw them all load). A card's own fragment request
    (`/admin/<page>/fragment/<card>`) always renders the whole card."""
    return not view.in_fragment


PartialBuild = Callable[[PageView], Awaitable[Mapping[str, Any]]]


async def render_partial(
    page: Page, request: Request, principal: AdminPrincipal, template: str, build: PartialBuild
) -> HTMLResponse:
    """A page-local fragment (a tester answer, a drawer body): the page's view, `build(view)` as the template's
    context, and an API refusal (`common.ApiError`, a known service error) rendered as its message, never a 500.
    The answer is always 200 so htmx swaps it in (an error is shown where the result would be)."""
    view = await page.view(request, principal)
    templates = templates_of(request)
    base = {"view": view, "tz": view.tz, "now": view.now, "time": view.time.view}
    try:
        context = dict(await build(view))
        error = None
    except common.ApiError as exc:
        context, error = {}, exc.error_message
        if exc.error_fields:
            error = "; ".join(str(message) for message in exc.error_fields.values())
    except Exception as exc:  # a partial must never turn into a 500 (the page keeps working)
        mapped = common.service_error(exc)
        if mapped is None:
            log.exception("page_partial_failed", extra={"fields": {"page": page.id, "template": template}})
            error = "This could not be loaded. The error is in the server log; try again shortly."
        else:
            error = mapped.error_message
        context = {}
    html = templates.render_to_string(request, template, {**base, **context, "error": error})
    return HTMLResponse(html)


__all__ = [
    "DEFERRED",
    "EGRESS_ABOUT",
    "EGRESS_LABELS",
    "FILL_BAD_PCT",
    "FILL_WARN_PCT",
    "decimal_bytes",
    "deferred",
    "egress_state",
    "fill_tone",
    "gauge",
    "ms_text",
    "pct_text",
    "per_min_text",
    "precision_words",
    "quoted_key",
    "reason_words",
    "render_partial",
]
