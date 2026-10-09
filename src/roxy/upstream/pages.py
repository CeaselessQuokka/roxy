"""Challenge and block page detection: did Roblox answer a call with a challenge, or with an HTML page on a JSON API?

What this is
    `classify_page(host, status, headers, body, accept=...) -> PageFlags`, run by the upstream exchange on every
    answer from Roblox (`upstream/service.py _send`). `PageFlags.challenge` is set when the answer carries a
    challenge header (Roblox's `rblx-challenge-*` headers, or a CDN's `cf-mitigated: challenge`);
    `PageFlags.html_body` when an endpoint that answers JSON sent an HTML document instead (a block, captcha or
    maintenance page). The flags ride on the call's `AttemptRecord` and are counted per minute in
    `upstream_attempt_minute` (`metrics/recorder.py record_attempts`).

Why it exists
    Plan 11.5 UP-CHALLENGE: "Responses with a challenge header or an HTML body on a JSON endpoint, > 5 in 15 min"
    means one egress is being challenged or blocked, and the remedy is to route that endpoint through the other
    anonymous egress. Nothing classified answers this way before (insights_core request 8, rules_upstream
    request 2), so the rule could never fire in production.

How it works
    - Challenge: any header named in `CHALLENGE_HEADERS`, or `cf-mitigated` with the value `challenge`. Header names
      arrive lowercased from the egress.
    - JSON endpoint: every `*.roblox.com` API host, plus any host when the caller asked for JSON (`Accept` names
      json). The web hosts in `PAGE_HOSTS` legitimately serve HTML pages, so an HTML answer there is not counted
      unless the caller asked for JSON.
    - HTML body: the `Content-Type` says HTML, or, when it does not say JSON, the first bytes of the body (after
      whitespace) open an HTML document (`<!doctype html` or `<html`). Only `HTML_SNIFF_BYTES` bytes are looked at,
      so the cost per call is a few dictionary lookups and one short slice (plan 6.3: the request path stays cheap).
    - Redirects (3xx), 204 and 304 carry no page to judge and are never counted.

What to read next
    `roxy/upstream/service.py` (`_send`, where this runs), `roxy/upstream/trace.py` (`AttemptRecord`), then the rule
    in `roxy/insights/rules/upstream.py` (`UpChallenge`).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

CHALLENGE_HEADERS: Final[tuple[str, ...]] = ("rblx-challenge-id", "rblx-challenge-type", "rblx-challenge-metadata")
"""Headers Roblox sends with a challenge (captcha, two-step or other proof) it wants solved before it answers."""
CDN_CHALLENGE_HEADER: Final = "cf-mitigated"
"""A CDN in front of an origin marks a challenge page with `cf-mitigated: challenge`."""
PAGE_HOSTS: Final[frozenset[str]] = frozenset({"roblox.com", "www.roblox.com", "web.roblox.com"})
"""Hosts that serve HTML pages to browsers as well as JSON; an HTML answer there counts only if JSON was asked for."""
HTML_SNIFF_BYTES: Final = 256
"""How much of the body is looked at when the content type does not decide (an HTML page starts at once)."""
HTML_MARKERS: Final[tuple[bytes, ...]] = (b"<!doctype html", b"<html")
NO_PAGE_STATUSES: Final[frozenset[int]] = frozenset({204, 304})


@dataclass(frozen=True, slots=True)
class PageFlags:
    """What one answer from Roblox was: a challenge, an HTML page on a JSON endpoint, both or neither."""

    challenge: bool = False
    html_body: bool = False

    @property
    def any(self) -> bool:
        return self.challenge or self.html_body


NO_FLAGS: Final = PageFlags()


def is_challenge(headers: Mapping[str, str]) -> bool:
    """A challenge header in a (lowercased) header map."""
    if any(name in headers for name in CHALLENGE_HEADERS):
        return True
    return str(headers.get(CDN_CHALLENGE_HEADER, "")).strip().lower() == "challenge"


def expects_json(host: str, accept: str = "") -> bool:
    """Whether the endpoint answers JSON: an API host, or any host when the caller's `Accept` asked for JSON."""
    name = (host or "").strip().lower().rstrip(".")
    return name not in PAGE_HOSTS or "json" in (accept or "").lower()


def is_html(headers: Mapping[str, str], body: bytes) -> bool:
    """The answer is an HTML document, by its content type or (when that does not say JSON) its first bytes."""
    content_type = str(headers.get("content-type", "")).lower()
    if "html" in content_type:
        return True  # text/html, application/xhtml+xml
    if "json" in content_type:
        return False
    head = bytes(body[:HTML_SNIFF_BYTES]).lstrip().lower()  # slice first: never copy a large body
    return head.startswith(HTML_MARKERS)


def classify_page(
    host: str, status: int, headers: Mapping[str, str], body: bytes | None, *, accept: str = ""
) -> PageFlags:
    """The flags of one answer from Roblox (see the module docstring). Never raises."""
    try:
        code = int(status)
        if 300 <= code < 400 or code in NO_PAGE_STATUSES:
            return NO_FLAGS
        challenge = is_challenge(headers)
        html = bool(body) and expects_json(host, accept) and is_html(headers, body or b"")
        if not challenge and not html:
            return NO_FLAGS
        return PageFlags(challenge=challenge, html_body=html)
    except (TypeError, ValueError, AttributeError):
        return NO_FLAGS


__all__ = [
    "CDN_CHALLENGE_HEADER",
    "CHALLENGE_HEADERS",
    "HTML_MARKERS",
    "HTML_SNIFF_BYTES",
    "NO_FLAGS",
    "PAGE_HOSTS",
    "PageFlags",
    "classify_page",
    "expects_json",
    "is_challenge",
    "is_html",
]
