"""Security headers: a fresh CSP nonce per response, the exact plan 9.2 policy, and the 9.3 headers.

What this is
    `SecurityHeadersMiddleware` (pure ASGI) adds the security headers to every response the public app sends.
    `page_csp(nonce)` builds the Content-Security-Policy for Roxy's own pages, `PROXIED_CSP` is the policy for
    proxied Roblox content, and `mark_proxied(scope)` is how the proxy router says "this response is upstream
    content". `standalone_headers(scope)` is the full set for responses built outside this middleware (the
    deadline 504, the unhandled error 500), which add it themselves.

Why it exists
    The dashboard shows attacker-controlled text by design (user agents, header values, probe paths). Escaping
    (Jinja2 autoescape) is the first defense; a strict CSP is the net for the day a template forgets. A nonce is
    a random value generated per response: only `<script>` and `<style>` tags carrying it may run, so an injected
    tag cannot, because the attacker cannot know the nonce of a response that has not been sent yet. That only
    holds if the nonce is new for EVERY response (plan 9.2), which is why it is made here and not once at startup.
    Proxied responses get `default-src 'none'; sandbox`: whatever Roblox (or an attacker who controls a Roblox
    response) returns can never run script on Roxy's origin.

How it works
    For each HTTP request the middleware makes a nonce (`secrets.token_urlsafe`), stores it in
    `scope["state"]["csp_nonce"]` (templates read it as `request.state.csp_nonce`), then rewrites the response
    start message: it sets the CSP for the response kind, `Reporting-Endpoints` for pages, the 9.3 headers,
    `Cross-Origin-Embedder-Policy` and `Cache-Control: no-store` under `/admin`, HSTS only when ROXY_SEND_HSTS=1
    (nginx owns HSTS, 9.1), and removes any `Server` header. Headers are set, not appended, so a route cannot
    weaken them by accident.

What to read next
    `roxy/core/templating.py` (how pages put the nonce on their tags), then `roxy/proxy/respond.py` (which calls
    `mark_proxied`).
"""

from __future__ import annotations

import secrets
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

STATE_CSP_NONCE = "csp_nonce"
"""Key in `scope["state"]` (so `request.state.csp_nonce`) holding this response's nonce."""

STATE_RESPONSE_KIND = "response_kind"
"""Key in `scope["state"]` naming the kind of response: "page" (default) or "proxied"."""

KIND_PAGE = "page"
KIND_PROXIED = "proxied"

PROXIED_CSP = "default-src 'none'; sandbox"
"""Policy for proxied upstream content served to browsers (plan 9.2)."""

CSP_REPORT_PATH = "/csp-report"
REPORTING_ENDPOINTS = f'csp-endpoint="{CSP_REPORT_PATH}"'

PERMISSIONS_POLICY = ", ".join(
    f"{feature}=()"
    for feature in (
        "accelerometer",
        "ambient-light-sensor",
        "autoplay",
        "bluetooth",
        "browsing-topics",
        "camera",
        "display-capture",
        "encrypted-media",
        "geolocation",
        "gyroscope",
        "hid",
        "idle-detection",
        "interest-cohort",
        "magnetometer",
        "microphone",
        "midi",
        "payment",
        "picture-in-picture",
        "screen-wake-lock",
        "serial",
        "usb",
        "xr-spatial-tracking",
    )
)
"""Every powerful browser feature disabled (plan 9.3). `publickey-credentials-*` are deliberately NOT listed:
their default is "self", which passkeys on the admin pages need (plan 9.5)."""

HSTS_VALUE = "max-age=63072000; includeSubDomains"

_BASELINE: tuple[tuple[str, str], ...] = (
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("permissions-policy", PERMISSIONS_POLICY),
    ("cross-origin-opener-policy", "same-origin"),
)

# Headers this middleware owns: any copy a route set is replaced, so there is exactly one of each.
_OWNED = frozenset(
    {
        b"content-security-policy",
        b"reporting-endpoints",
        b"x-content-type-options",
        b"x-frame-options",
        b"referrer-policy",
        b"permissions-policy",
        b"cross-origin-opener-policy",
        b"cross-origin-resource-policy",
        b"cross-origin-embedder-policy",
        b"strict-transport-security",
        b"server",
    }
)


def new_nonce() -> str:
    """A fresh, unguessable CSP nonce (128 bits of randomness, base64url)."""
    return secrets.token_urlsafe(16)


def page_csp(nonce: str) -> str:
    """The exact Content-Security-Policy of plan 9.2 for Roxy's own pages, on one line."""
    return (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "manifest-src 'self'; "
        "upgrade-insecure-requests; "
        "report-to csp-endpoint; "
        f"report-uri {CSP_REPORT_PATH}"
    )


def baseline_headers() -> list[tuple[str, str]]:
    """The 9.3 headers that apply to any response, for responses built outside the middleware."""
    return [*_BASELINE, ("cross-origin-resource-policy", "same-origin")]


def _send_hsts_for(scope: MutableMapping[str, Any]) -> bool:
    """ROXY_SEND_HSTS of the app serving this request (Starlette puts the app in `scope["app"]`)."""
    env = getattr(getattr(scope.get("app"), "state", None), "env", None)
    return bool(getattr(env, "send_hsts", False))


def standalone_headers(scope: MutableMapping[str, Any]) -> list[tuple[str, str]]:
    """Every security header for a response built OUTSIDE this middleware (the deadline 504, the unhandled 500).

    Those answers are sent by middleware that wraps this one, so the middleware never sees them; without this
    they would carry no CSP, and under `/admin` no `Cache-Control: no-store` or COEP, which plan 9.3 requires on
    every admin response. Same set as `SecurityHeadersMiddleware` adds.
    """
    pairs = [
        (name.decode("latin-1"), value.decode("latin-1"))
        for name, value in security_headers_for(scope, send_hsts=_send_hsts_for(scope))
    ]
    if is_admin_path(str(scope.get("path", ""))):
        pairs.append(("cache-control", "no-store"))
    return pairs


def is_admin_path(path: str) -> bool:
    """True for `/admin` and everything under `/admin/` (but not `/administrator`)."""
    return path == "/admin" or path.startswith("/admin/")


def _state(scope: MutableMapping[str, Any]) -> dict[str, Any]:
    state = scope.setdefault("state", {})
    if not isinstance(state, dict):  # pragma: no cover - a server that put something odd here
        state = scope["state"] = {}
    return state


def mark_proxied(scope: MutableMapping[str, Any]) -> None:
    """Declare that this request's response is proxied upstream content (gets the sandbox CSP, no nonce).

    Pass `request.scope` from a route. It must be called before the response starts.
    """
    _state(scope)[STATE_RESPONSE_KIND] = KIND_PROXIED


def get_nonce(scope: MutableMapping[str, Any]) -> str:
    """The nonce of the current response (creates one if the middleware did not run, for example in a unit test)."""
    state = _state(scope)
    nonce = state.get(STATE_CSP_NONCE)
    if not isinstance(nonce, str) or not nonce:
        nonce = state[STATE_CSP_NONCE] = new_nonce()
    return nonce


def security_headers_for(scope: MutableMapping[str, Any], *, send_hsts: bool = False) -> list[tuple[bytes, bytes]]:
    """Every security header for this request's response, as raw ASGI header pairs."""
    state = _state(scope)
    path = str(scope.get("path", ""))
    kind = state.get(STATE_RESPONSE_KIND, KIND_PAGE)
    pairs: list[tuple[str, str]] = list(_BASELINE)
    if kind == KIND_PROXIED:
        pairs.append(("content-security-policy", PROXIED_CSP))
    else:
        pairs.append(("content-security-policy", page_csp(get_nonce(scope))))
        pairs.append(("reporting-endpoints", REPORTING_ENDPOINTS))
        pairs.append(("cross-origin-resource-policy", "same-origin"))
    if is_admin_path(path):
        pairs.append(("cross-origin-embedder-policy", "require-corp"))
    if send_hsts:
        pairs.append(("strict-transport-security", HSTS_VALUE))
    return [(name.encode("latin-1"), value.encode("latin-1")) for name, value in pairs]


class SecurityHeadersMiddleware:
    """Pure ASGI middleware: nonce per request, security headers on every response (plan 9.2 and 9.3)."""

    def __init__(self, app: ASGIApp, *, send_hsts: bool = False) -> None:
        self.app = app
        self.send_hsts = send_hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state = _state(scope)
        state[STATE_CSP_NONCE] = new_nonce()  # always new: a nonce reused across responses protects nothing
        admin = is_admin_path(str(scope.get("path", "")))

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in _OWNED and not (admin and name.lower() == b"cache-control")
                ]
                headers.extend(security_headers_for(scope, send_hsts=self.send_hsts))
                if admin:
                    # Admin data must never sit in a browser or proxy cache (plan 9.3).
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
