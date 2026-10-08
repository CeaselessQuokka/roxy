"""Response building: the exact bytes, status and headers a caller receives for every proxy outcome.

What this is
    `render(req, result_or_refusal, ...)` turns a refusal (from the abuse pipeline or the proxy itself) or a
    serve result (from the cache or the upstream service) into a `Rendered` answer, and `Rendered.to_response()`
    into a Starlette `Response`. `build(...)` does both. `options_rendered(req)` is the local OPTIONS answer and
    `drip_response(refusal, plan)` the streaming tarpit answer. The plan 7.13 table lives here as
    `FAILURE_ROWS`, next to the v1 texts it sends.

Why it exists
    Callers are scripts that match on exact bytes: a Roblox game reading `Roxy-Throttle-Reset`, a bot comparing a
    body with "Not a Roblox URL". Parity (plan rows 3, 4, 7, 8) means v1's wire forms survive byte for byte: a
    refusal body is a JSON string plus a newline (Flask `jsonify`, LEAD_NOTES decision 2), booleans in Roxy
    headers are `True`/`False`, prettyprint uses indent 4 with non-ASCII escaped. Where v2 deliberately differs
    (real upstream status, plan D4; failure texts as `text/plain`; the C5 dash replacements) the difference is
    written down once, here, and pinned by golden tests. Keeping every caller-visible decision in one module also
    makes the safety rules impossible to skip: only allowlisted upstream headers pass, and every answer gets
    `Cache-Control: no-store` and the request id.

How it works
    Refusals: status from the refusal, body `json.dumps(text) + "\n"` (ASCII, `\\uXXXX` escapes), type
    `application/json`, the refusal's own headers as given (rendered with v1 value forms by `header_value`; the
    abuse pipeline's are complete, a disguised one carrying exactly a genuine throttle's), plus
    `Roxy-Refusal: <reason>` only when the refusal does not name itself and is not disguised. Never wrapped in
    HTML, never pretty printed (v1 parity); the challenge page is the one refusal that is HTML itself.
    Failures (a 7.13 row): the row gives the status (or the real Roblox 5xx), the fixed text, `Retry-After`, and
    whether `Roxy-Refusal` and `Roxy-Upstream-Cooldown` are sent. The text is sent as `text/plain; charset=utf-8`
    (v1 sent these as raw text labeled JSON), except the `internal_error` row: v1 answered every unhandled error
    with `jsonify("Internal Server Error")`, so that row is the JSON string plus a newline, the same bytes the
    unhandled error middleware sends (`core/errors.py`).
    Served answers: the real upstream status (D4), the upstream body pretty printed when `?prettyprint=true`, then
    for a browser (`context.is_browser`) a textual body is wrapped as `<pre>` with v1's markupsafe escaping and
    sent as HTML; a non-browser gets `application/json` for JSON (v1's exact type, no charset) or the real
    upstream `Content-Type` replayed otherwise (plan row 4). Headers: the abuse pipeline's (the throttle snapshot
    trio), `Roxy-Cache` with `Roxy-Cache-Age` and `Roxy-Cache-TTL` for cache serves, `Roxy-Upstream-Status`,
    `Roxy-Upstream-Cooldown`, and the plan 9.13 safe upstream headers (`scrub.safe_response_headers`).
    With `compat_collapse_upstream_errors` on (v1's behavior, for old scripts), every Roblox 4xx (live or cached)
    reaches the caller exactly as v1 sent it: status 500 with Roblox's own body and content type, never pretty
    printed (v1 pretty printed only successes), still shown as `<pre>` to a browser (v1 used the same view for
    errors). v1 never replaced a Roblox error body with its own text (v1 notes pipeline.md section 7 step 4, bug
    B1), and the setting exists to reproduce v1, so its body wins over plan 7.13's compat note, which assumed v1
    sent the failure text. Every Roblox 5xx and the 502 and 504 rows become 500 with `Upstream request failed;
    please try again later.` as plan 7.13 says. Roxy's own refusals and the 429 and 503 rows are unchanged, and
    `Retry-After` is still sent. Off (plan D4, the default) passes the real status.
    Header names keep their canonical casing (`Roxy-Cache`, `Retry-After`) because Starlette would lowercase them:
    they are appended to `raw_headers` directly. The router marks every proxy response as proxied content, so the
    security middleware sends `Content-Security-Policy: default-src 'none'; sandbox` (plan 9.2), and the HTML view
    can never run script on Roxy's origin even if escaping failed.
    Drip tarpit (plan 10.6): headers at once, then whatever `plan.drip_chunks()` yields (one filler byte per
    interval), then the refusal body; `X-Accel-Buffering: no` and `Content-Encoding: identity` stop nginx from
    buffering or compressing the drip. The response's `on_close` runs exactly once, when streaming ends for any
    reason (finished, client gone, deadline), which is where the router releases the slot and records the outcome.

What to read next
    `roxy/proxy/router.py` (who calls this, and when), `roxy/proxy/scrub.py` (the header allowlists), then
    `tests/integration/test_proxy_golden.py` (every row, with the exact bytes).
"""

from __future__ import annotations

import inspect
import json
import math
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from starlette.responses import Response, StreamingResponse
from starlette.types import Receive, Scope, Send

from roxy.core.deadline import DEADLINE_BODY
from roxy.core.errors import INTERNAL_ERROR_BODY, v1_json_body
from roxy.core.reasons import REFUSAL_HEADER, AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.proxy import scrub
from roxy.proxy.context import ProxyRequest

# --- caller-facing texts (v1 strings; C5 checked) -------------------------------------------------------------------

UPSTREAM_BUSY_TEXT = "All request methods are busy right now; please try again shortly."
UPSTREAM_FAILED_TEXT = DEADLINE_BODY  # "Upstream request failed; please try again later." (one copy, core/deadline)
INTERNAL_ERROR_TEXT = INTERNAL_ERROR_BODY  # "Internal Server Error"
INVALID_URL_TEXT = "Invalid URL"
NOT_ROBLOX_TEXT = "Not a Roblox URL"
AUTH_SMUGGLING_TEXT = "Requests requiring authentication are not allowed with this proxy."

# --- media types ----------------------------------------------------------------------------------------------------

JSON_TYPE = "application/json"  # v1 jsonify and raw bodies: no charset parameter
HTML_TYPE = "text/html; charset=utf-8"
TEXT_TYPE = "text/plain; charset=utf-8"
FALLBACK_BINARY_TYPE = "application/octet-stream"

# --- header names (canonical casing, as v1 sent them) ---------------------------------------------------------------

REQUEST_ID_HEADER = "Roxy-Request-Id"
RETRY_AFTER = "Retry-After"
ROXY_CACHE = "Roxy-Cache"
ROXY_CACHE_AGE = "Roxy-Cache-Age"
ROXY_CACHE_TTL = "Roxy-Cache-TTL"
ROXY_UPSTREAM_STATUS = "Roxy-Upstream-Status"
ROXY_UPSTREAM_COOLDOWN = "Roxy-Upstream-Cooldown"
ROXY_REQUESTS_LEFT = "Roxy-Requests-Left"
ROXY_THROTTLE_RESET = "Roxy-Throttle-Reset"
ROXY_THROTTLED = "Roxy-Throttled"
ROXY_PAUSED = "Roxy-Paused"
ROXY_GLOBAL_THROTTLED = "Roxy-Global-Throttled"
ROXY_CLIENT_LIMITED = "Roxy-Client-Limited"
ROXY_BLOCKED = "Roxy-Blocked"
ROXY_ENDPOINT_LIMITED = "Roxy-Endpoint-Limited"
THROTTLE_SNAPSHOT_HEADERS = (ROXY_REQUESTS_LEFT, ROXY_THROTTLE_RESET, ROXY_THROTTLED)
"""The three headers v1 put on every proxy answer (index.py `_with_throttle_headers`)."""

CACHE_CONTROL_VALUE = "no-store"
"""Roxy's own Cache-Control on every proxy answer (plan 9.13: upstream's is never relayed)."""

ALLOWED_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
ALLOW_HEADER_VALUE = ", ".join(ALLOWED_METHODS)
NO_BODY_STATUSES = frozenset({204, 304})
DRIP_HEADERS = (("X-Accel-Buffering", "no"), ("Content-Encoding", "identity"))

CACHE_SERVE_STATES = frozenset({CacheState.HIT, CacheState.REVALIDATING, CacheState.STALE, CacheState.COALESCED})


# --- shapes this module accepts -------------------------------------------------------------------------------------


@runtime_checkable
class RefusalLike(Protocol):
    """What `render` needs from a refusal (`abuse.pipeline.Refuse` or `Refusal` below)."""

    @property
    def status(self) -> int: ...
    @property
    def body(self) -> str: ...
    @property
    def reason(self) -> ReasonCode: ...
    @property
    def headers(self) -> Mapping[str, Any]: ...
    @property
    def disguised(self) -> bool: ...


@dataclass(slots=True)
class Refusal:
    """A refusal the proxy builds itself (target problems, the upstream guard). Same fields as abuse `Refuse`."""

    status: int
    body: str
    reason: ReasonCode
    check: str = "proxy"
    headers: dict[str, Any] = field(default_factory=dict)
    tarpit_category: str | None = None
    disguised: bool = False
    message_source: str = "default"
    allow_fresh_cache_serve: bool = False
    penalty_retry_after_s: int | None = None
    detail: str = ""
    """The v1 tarpit and live-feed reason string (for example `Invalid URL (unsafe characters)`)."""
    content_type: str = JSON_TYPE

    def encoded_body(self) -> bytes:
        """The bytes sent: v1's JSON string form, or the body itself for an HTML page."""
        return refusal_body(self.body) if self.content_type == JSON_TYPE else self.body.encode("utf-8")


@dataclass(slots=True)
class ProxyResult:
    """A result with the `cache.service.ServeResult` fields (DESIGN 11.2), built by the proxy itself.

    Used for answers the proxy makes without the cache (degraded, the cache missing) and as a test fake.
    """

    reason: ReasonCode
    status: int = 200
    body: bytes = b""
    content_type: str | None = None
    upstream_headers: dict[str, str] = field(default_factory=dict)
    cache_state: CacheState = CacheState.OFF
    cache_age_s: int | None = None
    cache_ttl_s: int | None = None
    outcome: Outcome = Outcome.FAILED
    source: Source = Source.ROXY
    egress: Egress = Egress.NONE
    auth_class: AuthClass = AuthClass.ANON
    upstream_status: int | None = None
    retry_after_s: int | float | None = None
    cooldown_s: int | float | None = None
    upstream_calls: int = 0
    upstream_bytes_in: int = 0
    upstream_bytes_out: int = 0
    queue_wait_ms: float = 0.0
    upstream_ms: float = 0.0
    trace: Any = None
    stale_after_failure: bool = False


@dataclass(frozen=True, slots=True)
class FailureRow:
    """One plan 7.13 row for an answer Roxy writes itself."""

    status: int | None
    """Caller status; None means the real Roblox 5xx status (row `upstream_5xx`)."""
    text: str
    retry_default: int
    retry_sources: tuple[str, ...] = ()
    """Result attributes tried in order for Retry-After before `retry_default` (plan 7.13 "remaining" values)."""
    refusal_header: bool = True
    cooldown_header: bool = False
    collapsible: bool = False
    """True when `compat_collapse_upstream_errors` turns this row into a 500 (Roblox 5xx, 502, 504)."""
    json_string: bool = False
    """True when v1 sent this text with `jsonify` (a JSON string plus a newline, `application/json`)."""


FAILURE_ROWS: dict[ReasonCode, FailureRow] = {
    ReasonCode.UPSTREAM_COOLDOWN: FailureRow(
        429, UPSTREAM_BUSY_TEXT, 1, ("retry_after_s", "cooldown_s"), cooldown_header=True
    ),
    ReasonCode.UPSTREAM_BUSY: FailureRow(429, UPSTREAM_BUSY_TEXT, 1, ("retry_after_s",)),
    ReasonCode.QUEUE_OVERFLOW: FailureRow(429, UPSTREAM_BUSY_TEXT, 1, ("retry_after_s",)),
    ReasonCode.UPSTREAM_5XX: FailureRow(
        None, UPSTREAM_FAILED_TEXT, 5, ("retry_after_s",), refusal_header=False, collapsible=True
    ),
    ReasonCode.UPSTREAM_TIMEOUT: FailureRow(504, UPSTREAM_FAILED_TEXT, 5, collapsible=True),
    ReasonCode.UPSTREAM_CONNECT: FailureRow(502, UPSTREAM_FAILED_TEXT, 5, collapsible=True),
    ReasonCode.DEADLINE: FailureRow(504, UPSTREAM_FAILED_TEXT, 5, collapsible=True),
    ReasonCode.COALESCE_TIMEOUT: FailureRow(503, UPSTREAM_BUSY_TEXT, 1, ("retry_after_s",)),
    ReasonCode.EGRESS_DISABLED: FailureRow(503, UPSTREAM_BUSY_TEXT, 60),
    ReasonCode.CREDENTIAL_UNAVAILABLE: FailureRow(503, UPSTREAM_BUSY_TEXT, 300, ("retry_after_s", "cooldown_s")),
    ReasonCode.DEGRADED: FailureRow(503, UPSTREAM_BUSY_TEXT, 10),
    # Not a 7.13 row: the leak guard disabled an egress mid-request. Treated like `egress_disabled`.
    ReasonCode.LEAK_BLOCKED: FailureRow(503, UPSTREAM_BUSY_TEXT, 60),
    ReasonCode.INTERNAL_ERROR: FailureRow(500, INTERNAL_ERROR_TEXT, 5, refusal_header=False, json_string=True),
}
"""Plan 7.13, the rows whose body Roxy writes. Served rows (2xx, 4xx, cache serves) pass the upstream body."""

TARGET_REFUSALS: dict[ReasonCode, tuple[int, str]] = {
    ReasonCode.UNSAFE_URL: (404, INVALID_URL_TEXT),
    ReasonCode.NOT_ROBLOX: (404, NOT_ROBLOX_TEXT),
    ReasonCode.HOST_NOT_ALLOWED: (404, NOT_ROBLOX_TEXT),
    ReasonCode.AUTH_SMUGGLING: (400, AUTH_SMUGGLING_TEXT),
}
"""Refusals the proxy can make without the abuse pipeline (v1 steps 7, 8, 9; plan 9.10 and C2 item 5)."""


def target_refusal(reason: ReasonCode) -> Refusal:
    """The refusal for a target problem or an upstream guard refusal (404 "Invalid URL", "Not a Roblox URL"...)."""
    status, text = TARGET_REFUSALS.get(reason, (404, NOT_ROBLOX_TEXT))
    category = "auth_attempt" if reason is ReasonCode.AUTH_SMUGGLING else "probe"
    return Refusal(status=status, body=text, reason=reason, tarpit_category=category)


def failure_result(reason: ReasonCode, **fields: Any) -> ProxyResult:
    """A ProxyResult for a 7.13 failure row (for example `failure_result(ReasonCode.DEGRADED)`)."""
    return ProxyResult(reason=reason, outcome=Outcome.FAILED, source=Source.ROXY, **fields)


def result_from_upstream(upstream: Any) -> ProxyResult:
    """Adapt an `upstream.service.UpstreamResult` (DESIGN 11.3) when no cache service exists."""
    reason = ReasonCode(upstream.reason)
    if reason.is_served:
        outcome, source = Outcome.SERVED_UPSTREAM, Source.ROBLOX
    elif reason.is_refusal:
        outcome, source = Outcome.REFUSED, Source.ROXY
    else:
        outcome, source = Outcome.FAILED, Source.ROXY
    return ProxyResult(
        reason=reason,
        status=int(upstream.status),
        body=_as_bytes(upstream.body),
        content_type=upstream.content_type,
        upstream_headers=dict(scrub.safe_response_headers(upstream.headers)),
        cache_state=CacheState.OFF,
        outcome=outcome,
        source=source,
        egress=Egress(upstream.egress),
        auth_class=AuthClass(upstream.auth_class),
        upstream_status=upstream.upstream_status,
        retry_after_s=upstream.retry_after_s,
        cooldown_s=upstream.cooldown_s,
        upstream_calls=int(upstream.calls),
        upstream_bytes_in=int(upstream.bytes_in),
        upstream_bytes_out=int(upstream.bytes_out),
        queue_wait_ms=float(upstream.queue_wait_ms),
        upstream_ms=float(upstream.upstream_ms),
        trace=getattr(upstream, "trace", None),
    )


# --- value forms ----------------------------------------------------------------------------------------------------


def header_value(value: Any) -> str | None:
    """A Roxy header value in v1 wire form: `True`/`False` for booleans, whole numbers without a fraction.

    None means "do not send this header".
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "True" if value else "False"  # Werkzeug wrote str(bool) (v1 note 0.1)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return str(int(value))
        return str(value)
    return str(value)


def seconds_header(value: float | int | None, *, minimum: int = 0) -> str | None:
    """Whole seconds rounded up (a client must not retry early), never below `minimum`."""
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return str(max(minimum, math.ceil(number)))


def _header_safe(name: str, value: str) -> bool:
    """No CR, LF or NUL and latin-1 encodable: a header can never split the response."""
    text = name + value
    if "\r" in text or "\n" in text or "\x00" in text:
        return False
    try:
        text.encode("latin-1")
    except UnicodeEncodeError:
        return False
    return True


def refusal_body(text: str) -> bytes:
    """v1 `jsonify(text)`: the JSON string (ASCII, non-ASCII as \\uXXXX) followed by a newline."""
    return v1_json_body(text)


def pretty_json(body: bytes) -> bytes:
    """v1 `_pretty`: `json.dumps(json.loads(body), indent=4)`; the body unchanged when it is not JSON.

    `ensure_ascii` stays on (v1 B20): `"caf\\u00e9"` style escapes, key order preserved, no trailing newline.
    """
    try:
        return json.dumps(json.loads(body), indent=4).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        return body


def markup_escape(text: str) -> str:
    """Exactly markupsafe's `escape` (what v1 used): & < > ' " become &amp; &lt; &gt; &#39; &#34;."""
    return (
        text.replace("&", "&amp;").replace(">", "&gt;").replace("<", "&lt;").replace("'", "&#39;").replace('"', "&#34;")
    )


def html_pre(body: bytes) -> bytes:
    """v1 browser view: `<pre>{escape(body)}</pre>`."""
    return ("<pre>" + markup_escape(body.decode("utf-8", "replace")) + "</pre>").encode("utf-8")


def media_type_of(content_type: str | None) -> str:
    """The lowercased media type without parameters (`application/json; charset=utf-8` -> `application/json`)."""
    return (content_type or "").split(";", 1)[0].strip().lower()


def is_json_type(content_type: str | None) -> bool:
    """JSON, or no type at all (v1 treated every body as JSON)."""
    media = media_type_of(content_type)
    return media in ("", "application/json", "text/json") or media.endswith("+json")


def is_textual_type(content_type: str | None) -> bool:
    """Text a browser should see escaped inside `<pre>`; anything else is replayed raw with its own type."""
    media = media_type_of(content_type)
    return (
        is_json_type(content_type)
        or media.startswith("text/")
        or media.endswith("+xml")
        or media in ("application/xml", "application/javascript", "application/x-www-form-urlencoded")
    )


def _as_bytes(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, bytes | bytearray | memoryview):
        return bytes(body)
    return str(body).encode("utf-8")


# --- the rendered answer --------------------------------------------------------------------------------------------


class _HeaderList:
    """Ordered headers keyed case-insensitively; setting a name again replaces its value in place."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[str, str]] = {}

    def set(self, name: str, value: Any) -> None:
        text = header_value(value)
        if text is None or not _header_safe(name, text):
            return
        self._items[name.lower()] = (name, text)

    def setdefault(self, name: str, value: Any) -> None:
        if name.lower() not in self._items:
            self.set(name, value)

    def items(self) -> list[tuple[str, str]]:
        return list(self._items.values())


@dataclass(slots=True)
class Rendered:
    """A finished answer: what is sent, plus what the metrics record needs."""

    status: int
    body: bytes
    content_type: str | None
    headers: list[tuple[str, str]]
    outcome: Outcome
    reason: ReasonCode
    source: Source
    cache_state: CacheState
    collapsed: bool = False
    """True when compat mode turned an upstream error into v1's 500."""
    page: bool = False
    """True for Roxy's own HTML page (the challenge refusal): it needs the page CSP with its nonce, not the
    proxied-content sandbox."""

    def header(self, name: str) -> str | None:
        """The value of one header (case-insensitive), for tests and logs."""
        lowered = name.lower()
        return next((value for key, value in self.headers if key.lower() == lowered), None)

    def raw_headers(self, *, content_length: int | None) -> list[tuple[bytes, bytes]]:
        raw: list[tuple[bytes, bytes]] = []
        if content_length is not None:
            raw.append((b"content-length", str(content_length).encode("latin-1")))
        if self.content_type:
            raw.append((b"content-type", self.content_type.encode("latin-1")))
        raw.extend((name.encode("latin-1"), value.encode("latin-1")) for name, value in self.headers)
        return raw

    def to_response(self, *, head: bool = False) -> Response:
        """A Starlette Response. For HEAD the body is dropped but Content-Length still describes it (RFC 9110)."""
        response = Response(content=b"" if head else self.body, status_code=self.status)
        allows_body = not (self.status < 200 or self.status in NO_BODY_STATUSES)
        response.raw_headers = self.raw_headers(content_length=len(self.body) if allows_body else None)
        return response


def _common_tail(headers: _HeaderList, req: ProxyRequest, cors_any_origin: bool) -> None:
    headers.set("Cache-Control", CACHE_CONTROL_VALUE)
    if cors_any_origin and req.caller_method in ("GET", "HEAD"):
        headers.set("Access-Control-Allow-Origin", "*")  # never with credentials (plan 9.4, D20)
    headers.set(REQUEST_ID_HEADER, req.request_id)


def render_refusal(
    req: ProxyRequest,
    refusal: RefusalLike,
    *,
    extra_headers: Mapping[str, Any] | None = None,
    cors_any_origin: bool = False,
) -> Rendered:
    """A refusal: JSON string body plus newline, the refusal's own headers, and `Roxy-Refusal`.

    The abuse pipeline's `Refuse.headers` is complete (`abuse/verdict.py`): it already names the refusal, and a
    disguised refusal carries exactly what a genuine throttle refusal carries (`Roxy-Refusal: throttle`), so those
    headers are copied as they are and never "corrected" from `reason`, which would unmask the disguise. Only a
    refusal that does not name itself (one the proxy built) gets `Roxy-Refusal: <reason>`, and never when it is
    disguised. `Refuse.encoded_body()` and `content_type` are honored when present (the HTML challenge page).
    """
    headers = _HeaderList()
    for name, value in (extra_headers or {}).items():
        headers.set(name, value)
    for name, value in refusal.headers.items():
        headers.set(name, value)
    reason = ReasonCode(refusal.reason)
    if not refusal.disguised:
        headers.setdefault(REFUSAL_HEADER, reason.value)
    _common_tail(headers, req, cors_any_origin)
    content_type = str(getattr(refusal, "content_type", None) or JSON_TYPE)
    encoder = getattr(refusal, "encoded_body", None)
    body = encoder() if callable(encoder) else refusal_body(refusal.body)
    return Rendered(
        status=int(refusal.status),
        body=_as_bytes(body),
        content_type=content_type,
        headers=headers.items(),
        outcome=Outcome.REFUSED,
        reason=reason,
        source=Source.ROXY,
        cache_state=CacheState.NA,
        page=media_type_of(content_type) == "text/html",
    )


def _retry_after_for(row: FailureRow, reason: ReasonCode, result: Any) -> str | None:
    for attribute in row.retry_sources:
        value = getattr(result, attribute, None)
        if value is not None:
            return seconds_header(value, minimum=1)
    if reason is ReasonCode.UPSTREAM_5XX:
        # "Retry-After: 5 (or Roblox's value)": a numeric Retry-After Roblox sent with its 5xx.
        for name, value in scrub.safe_response_headers(getattr(result, "upstream_headers", None)):
            if name == RETRY_AFTER and value.isdigit():
                return seconds_header(int(value), minimum=1)
    return str(row.retry_default)


def _upstream_5xx_status(result: Any) -> int:
    for candidate in (getattr(result, "upstream_status", None), getattr(result, "status", None)):
        if isinstance(candidate, int) and 500 <= candidate <= 599:
            return candidate
    return 502


def _cache_headers(headers: _HeaderList, result: Any) -> None:
    state = CacheState(getattr(result, "cache_state", CacheState.NA))
    if state is CacheState.NA:
        return
    headers.set(ROXY_CACHE, state.value)
    if state in CACHE_SERVE_STATES:
        headers.set(ROXY_CACHE_AGE, seconds_header(_floor(getattr(result, "cache_age_s", None))))
        headers.set(ROXY_CACHE_TTL, seconds_header(_floor(getattr(result, "cache_ttl_s", None))))


def _floor(value: Any) -> int | None:
    """v1 sent `str(int(age))`: truncated whole seconds, never negative."""
    if value is None:
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


def render_failure(
    req: ProxyRequest,
    result: Any,
    row: FailureRow,
    *,
    extra_headers: Mapping[str, Any] | None = None,
    compat_collapse: bool = False,
    cors_any_origin: bool = False,
) -> Rendered:
    """A plan 7.13 row whose body Roxy writes (busy, failed, internal error)."""
    reason = ReasonCode(result.reason)
    status = row.status if row.status is not None else _upstream_5xx_status(result)
    text = row.text
    collapsed = compat_collapse and row.collapsible
    if collapsed:
        status, text = 500, UPSTREAM_FAILED_TEXT
    headers = _HeaderList()
    headers.set(RETRY_AFTER, _retry_after_for(row, reason, result))
    for name, value in (extra_headers or {}).items():
        headers.set(name, value)
    _cache_headers(headers, result)
    headers.set(ROXY_UPSTREAM_STATUS, getattr(result, "upstream_status", None))
    if row.cooldown_header:
        headers.set(ROXY_UPSTREAM_COOLDOWN, seconds_header(getattr(result, "cooldown_s", None), minimum=0))
    if row.refusal_header:
        headers.set(REFUSAL_HEADER, reason.value)
    _common_tail(headers, req, cors_any_origin)
    as_json = row.json_string and not collapsed
    return Rendered(
        status=status,
        body=refusal_body(text) if as_json else text.encode("utf-8"),
        content_type=JSON_TYPE if as_json else TEXT_TYPE,
        headers=headers.items(),
        outcome=Outcome.FAILED,
        reason=reason,
        source=Source.ROXY,
        cache_state=CacheState(getattr(result, "cache_state", CacheState.NA)),
        collapsed=collapsed,
    )


def render_served(
    req: ProxyRequest,
    result: Any,
    *,
    extra_headers: Mapping[str, Any] | None = None,
    compat_collapse: bool = False,
    cors_any_origin: bool = False,
) -> Rendered:
    """A served answer (Roblox's status and body, live or from the cache)."""
    reason = ReasonCode(result.reason)
    status = int(result.status)
    body = _as_bytes(result.body)
    content_type: str | None = getattr(result, "content_type", None)
    source = Source(getattr(result, "source", Source.ROBLOX))
    collapsed = compat_collapse and status >= 400
    transformed = False
    if collapsed and status >= 500:
        # A Roblox 5xx served as such: plan 7.13's compat note gives it v1's failure text.
        status, body, content_type = 500, UPSTREAM_FAILED_TEXT.encode("utf-8"), TEXT_TYPE
    elif status < 200 or status in NO_BODY_STATUSES:
        body, content_type = b"", None
    else:
        if collapsed:
            # v1 never relayed a Roblox error status (bug B1): a 4xx, live or cached, reached the caller as 500
            # carrying Roblox's own body. Compat mode exists to reproduce that, so only the status changes, and
            # the body is not pretty printed (v1 pretty printed successes only).
            status = 500
        elif req.prettyprint:
            pretty = pretty_json(body)
            transformed = pretty != body
            body = pretty
        if req.is_browser and is_textual_type(content_type):
            body, content_type, transformed = html_pre(body), HTML_TYPE, True
        elif is_json_type(content_type):
            content_type = JSON_TYPE
        elif content_type is None or not scrub.is_safe_value(content_type):
            content_type = FALLBACK_BINARY_TYPE
    headers = _HeaderList()
    for name, value in (extra_headers or {}).items():
        headers.set(name, value)
    _cache_headers(headers, result)
    headers.set(ROXY_UPSTREAM_STATUS, getattr(result, "upstream_status", None))
    headers.set(ROXY_UPSTREAM_COOLDOWN, seconds_header(getattr(result, "cooldown_s", None), minimum=0))
    for name, value in scrub.safe_response_headers(getattr(result, "upstream_headers", None)):
        headers.setdefault(name, value)
    _common_tail(headers, req, cors_any_origin)
    if transformed and source is Source.ROBLOX:
        source = Source.RELAY  # Roblox's answer, reshaped by Roxy (prettyprint or the browser view)
    return Rendered(
        status=status,
        body=body,
        content_type=content_type,
        headers=headers.items(),
        outcome=Outcome(getattr(result, "outcome", Outcome.SERVED_UPSTREAM)),
        reason=reason,
        source=source,
        cache_state=CacheState(getattr(result, "cache_state", CacheState.NA)),
        collapsed=collapsed,
    )


def render(
    req: ProxyRequest,
    result: Any,
    *,
    extra_headers: Mapping[str, Any] | None = None,
    compat_collapse: bool = False,
    cors_any_origin: bool = False,
) -> Rendered:
    """Render a refusal or a serve result (DESIGN 7 `respond.build`, before the Response object is made).

    `extra_headers` are the abuse pipeline's `Allow.headers` (the throttle snapshot trio).
    """
    if isinstance(result, RefusalLike) and not hasattr(result, "cache_state"):
        return render_refusal(req, result, extra_headers=extra_headers, cors_any_origin=cors_any_origin)
    reason = ReasonCode(result.reason)
    if reason.is_refusal:
        # The upstream layer refused (for example the guard saw a public credential marker): v1's refusal.
        return render_refusal(req, target_refusal(reason), extra_headers=extra_headers, cors_any_origin=cors_any_origin)
    row = FAILURE_ROWS.get(reason)
    if row is not None:
        return render_failure(
            req,
            result,
            row,
            extra_headers=extra_headers,
            compat_collapse=compat_collapse,
            cors_any_origin=cors_any_origin,
        )
    return render_served(
        req, result, extra_headers=extra_headers, compat_collapse=compat_collapse, cors_any_origin=cors_any_origin
    )


def build(
    req: ProxyRequest,
    result: Any,
    *,
    extra_headers: Mapping[str, Any] | None = None,
    compat_collapse: bool = False,
    cors_any_origin: bool = False,
) -> Response:
    """DESIGN 7: the final Starlette Response for a refusal, a cache serve or an upstream result."""
    rendered = render(
        req, result, extra_headers=extra_headers, compat_collapse=compat_collapse, cors_any_origin=cors_any_origin
    )
    return rendered.to_response(head=req.is_head)


def options_rendered(req: ProxyRequest) -> Rendered:
    """OPTIONS answered locally (plan row 1): 204, `Allow`, no body, nothing upstream, never a probe."""
    headers = _HeaderList()
    headers.set("Allow", ALLOW_HEADER_VALUE)
    headers.set("Cache-Control", CACHE_CONTROL_VALUE)
    headers.set(REQUEST_ID_HEADER, req.request_id)
    return Rendered(
        status=204,
        body=b"",
        content_type=None,
        headers=headers.items(),
        outcome=Outcome.SERVED_UPSTREAM,
        reason=ReasonCode.OPTIONS_LOCAL,
        source=Source.ROXY,
        cache_state=CacheState.NA,
    )


# --- drip tarpit ----------------------------------------------------------------------------------------------------


def _chunk_bytes(chunk: Any) -> bytes:
    if isinstance(chunk, bytes | bytearray | memoryview):
        return bytes(chunk)
    if isinstance(chunk, str):
        return chunk.encode("utf-8")
    return b" "  # a tick without data: one space (JSON allows leading whitespace before the string)


def _takes_body(function: Callable[..., Any]) -> bool:
    """True when `plan.drip_chunks` wants the body (it then yields the body itself)."""
    try:
        parameters = inspect.signature(function).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) and p.default is p.empty for p in parameters)


async def _drip_body(plan: Any, body: bytes) -> AsyncIterator[bytes]:
    """Filler from `plan.drip_chunks()` while the hold lasts, then the refusal body."""
    function = getattr(plan, "drip_chunks", None)
    includes_body = False
    if callable(function):
        includes_body = _takes_body(function)
        source = function(body) if includes_body else function()
        if inspect.isawaitable(source):
            source = await source
        if hasattr(source, "__aiter__"):
            async for chunk in source:
                yield _chunk_bytes(chunk)
        elif isinstance(source, Iterable):
            for chunk in source:
                yield _chunk_bytes(chunk)
    if not includes_body:
        yield body


class DripResponse(StreamingResponse):
    """A streaming refusal whose `on_close` callback runs exactly once, however the stream ends."""

    def __init__(
        self,
        rendered: Rendered,
        plan: Any,
        *,
        on_close: Callable[[], Awaitable[None] | None] | None = None,
    ) -> None:
        super().__init__(_drip_body(plan, rendered.body), status_code=rendered.status)
        raw = rendered.raw_headers(content_length=None)  # streamed: no length known up front
        extra = _HeaderList()
        for name, value in DRIP_HEADERS:
            extra.set(name, value)
        plan_headers = getattr(plan, "response_headers", None)
        if isinstance(plan_headers, Mapping):
            for name, value in plan_headers.items():
                extra.setdefault(str(name), value)  # the plan may name the same two headers; send each once
        raw.extend((name.encode("latin-1"), value.encode("latin-1")) for name, value in extra.items())
        self.raw_headers = raw
        self.rendered = rendered
        self._on_close = on_close
        self._closed = False

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._on_close is not None:
            outcome = self._on_close()
            if inspect.isawaitable(outcome):
                await outcome

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self.close()


def drip_response(
    refusal: RefusalLike | Rendered,
    plan: Any,
    *,
    req: ProxyRequest | None = None,
    on_close: Callable[[], Awaitable[None] | None] | None = None,
) -> DripResponse:
    """DESIGN 11.1 step 5 `drip`: stream the refusal slowly (plan 10.6). `req` is needed for a raw refusal."""
    if isinstance(refusal, Rendered):
        rendered = refusal
    else:
        if req is None:
            raise ValueError("drip_response needs req to render a refusal")
        rendered = render_refusal(req, refusal)
    return DripResponse(rendered, plan, on_close=on_close)
