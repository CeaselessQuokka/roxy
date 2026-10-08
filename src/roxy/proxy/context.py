"""The proxy request: everything later stages need to know about one caller request, gathered once.

What this is
    `ProxyRequest`, the dataclass every stage of the proxy flow receives (abuse checks, the cache, the upstream
    service, the response builder), shaped exactly as DESIGN.md section 7 pins it plus the fields section 11.1
    adds. Also `is_browser(user_agent)` (the v1 heuristic that decides between raw JSON and escaped HTML),
    `endpoint_template(host, path)` and `FallbackOutcomeEvent` (the metrics record shape, used only while the
    metrics package is not built).

Why it exists
    v1 read the live Flask request object everywhere, so each check re-parsed headers and the query, and the path
    a rule matched was not the path that was fetched (bug B4). Gathering the facts once into a plain dataclass
    means every stage sees the same normalized values, tests can build one without a web server, and the hot path
    avoids FastAPI dependency injection and Pydantic validation per request.

How it works
    `roxy/proxy/router.py` builds one `ProxyRequest` per request from the ASGI scope and `validate.parse_target`.
    `slots=True` makes the object small and turns a typo such as `req.bypas = True` into an error instead of a
    silently added attribute. A HEAD request is carried as `method="GET"` with `is_head=True`, because HEAD runs
    as GET (same cache entry, same upstream call) and only the body is dropped at the end.
    `is_browser` keeps v1's substring list exactly, false positives included (v1 note B24: `edge` also matches
    `knowledge`), because callers depend on what they get today.

What to read next
    `roxy/proxy/validate.py` (where host, path and query come from), then `roxy/proxy/router.py`.
"""

from __future__ import annotations

import importlib
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from roxy.config.constants import PATH_TEMPLATE_FALLBACK_PLACEHOLDER, PATH_TEMPLATE_PLACEHOLDERS
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.proxy import scrub, validate

BROWSER_UA_MARKERS: tuple[str, ...] = (
    "gecko",
    "webkit",
    "blink",
    "trident",
    "edgehtml",
    "chrome",
    "safari",
    "firefox",
    "edge",
    "opera",
    "opr",
    "msie",
    "ucbrowser",
    "vivaldi",
    "brave",
    "yandex",
    "samsungbrowser",
    "mozilla",
)
"""v1 `is_browser` markers (index.py), unchanged: a User-Agent containing any of them gets HTML."""

MAX_PLACE_ID = 64
"""v1 kept at most 64 characters of the `Roblox-Id` header."""


def is_browser(user_agent: str | None) -> bool:
    """v1 heuristic: True when the lowercased User-Agent contains any browser marker."""
    lowered = (user_agent or "").lower()
    return any(marker in lowered for marker in BROWSER_UA_MARKERS)


_ID_SEGMENT = re.compile(r"\d+|[0-9a-fA-F-]{32,36}")


def _fallback_template(host: str, path: str) -> str:
    """Numeric (or UUID-like) segments become placeholders named after the segment before them."""
    segments = [segment for segment in path.split("/") if segment]
    out: list[str] = []
    for index, segment in enumerate(segments):
        if _ID_SEGMENT.fullmatch(segment):
            before = segments[index - 1].lower() if index else ""
            out.append("{" + PATH_TEMPLATE_PLACEHOLDERS.get(before, PATH_TEMPLATE_FALLBACK_PLACEHOLDER) + "}")
        else:
            out.append(segment)
    return host + "/" + "/".join(out) if out else host


_template_function: Callable[[str, str], str] | None = None


def endpoint_template(host: str, path: str) -> str:
    """The metrics endpoint template (`metrics/templating.py: template_for`), or a simple stand-in until it exists."""
    global _template_function
    if _template_function is None:
        try:
            module = importlib.import_module("roxy.metrics.templating")
            _template_function = getattr(module, "template_for", None) or _fallback_template
        except ModuleNotFoundError:
            _template_function = _fallback_template
    try:
        return str(_template_function(host, path))
    except Exception:  # a templating bug must never fail a request
        return _fallback_template(host, path)


def problem_template(problem: ReasonCode) -> str:
    """One fixed template per target problem, so scanners cannot create unbounded endpoint rows (plan P9)."""
    return f"({problem.value})"


@dataclass(slots=True)
class ProxyRequest:
    """One caller request to the proxy route (DESIGN.md sections 7 and 11.1). Add fields; never rename them."""

    request_id: str
    received_ms: int
    deadline_at: float
    """When the request deadline expires, in `time.monotonic()` seconds."""
    client_ip: str
    limit_key: str
    """The key per-IP limits count against (IPv6 grouped by `ipv6_limit_prefix`)."""
    method: str
    """Uppercase. HEAD is carried as GET (see `is_head`)."""
    host: str
    path: str
    query: list[tuple[str, str]]
    """Caller order, prettyprint removed."""
    prettyprint: bool
    body: bytes
    content_type: str | None
    headers: dict[str, str]
    """Caller headers with lowercase names, for checks only. Never forwarded as a whole (see `scrub.py`)."""
    header_names_in_order: list[str]
    user_agent: str
    place_id: str | None
    is_browser: bool
    template: str
    bypass: bool = False
    # Added by DESIGN.md section 11.1:
    target_problem: ReasonCode | None = None
    cache_key: Any = None
    """`cache/keys.py: CacheKey`, set by `cache.peek`."""
    fresh_cache_hit: bool = False
    # Added by the proxy package:
    is_head: bool = False
    """The caller sent HEAD; the request runs as GET and the response body is dropped."""
    target: str = ""
    """What rules match: host plus path without the leading slash (v1's `dst`)."""
    target_detail: str = ""
    """Why the target is refused, in plain words ("" when valid)."""
    raw_query: str = ""
    received_monotonic: float = field(default_factory=time.monotonic)
    raw_path: str = ""
    """The percent-decoded path without its leading slash, as received (v1's `dst`): ignored paths and probe
    signatures match it (`abuse/verdict.py raw_path`)."""
    csp_nonce: str | None = None
    """This response's CSP nonce, for the one HTML refusal (the challenge page, plan 10.8)."""

    @property
    def query_string(self) -> str:
        """The raw query string as received (`prettyprint` included), for logs and captures."""
        return self.raw_query

    @property
    def caller_method(self) -> str:
        """The method the caller actually sent (HEAD for a HEAD request)."""
        return "HEAD" if self.is_head else self.method

    @property
    def upstream_url(self) -> str:
        """The https URL Roblox receives for this request (valid targets only)."""
        return validate.build_upstream_url(self.host, self.path, self.query)

    def forwarded_headers(self) -> dict[str, str]:
        """The caller headers that may go upstream (plan 9.13 allowlist)."""
        return scrub.forwarded_request_headers(self.method, self.headers, self.body)

    def deadline_remaining(self) -> float:
        """Seconds left before the request deadline (never negative)."""
        return max(0.0, self.deadline_at - time.monotonic())


@dataclass(slots=True)
class FallbackOutcomeEvent:
    """The DESIGN.md section 8 `OutcomeEvent` shape, used only while `roxy/metrics/recorder.py` does not exist."""

    at_ms: int
    request_id: str
    endpoint_template: str
    host: str
    method: str
    egress: Egress
    outcome: Outcome
    reason: ReasonCode
    status: int
    source: Source
    cache_state: CacheState
    auth_class: AuthClass
    caller_bytes_in: int
    caller_bytes_out: int
    upstream_calls: int
    upstream_bytes_in: int
    upstream_bytes_out: int
    latency_ms: float
    queue_wait_ms: float
    upstream_ms: float
    client_ip: str
    place_id: str | None
    user_agent: str
    bypass: bool
    error: bool
