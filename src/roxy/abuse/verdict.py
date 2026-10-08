"""Verdicts: what the abuse pipeline answers for one request (`Allow` or `Refuse`) and the request shape it reads.

What this is
    `Allow` and `Refuse` (DESIGN.md sections 7 and 11.5), the response header names the abuse layer sets, the v1
    wire form of a refusal body, and `AbuseRequest`, the attributes of `proxy/context.py ProxyRequest` this package
    reads (a Protocol, so tests can pass a small dataclass and the abuse layer never imports the proxy package).

Why it exists
    Every refusal must be byte for byte what v1 sent (plan 4.1 row 7, golden tests), carry the v1 `Roxy-*` headers
    (row 8), and say why in `Roxy-Refusal` unless the refusal is deliberately disguised as an ordinary throttle. One
    small, frozen vocabulary keeps the twenty checks consistent and lets `proxy/respond.py` build the response
    without knowing which check refused.

How it works
    - `Refuse.body` is the message TEXT. `Refuse.encoded_body()` is the v1 wire form: the JSON encoding of the text
      with non-ASCII escaped (Flask `jsonify` used `ensure_ascii`) and a trailing newline, sent as
      `application/json` (lead decision 2). The challenge page is the one HTML refusal (`content_type`).
    - `Refuse.headers` is COMPLETE: it already contains `Roxy-Refusal` (or, for a disguised refusal, exactly the
      headers a genuine throttle refusal carries, `Roxy-Refusal: throttle` included). `proxy/respond.py` copies it
      as is and must not add `Roxy-Refusal` from `reason`, which would unmask a disguised refusal.
    - `reason` is always the true reason code (metrics, live feed); `disguised` says the caller was told otherwise.
    - `detail` is the v1 tarpit and live-feed reason string (for example `Rate rule: games.roblox.com/v1/*`).

What to read next
    `roxy/abuse/messages.py` (every text), then `roxy/abuse/pipeline.py`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from roxy.core.reasons import REFUSAL_HEADER, ReasonCode

# --- header names (plan 4.1 row 8; v1 index.py `_with_throttle_headers`) ----------------------------------------------

H_REQUESTS_LEFT = "Roxy-Requests-Left"
H_THROTTLE_RESET = "Roxy-Throttle-Reset"
H_THROTTLED = "Roxy-Throttled"
H_RETRY_AFTER = "Retry-After"
H_PAUSED = "Roxy-Paused"
H_BLOCKED = "Roxy-Blocked"
H_ENDPOINT_LIMITED = "Roxy-Endpoint-Limited"
H_GLOBAL_THROTTLED = "Roxy-Global-Throttled"
H_CLIENT_LIMITED = "Roxy-Client-Limited"
H_REFUSAL = REFUSAL_HEADER

TRUE = "True"
"""v1 wrote booleans with Python `str(bool)`, so header values are `True` and `False` (capitalized)."""
FALSE = "False"

JSON_CONTENT_TYPE = "application/json"
HTML_CONTENT_TYPE = "text/html; charset=utf-8"

MessageSource = Literal["custom", "default"]
"""`custom`: the text was written by an admin (a rule message, a pause reason, a ladder rung); `default`: built in."""


def encode_refusal_body(text: str) -> bytes:
    """The v1 wire form of a refusal: `jsonify(text)`, so a JSON string with non-ASCII escaped, then a newline."""
    return (json.dumps(text, ensure_ascii=True) + "\n").encode("ascii")


@dataclass(slots=True)
class Allow:
    """The request may continue. `headers` are the per-IP trio computed in the abuse transaction (plan 10.2)."""

    headers: dict[str, str] = field(default_factory=dict)
    serve_throttled_from_cache: bool = False


@dataclass(slots=True)
class Refuse:
    """Roxy refuses the request. See the module docstring for how each field is used."""

    status: int
    body: str
    reason: ReasonCode
    check: str
    headers: dict[str, str] = field(default_factory=dict)
    tarpit_category: str | None = None
    disguised: bool = False
    message_source: MessageSource = "default"
    # DESIGN.md 11.5 additions.
    allow_fresh_cache_serve: bool = False
    penalty_retry_after_s: int | None = None
    # Added by the abuse agent (DESIGN.md: add fields, never rename).
    detail: str = ""
    content_type: str = JSON_CONTENT_TYPE

    def encoded_body(self) -> bytes:
        """The bytes to send: the JSON wire form for every refusal, the page itself for the HTML challenge."""
        if self.content_type == JSON_CONTENT_TYPE:
            return encode_refusal_body(self.body)
        return self.body.encode("utf-8")


Verdict = Allow | Refuse


class AbuseRequest(Protocol):
    """The parts of `proxy/context.py ProxyRequest` the abuse layer reads (DESIGN.md sections 7 and 11.1).

    Optional extras read with `getattr` when present: `raw_path` (the request path without its leading slash, v1
    `dst`), `query_string` (raw), and `csp_nonce` (for the challenge page).
    """

    request_id: str
    client_ip: str
    limit_key: str
    method: str
    host: str
    path: str
    query: list[tuple[str, str]]
    body: bytes
    headers: dict[str, str]
    header_names_in_order: list[str]
    user_agent: str
    place_id: str | None
    is_browser: bool
    template: str
    bypass: bool
    deadline_at: float
    target_problem: ReasonCode | None
    fresh_cache_hit: bool


def request_target(req: Any) -> str:
    """`host/path` as v1's rule matchers saw it (`dst`); `rules/match.py normalize_target` lowercases it later."""
    host = str(getattr(req, "host", "") or "")
    path = str(getattr(req, "path", "") or "").lstrip("/")
    if not host:
        return path
    return f"{host}/{path}" if path else host


def raw_path(req: Any) -> str:
    """The request path without its leading slash (v1 `dst`), for ignored paths and probe signatures."""
    value = getattr(req, "raw_path", None)
    if isinstance(value, str) and value:
        return value.lstrip("/")
    return request_target(req)


def title_case_header(name: str) -> str:
    """Werkzeug's display form of a header name (`x-test` -> `X-Test`), which v1 reasons and testers showed."""
    return "-".join(part[:1].upper() + part[1:].lower() for part in name.split("-"))


__all__ = [
    "FALSE",
    "HTML_CONTENT_TYPE",
    "H_BLOCKED",
    "H_CLIENT_LIMITED",
    "H_ENDPOINT_LIMITED",
    "H_GLOBAL_THROTTLED",
    "H_PAUSED",
    "H_REFUSAL",
    "H_REQUESTS_LEFT",
    "H_RETRY_AFTER",
    "H_THROTTLED",
    "H_THROTTLE_RESET",
    "JSON_CONTENT_TYPE",
    "TRUE",
    "AbuseRequest",
    "Allow",
    "MessageSource",
    "Refuse",
    "Verdict",
    "encode_refusal_body",
    "raw_path",
    "request_target",
    "title_case_header",
]
