"""Security events: probes, admin logins, crawls and throttled clients, stored in the `events` table.

What this is
    The event types the Security and Protection pages read (parity rows 51, 80, 97 and the throttle watch):
    `probe` (exploit and probe attempts, v1 `exploit_attempts` and `exploit_summary`), `login` (admin login
    attempts), `crawl` (robots.txt and sitemap fetches per IP) and `throttled` (an IP that just became
    throttled, v1 `throttled_ips`). For each: a detail builder, the per-type row cap (`max_*_records`), the
    leader's cap enforcement, and the read models (paged rings and grouped summaries). `install_error_hooks`
    attaches the metrics side of `core/errors.py`: client errors become probes (`HTTP 404 via GET` plus the
    path as target; the method is a standard one or OTHER, `client_error_reason`, so a caller's own method token is
    never a signature), server errors become error signatures with `module:line` and a redacted traceback.

Why it exists
    v1 kept 20 of each in memory. v2 keeps thousands on disk, paged and filterable, and fixes v1 bug B19: a
    probe reason that embedded the raw probed URL (`Invalid URL: "<anything>"`) made every probe its own summary
    row. Here the reason is reduced to a stable signature and the URL goes to the detail, truncated and redacted.

How it works
    - Rows are ordinary `events` rows written by the recorder's batch writer. The raw client IP is kept in the
      detail for these types only, because the admin needs it to ban or allow a client; the `ip_hash` column
      (HMAC, plan 12.3) is what exports and per-client lookups use.
    - Each type has its own cap setting. `enforce_caps` (a leader job, every minute) deletes the oldest rows of
      a type beyond its cap; a cap of 0 keeps none. The global `events_max_rows` and `retention_events_days`
      still apply through the storage retention job.
    - Every read is a plain function of a connection, meant to run inside `Database.read` (one snapshot).

What to read next
    `roxy/metrics/recorder.py` (`record_probe`, `record_login`, `record_crawl`, `record_throttled`), then
    `roxy/metrics/queries.py`.
"""

from __future__ import annotations

import json
import re
import sqlite3
import traceback
from collections.abc import Callable
from typing import Any

from roxy.core.redact import redact_text

PROBE = "probe"
LOGIN = "login"
CRAWL = "crawl"
THROTTLED = "throttled"
SECURITY_TYPES: tuple[str, ...] = (PROBE, LOGIN, CRAWL, THROTTLED)

CAP_SETTINGS: dict[str, str] = {
    PROBE: "max_exploit_records",
    LOGIN: "max_login_records",
    CRAWL: "max_crawl_records",
    THROTTLED: "max_throttle_records",
}
"""Per-type row caps (plan 15.3 I: 5000 each by default, 0 keeps none)."""

DEFAULT_CAP = 5000
MAX_REASON_CHARS = 200
MAX_TARGET_CHARS = 200
MAX_UA_CHARS = 400

# v1 probe reasons that carried the raw probed URL (index.py:1997, 2002): `Invalid URL: "<dst>"`, and the 4xx
# handler's `HTTP <code> via <METHOD> <path>` (index.py:2223): the variable part becomes the target.
_URL_REASON = re.compile(r'^(Invalid URL|Non-Roblox URL): "(.*)"$', re.DOTALL)
_HTTP_REASON = re.compile(r"^(HTTP \d{3} via [A-Z]{1,12}) (.*)$", re.DOTALL)

METHOD_CLASSES: frozenset[str] = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
)
"""The methods a client error signature names; any other token is `OTHER_METHOD` (finding secfix-7)."""
OTHER_METHOD = "OTHER"
MAX_METHOD_CHARS = 32
"""How much of an unknown method token the target column keeps (redacted, never the signature)."""


def method_class(method: str | None) -> str:
    """The method as a client error signature names it: one of `METHOD_CLASSES`, else `OTHER`.

    The method is the caller's choice (any token). Keyed by the raw method, a flood with a new method per request
    would mint a new signature, summary row and event budget per request and never be folded (v1 bug B19 again,
    review round 4 finding secfix-7); a fixed set of ten classes keeps the probe log bounded per attacker effort.
    """
    return method if method in METHOD_CLASSES else OTHER_METHOD


def client_error_reason(status: int, method: str | None, path: str | None) -> str:
    """The probe log text of a client error (v1's `HTTP <code> via <METHOD> <path>`, index.py:2223).

    The signature part is `HTTP <status> via <method class>` (Roxy's own status and one of ten classes); the path,
    and for an `OTHER` method the raw method token in front of it, form the target, which `probe_signature` moves to
    its own redacted column. `POST /` still logs `HTTP 405 via POST` with target `/`, as v1 did.
    """
    cls = method_class(method)
    target = path or "/"
    if cls == OTHER_METHOD:
        target = f"{(method or '?')[:MAX_METHOD_CHARS]} {target}"
    return f"HTTP {int(status)} via {cls} {target}"[:MAX_REASON_CHARS]


def probe_signature(reason: str) -> tuple[str, str]:
    """Split a probe reason into a stable signature and the variable target (fix for v1 bug B19).

    `Invalid URL: "x.example/a"` gives `("Invalid URL", "x.example/a")`; any other reason is its own signature
    (truncated to 200 characters, like v1's 4xx handler) with an empty target.
    """
    text = (reason or "Unknown").strip()
    match = _URL_REASON.match(text) or _HTTP_REASON.match(text)
    if match:
        return match.group(1), match.group(2)[:MAX_TARGET_CHARS]
    return text[:MAX_REASON_CHARS], ""


def probe_detail(ip: str, reason: str, user_agent: str | None, path: str | None = None) -> tuple[str, dict[str, Any]]:
    """`(signature, detail)` for a probe event. Target and path are redacted (they are attacker supplied)."""
    signature, target = probe_signature(reason)
    detail: dict[str, Any] = {"ip": (ip or "unknown")[:64], "user_agent": (user_agent or "")[:MAX_UA_CHARS]}
    if target:
        detail["target"] = redact_text(target)
    if path:
        detail["path"] = redact_text(path.split("?", 1)[0])[:MAX_TARGET_CHARS]
    return redact_text(signature), detail


def login_detail(ip: str, successful: bool, username: str | None = None, method: str = "") -> dict[str, Any]:
    """Detail of an admin login attempt (v1 `log_login_attempt`: IP, date, success)."""
    detail: dict[str, Any] = {"ip": (ip or "unknown")[:64], "successful": bool(successful)}
    if username:
        detail["username"] = username[:64]
    if method:
        detail["method"] = method[:32]
    return detail


def crawl_detail(ip: str, path: str, user_agent: str | None) -> dict[str, Any]:
    """Detail of a robots.txt or sitemap fetch (v1 `log_crawl`, which kept only a count per IP)."""
    return {"ip": (ip or "unknown")[:64], "path": path[:64], "user_agent": (user_agent or "")[:MAX_UA_CHARS]}


def throttled_detail(ip: str, tier: int | None = None, strikes: int | None = None) -> dict[str, Any]:
    """Detail of a client that just became throttled (v1 `log_throttle`)."""
    detail: dict[str, Any] = {"ip": (ip or "unknown")[:64]}
    if tier is not None:
        detail["tier"] = int(tier)
    if strikes is not None:
        detail["strikes"] = int(strikes)
    return detail


# --------------------------------------------------------------------------------------------- error hooks


def describe_exception(exc: BaseException | None) -> tuple[str, str, str]:
    """`(signature, module:line, traceback)` for the errors table (row 72): the signature is v1's
    `"{Type}: {error}"`, `module:line` the raising frame inside Roxy, the traceback its last 20 frames."""
    if exc is None:
        return "Unknown error", "", ""
    signature = f"{type(exc).__name__}: {exc}"[:200]
    frames = traceback.extract_tb(exc.__traceback__)[-20:]
    module_line = ""
    for frame in reversed(frames):
        marker = frame.filename.replace("\\", "/").rfind("/roxy/")
        if marker >= 0:
            module_line = f"{frame.filename[marker + 1 :]}:{frame.lineno}"
            break
    if not module_line and frames:
        module_line = f"{frames[-1].filename.rsplit('/', 1)[-1]}:{frames[-1].lineno}"
    text = "".join(traceback.format_list(frames)) + f"{type(exc).__name__}: {exc}"
    return signature, module_line, text


def install_error_hooks(hooks: Any, recorder: Callable[[], Any]) -> None:
    """Attach the metrics side of `core/errors.py` hooks: client errors become probes (v1 logged every 4xx as
    `HTTP <code> via <METHOD> <path>`), server errors become error signatures (v1 `log_error`).

    `recorder()` returns `ctx.recorder` (or None while it is not built); both hooks are best effort.
    """

    def client_error(event: Any) -> None:
        rec = recorder()
        if rec is None:
            return
        reason = client_error_reason(event.status, event.method, event.path)  # signature: status and method class
        rec.record_probe(event.client_ip or "unknown", reason, event.user_agent, event.path)

    def server_error(event: Any) -> None:
        rec = recorder()
        if rec is None:
            return
        signature, module_line, text = describe_exception(event.exc)
        lines = (f"{event.method} {event.path}", f"IP: {event.client_ip or 'unknown'}", f"Request: {event.request_id}")
        detail = "\n".join(lines)  # v1 detail shape: "{METHOD} {path}", then the client IP
        rec.record_error(signature, detail=detail, source="roxy", module_line=module_line, traceback=text)

    hooks.add("client_error", client_error)
    hooks.add("server_error", server_error)


# ------------------------------------------------------------------------------------------------ caps


def enforce_caps(conn: sqlite3.Connection, get: Callable[[str], Any], *, limit: int = 5000) -> dict[str, int]:
    """Delete the oldest rows of each security type beyond its cap (at most `limit` rows per type per call)."""
    deleted: dict[str, int] = {}
    for event_type, key in CAP_SETTINGS.items():
        try:
            cap = max(0, int(get(key)))
        except (KeyError, LookupError, TypeError, ValueError):
            cap = DEFAULT_CAP
        count = int(conn.execute("SELECT count(*) FROM events WHERE type = ?", (event_type,)).fetchone()[0])
        excess = min(count - cap, limit)
        if excess > 0:
            cur = conn.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE type = ? ORDER BY id LIMIT ?)",
                (event_type, excess),
            )
            deleted[event_type] = cur.rowcount
    return deleted


# ------------------------------------------------------------------------------------------------- reads


def _detail(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def ring(
    conn: sqlite3.Connection,
    event_type: str,
    *,
    since_ms: int | None = None,
    until_ms: int | None = None,
    ip: str | None = None,
    reason: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Newest-first page of one security type, with the total for the pager (server-side paging, row 89)."""
    where = ["type = ?"]
    params: list[Any] = [event_type]
    if since_ms is not None:
        where.append("at_ms >= ?")
        params.append(int(since_ms))
    if until_ms is not None:
        where.append("at_ms < ?")
        params.append(int(until_ms))
    if ip:
        where.append("json_extract(detail_json, '$.ip') = ?")
        params.append(ip)
    if reason:
        where.append("reason_code = ?")
        params.append(reason)
    clause = " AND ".join(where)
    total = int(conn.execute(f"SELECT count(*) FROM events WHERE {clause}", params).fetchone()[0])  # noqa: S608 (fixed clauses)
    rows = conn.execute(
        f"SELECT id, at_ms, severity, reason_code, detail_json FROM events WHERE {clause} "  # noqa: S608 (fixed clauses)
        "ORDER BY id DESC LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), 1000)), max(0, int(offset))),
    ).fetchall()
    items = []
    for row in rows:
        detail = _detail(row["detail_json"])
        items.append(
            {
                "id": int(row["id"]),
                "at_ms": int(row["at_ms"]),
                "severity": row["severity"],
                "reason": row["reason_code"],
                "count": int(detail.pop("count", 1)),
                **detail,
            }
        )
    return {"total": total, "items": items}


def summary_by_reason(
    conn: sqlite3.Connection, event_type: str, since_ms: int, until_ms: int, limit: int = 100
) -> list[dict[str, Any]]:
    """Grouped by reason (the v1 probe summary): count (aggregated rows weighted), first and last seen."""
    rows = conn.execute(
        """
        SELECT reason_code, sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n,
               min(at_ms) AS first_ms, max(at_ms) AS last_ms
        FROM events WHERE type = ? AND at_ms >= ? AND at_ms < ?
        GROUP BY reason_code ORDER BY n DESC, last_ms DESC LIMIT ?
        """,
        (event_type, int(since_ms), int(until_ms), max(1, int(limit))),
    ).fetchall()
    return [
        {"reason": r["reason_code"], "count": int(r["n"]), "first_ms": int(r["first_ms"]), "last_ms": int(r["last_ms"])}
        for r in rows
    ]


def summary_by_ip(
    conn: sqlite3.Connection, event_type: str, since_ms: int, until_ms: int, limit: int = 100
) -> list[dict[str, Any]]:
    """Grouped by client IP (v1 `crawls` and `throttled_ips`: count and last time), busiest first."""
    rows = conn.execute(
        """
        SELECT json_extract(detail_json, '$.ip') AS ip, sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n,
               max(at_ms) AS last_ms
        FROM events WHERE type = ? AND at_ms >= ? AND at_ms < ?
        GROUP BY ip ORDER BY n DESC, last_ms DESC LIMIT ?
        """,
        (event_type, int(since_ms), int(until_ms), max(1, int(limit))),
    ).fetchall()
    return [{"ip": r["ip"], "count": int(r["n"]), "last_ms": int(r["last_ms"])} for r in rows]
