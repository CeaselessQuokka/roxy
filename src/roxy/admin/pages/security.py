"""The Security page (`/admin/security`, plan 14.1): sign-ins, probes, crawls, fingerprints, CSP reports, and your
sessions, trusted devices, passkeys and recovery codes.

What this is
    Eleven cards from the registry (`registry.cards_for("security")`), each rendered by its own template under
    `templates/admin/pages/security/`:
      * `admin-access`: the admin security settings (login limits, session lifetimes, the admin allowlist; the
        catalog places 17 settings here) and where you are signing in from.
      * `logins`, `probes` (the page's main table), `probe-summary`, `crawls`: the security event logs of v1 rows 25,
        27, 28 and 32 (parity rows 80 and 97), paged on the server, exportable through the API.
      * `fingerprints`: the header names (with each header's stored values, "Clear values", "Remove" and the ignore
        switch in its drawer), the User-Agents, the blocked variants and the headers whose values are not recorded
        (v1 rows 29 and 30, parity rows 79 and 134), as four tabs of one card.
      * `csp-reports`: browser reports of content the Content-Security-Policy refused on Roxy's own pages (plan 9.2).
      * `sessions`, `trusted-devices`, `passkeys`, `recovery-codes`: the signed-in admin's own account security
        (v1 Service Controls' trusted devices, plan 9.5 and 9.6).

Why it exists
    Plan 14.1 "Security", the v1 sections it replaces (rows 4, 25, 27 to 30 and 32 of the 14.1 map) and plan P6:
    every number here is read through the same helpers as `GET /admin/api/v1/security/...`
    (`roxy/admin/api/security.py ring_fetch`, `table_page`, `header_fetch` and the rest), and every change posts to
    that API (CSRF, a fresh second factor where it asks for one, the audit log), so the page and the API can never
    disagree and the page itself writes nothing.

How it works
    `page = Page("security")`; one renderer per card. Event logs follow the top bar's time range; the fingerprint
    tables count everything kept (they have no time column per request). Tables other than the probe log
    (`address=False`) keep their own state in their fragment requests. A table's requests carry `part=table` (or the
    fingerprint tab's name), and the card template then answers that table alone, so a search or a page of one table
    swaps only that table (the shared table macro swaps the element it targets with the whole answer). A
    fingerprint header row opens `part=header&name=...` in the drawer: its values and the actions for it. Every
    caller-chosen text (a probed path, a User-Agent, a header name and its values, a CSP report field) is rendered by
    `format.html caller_text`, never as markup; values a caller chose reach a URL only percent-encoded inside one
    of Roxy's own API paths.

What to read next
    `templates/admin/pages/security.html` (the layout), `static/js/pages/security.js` (tabs, passkeys, recovery
    codes), `roxy/admin/api/security.py`, `roxy/metrics/read_security.py`, `roxy/metrics/security_events.py`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any, Final
from urllib.parse import quote, urlencode

from roxy.admin.api import common
from roxy.admin.api import security as security_api
from roxy.admin.api.common import TableQuery, TableSpec
from roxy.admin.pages import fmt
from roxy.admin.pages.kit import Page, PageView, filter_chip, table_query, table_view
from roxy.metrics import read_security, security_events

page = Page("security")
router = page.router

PART: Final = "part"
"""Query parameter naming one part of a card: `table` (a table alone), a fingerprint tab, or the header drawer."""

API: Final = common.API_PREFIX
RESULTS: Final[tuple[tuple[str, str], ...]] = (
    ("all", "Every attempt"),
    ("success", "Successful"),
    ("failure", "Failed"),
)
FINGERPRINT_TABS: Final[tuple[tuple[str, str], ...]] = (
    ("headers", "Header names"),
    ("agents", "User-Agents"),
    ("blocked", "Blocked"),
    ("ignored", "Not recorded"),
)
"""The fingerprint card's tabs (id, label); each id is also its table's `part` value."""
BLOCKED_KINDS: Final[tuple[tuple[str, str], ...]] = (
    ("", "Both"),
    ("header", "Header names"),
    ("user_agent", "User-Agents"),
)
CSP_DIRECTIVES: Final[tuple[str, ...]] = (
    "script-src",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "img-src",
    "connect-src",
    "font-src",
    "default-src",
    "form-action",
    "frame-ancestors",
    "base-uri",
    "object-src",
    "manifest-src",
)
"""Directives offered by the CSP filter (plan 9.2's policy); a directive named in the address is offered too."""
SIGNATURE_OPTIONS: Final = 40
"""Most probe signatures the probe log's filter offers (the busiest in the range)."""
HEADER_VALUES_SHOWN: Final = 50
"""Values the header drawer lists (v1 `FP_VALUES_SHOWN`); the export has them all."""
HEADER_SEARCH_PAGES: Final = 8
"""Pages of 250 names the drawer searches for its exact header (the table is capped by `max_header_name_records`)."""
RECOVERY_LOW: Final = 3
"""Recovery codes left at or below which the card warns."""
RESET_FAMILY: Final[dict[str, str]] = {
    "logins": "logins",
    "probes": "probes",
    "probe-summary": "probes",
    "crawls": "crawls",
    "fingerprints": "fingerprints",
}
"""Card -> the Data page reset family that clears it (plan 6.8 "inline on page / card")."""


# ============================================================================================ helpers


def part_of(view: PageView) -> str:
    """The card part a fragment request asks for (only in fragment requests; a page render draws whole cards)."""
    return view.param(PART, max_chars=16) if view.in_fragment else ""


def choice(value: str, allowed: Sequence[str], default: str) -> str:
    return value if value in allowed else default


def newest_first(tq: TableQuery) -> tuple[TableQuery, str | None]:
    """The security logs are listed newest first only (the API refuses another order with 422): a request for
    another order shows the newest first and says so, never an error."""
    if tq.order == "desc":
        return tq, None
    return replace(tq, order="desc"), "This log is listed newest first only."


def unsortable(table: dict[str, Any]) -> dict[str, Any]:
    """A table whose order is fixed: no sort buttons in its header."""
    for column in table["columns"]:
        column["sortable"] = False
    return table


def reset_link(card_id: str) -> str:
    """The Data page's reset form with this card's family chosen (plan 6.8: resets inline next to their data)."""
    return f"/admin/data?{urlencode({'families': RESET_FAMILY[card_id]})}#resets"


def row_key(*parts: Any) -> str:
    """A short stable id for a table row named by caller text (the same in every worker, unlike `hash`)."""
    text = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.blake2s(text.encode("utf-8", "replace"), digest_size=6).hexdigest()


def api_path(*parts: str) -> str:
    """An admin API URL with each part percent-encoded (`/` included), so a header name a caller chose stays one
    path segment of Roxy's own API path (it can never name another host or step out of the path)."""
    return API + "/" + "/".join(quote(part, safe="") for part in parts)


def ms_cell(view: PageView, at_ms: Any) -> dict[str, Any] | None:
    return view.time_cell(at_ms / 1000) if isinstance(at_ms, int | float) and not isinstance(at_ms, bool) else None


def frame_extras(view: PageView, card_id: str) -> dict[str, Any]:
    return {"reset_href": reset_link(card_id) if card_id in RESET_FAMILY else "", "range": view.time.view}


# ============================================================================================ admin access


@page.card("admin-access", lazy=True)
async def admin_access_card(view: PageView) -> dict[str, Any]:
    """The admin security settings (placed by the catalog) and the facts they act on: this address, the allowlist."""
    snapshot = view.ctx.rules.snapshot
    allow = snapshot.access.allow_admin
    ip = str(view.principal.ip or "")
    return {
        "your_ip": ip,
        "allowlist_on": bool(view.ctx.settings.bool("admin_allowlist_enabled")),
        "allow_entries": len(allow),
        "you_are_allowed": bool(ip) and allow.contains(ip, view.now),
        "trusted_on": bool(view.ctx.settings.bool("admin_trusted_devices_enabled")),
        "reauth_minutes": max(1, int(view.ctx.settings.int("admin_reauth_window_s")) // 60),
    }


# ============================================================================================ event logs


@page.card("logins")
async def logins_card(view: PageView) -> dict[str, Any]:
    """Admin sign-in attempts in the range, newest first; the result filter is v1's failed logins list."""
    spec = security_api.LOGIN_SPEC
    tq, notice = table_query(view, spec, address=False)
    tq, order_note = newest_first(tq)
    result = choice(view.state_param("result", address=False), [r for r, _ in RESULTS], "all")
    fetch = security_api.ring_fetch(
        view.ctx, security_events.LOGIN, view.tr, reason=None if result == "all" else result
    )
    answer = await security_api.table_page(spec, tq, fetch, tr=view.tr)
    start, end = view.tr.window.start * 1000, view.tr.window.end * 1000

    def counts(conn: Any) -> tuple[int, int]:
        every = security_events.ring(conn, security_events.LOGIN, since_ms=start, until_ms=end, limit=1)
        failed = security_events.ring(
            conn, security_events.LOGIN, since_ms=start, until_ms=end, reason="failure", limit=1
        )
        return int(every["total"]), int(failed["total"])

    attempts, failures = await view.ctx.dbs.metrics.read(counts)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        ok = bool(item.get("successful"))
        return {
            "at_ms": ms_cell(view, item.get("at_ms")),
            "successful": {"text": "Signed in" if ok else "Failed", "tone": "ok" if ok else "bad"},
            "ip": {"text": item.get("ip"), "mono": True} if item.get("ip") else None,
        }

    table = table_view(
        view,
        "security-logins",
        spec,
        answer,
        src=view.fragment_url("logins", part="table"),
        columns=("at_ms", "successful", "ip", "username", "method"),
        labels={"successful": "Result"},
        key_columns=("at_ms", "successful", "ip"),
        cells=cells,
        row_id=lambda item: f"login-{item['id']}",
        filters=[filter_chip("result", "Result", result, list(RESULTS))],
        export_url=view.api_url("security/logins"),
        caption="Admin sign-in attempts",
        empty={
            "title": "No sign-in attempts in this range",
            "body": "Every attempt to sign in to this dashboard is written here, successful or not. Choose a longer "
            "range in the top bar to see older ones.",
            "icon": "lock",
        },
        notice=notice or order_note,
        address=False,
    )
    table["searchable"] = False
    return {
        "table": unsortable(table),
        "part": part_of(view),
        "attempts": attempts,
        "failures": failures,
        **frame_extras(view, "logins"),
    }


@page.card("probes")
async def probes_card(view: PageView) -> dict[str, Any]:
    """Probe and exploit attempts in the range, newest first (the page's main table: its filters are in the
    address, so a link such as `?signature=Invalid URL` opens the log filtered)."""
    spec = security_api.PROBE_SPEC
    tq, notice = table_query(view, spec)
    tq, order_note = newest_first(tq)
    signature = view.param("signature", max_chars=200) or None
    ip = view.param("ip", max_chars=64) or None
    fetch = security_api.ring_fetch(view.ctx, security_events.PROBE, view.tr, ip=ip, reason=signature)
    answer = await security_api.table_page(spec, tq, fetch, tr=view.tr)
    top = await security_api.probe_summary_rows(view.ctx, view.tr, limit=SIGNATURE_OPTIONS)
    options = [("", "Every signature")] + [(str(row["reason"]), f"{row['reason']} ({row['count']:,})") for row in top]
    if signature and signature not in {value for value, _ in options}:
        options.insert(1, (signature, signature))

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "at_ms": ms_cell(view, item.get("at_ms")),
            "ip": {"text": item.get("ip"), "mono": True} if item.get("ip") else None,
        }

    keep = dict(view.time.params)
    if ip:
        keep["ip"] = ip
    table = table_view(
        view,
        "security-probes",
        spec,
        answer,
        src=view.fragment_url("probes", part="table"),
        columns=("at_ms", "ip", "reason", "target", "path", "user_agent", "count"),
        key_columns=("at_ms", "reason", "ip"),
        hidden=("count",),
        cells=cells,
        row_id=lambda item: f"probe-{item['id']}",
        filters=[filter_chip("signature", "Signature", signature or "", options)],
        keep=keep,
        export_url=view.api_url("security/probes"),
        caption="Probe and exploit attempts",
        empty={
            "title": "No probes in this range",
            "body": "A probe is a request that looked for something Roxy does not have (an admin page elsewhere, a "
            "file, a script) or was not a Roblox URL. Nothing like that arrived in this range: good news.",
            "icon": "shield",
            "tone": "good",
        },
        notice=notice or order_note,
    )
    table["searchable"] = False
    return {
        "table": unsortable(table),
        "part": part_of(view),
        "ip_filter": ip,
        "clear_ip_href": view.page_url(signature=signature) + "#probes",
        **frame_extras(view, "probes"),
    }


@page.card("probe-summary")
async def probe_summary_card(view: PageView) -> dict[str, Any]:
    """Probes grouped by signature in the range (v1 "Exploit / Probe Summary"); a signature opens the log."""
    spec = security_api.SUMMARY_SPEC
    tq, notice = table_query(view, spec, address=False)
    rows = await security_api.probe_summary_rows(view.ctx, view.tr)
    answer = security_api.listed_page(spec, tq, rows, search_keys=("reason",), tr=view.tr)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        reason = str(item.get("reason") or "")
        return {
            "reason": {"text": reason, "caller": True, "href": view.page_url(signature=reason) + "#probes"},
            "first_ms": ms_cell(view, item.get("first_ms")),
            "last_ms": ms_cell(view, item.get("last_ms")),
        }

    table = table_view(
        view,
        "security-probe-summary",
        spec,
        answer,
        src=view.fragment_url("probe-summary", part="table"),
        cells=cells,
        row_id=lambda item: f"signature-{row_key(item.get('reason'))}",
        export_url=view.api_url("security/probes/summary"),
        caption="Probes by signature",
        empty={
            "title": "No probe signatures in this range",
            "body": "When scanners probe Roxy, each kind of probe is counted here once per signature, so a flood of "
            "the same probe stays one line.",
            "icon": "shield",
            "tone": "good",
        },
        search_placeholder="Search signatures",
        notice=notice,
        address=False,
    )
    return {"table": table, "part": part_of(view), **frame_extras(view, "probe-summary")}


@page.card("crawls")
async def crawls_card(view: PageView) -> dict[str, Any]:
    """robots.txt and sitemap fetches in the range by client address (v1 "Crawler Activity")."""
    spec = security_api.CRAWL_SPEC
    tq, notice = table_query(view, spec, address=False)
    rows = await security_api.crawl_rows(view.ctx, view.tr)
    answer = security_api.listed_page(spec, tq, rows, search_keys=("ip",), tr=view.tr)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        return {"ip": {"text": item.get("ip"), "mono": True}, "last_ms": ms_cell(view, item.get("last_ms"))}

    table = table_view(
        view,
        "security-crawls",
        spec,
        answer,
        src=view.fragment_url("crawls", part="table"),
        cells=cells,
        row_id=lambda item: f"crawl-{row_key(item.get('ip'))}",
        export_url=view.api_url("security/crawls"),
        caption="Crawler fetches by address",
        empty={
            "title": "No crawler fetched robots.txt in this range",
            "body": "Search engines and other crawlers read robots.txt (and the sitemap) before they look around. "
            "Each address that did is counted here.",
            "icon": "globe",
        },
        search_placeholder="Search addresses",
        notice=notice,
        address=False,
    )
    return {"table": table, "part": part_of(view), **frame_extras(view, "crawls")}


# ============================================================================================ fingerprints


def _fingerprint_table(view: PageView, tab: str, spec: TableSpec, answer: Mapping[str, Any], **options: Any) -> Any:
    return table_view(
        view,
        f"fp-{tab}",
        spec,
        answer,
        src=view.fragment_url("fingerprints", part=tab),
        address=False,
        **options,
    )


async def _headers_table(view: PageView) -> dict[str, Any]:
    spec = security_api.HEADER_SPEC
    tq, notice = table_query(view, spec, address=False)
    answer = await security_api.table_page(spec, tq, security_api.header_fetch(view.ctx, tq))

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        ignored = bool(item.get("values_ignored"))
        high = bool(item.get("high_cardinality"))
        ratio = item.get("unique_ratio")
        return {
            "value_count": "not recorded" if ignored else item.get("value_count"),
            "unique_ratio": None if ratio is None else f"{float(ratio) * 100:.0f}%",
            "values_ignored": {"text": "Not recorded", "tone": "muted"} if ignored else "Recorded",
            "high_cardinality": {"text": "Yes: consider not recording", "tone": "warn"} if high else "No",
            "first_seen": view.time_cell(item.get("first_seen")),
            "last_seen": view.time_cell(item.get("last_seen")),
        }

    return _fingerprint_table(
        view,
        "headers",
        spec,
        answer,
        columns=(
            "name",
            "count",
            "value_count",
            "values_ignored",
            "high_cardinality",
            "unique_ratio",
            "first_seen",
            "last_seen",
        ),
        key_columns=("name", "count", "value_count"),
        hidden=("unique_ratio", "first_seen"),
        cells=cells,
        row_id=lambda item: f"fp-header-{row_key(item.get('name'))}",
        drawer=lambda item: view.fragment_url("fingerprints", part="header", name=str(item["name"])),
        drawer_title=lambda item: f"Header {item['name']}",
        export_url=view.api_url("security/fingerprints/headers", time=False),
        caption="Header names callers send",
        empty={
            "title": "No header names recorded yet",
            "body": "Every request that passes every check is fingerprinted: its header names are counted here, "
            "with their values. Send traffic through Roxy to fill it.",
            "icon": "inbox",
        },
        search_placeholder="Search header names",
        notice=notice,
    )


async def _agents_table(view: PageView) -> dict[str, Any]:
    spec = security_api.UA_SPEC
    tq, notice = table_query(view, spec, address=False)
    answer = await security_api.table_page(spec, tq, security_api.user_agent_fetch(view.ctx, tq))

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "first_seen": view.time_cell(item.get("first_seen")),
            "last_seen": view.time_cell(item.get("last_seen")),
        }

    return _fingerprint_table(
        view,
        "agents",
        spec,
        answer,
        key_columns=("user_agent", "count", "last_seen"),
        hidden=("first_seen",),
        cells=cells,
        row_id=lambda item: f"fp-agent-{row_key(item.get('user_agent'))}",
        drawer_title=lambda item: "User-Agent",
        export_url=view.api_url("security/fingerprints/user-agents", time=False),
        caption="User-Agents callers send",
        empty={
            "title": "No User-Agents recorded yet",
            "body": "The User-Agent of every request that passes every check is counted here.",
            "icon": "inbox",
        },
        search_placeholder="Search User-Agents",
        notice=notice,
    )


async def _blocked_table(view: PageView) -> dict[str, Any]:
    spec = security_api.BLOCKED_SPEC
    tq, notice = table_query(view, spec, address=False)
    kind = choice(view.state_param("kind", address=False), ("header", "user_agent"), "")
    rows = await security_api.blocked_table_rows(view.ctx, view.tr, kind or None)
    answer = security_api.listed_page(spec, tq, rows, search_keys=("name", "user_agent"), tr=view.tr)
    common.add_caller_text(answer, security_api.BLOCKED_CALLER_TEXT)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        label = "Header name" if item.get("kind") == "header" else "User-Agent"
        return {"kind": label, "last_ms": ms_cell(view, item.get("last_ms"))}

    def drawer(item: Mapping[str, Any]) -> str | None:
        if item.get("kind") != "header" or not item.get("name"):
            return None
        return view.fragment_url("fingerprints", part="blocked-header", name=str(item["name"]))

    return _fingerprint_table(
        view,
        "blocked",
        spec,
        answer,
        key_columns=("kind", "name", "user_agent", "count"),
        cells=cells,
        row_id=lambda item: f"fp-blocked-{row_key(item.get('kind'), item.get('name'), item.get('user_agent'))}",
        drawer=drawer,
        drawer_title=lambda item: f"Blocked header {item.get('name') or ''}".strip(),
        filters=[filter_chip("kind", "Type", kind, list(BLOCKED_KINDS))],
        export_url=view.api_url("security/fingerprints/blocked"),
        caption="Header names and User-Agents of refused requests",
        empty={
            "title": "No request filter refused anything in this range",
            "body": "When a request filter (Protection > Request filters) refuses a request, its header names and "
            "User-Agent are counted here, so a filter that catches real callers by mistake shows up.",
            "icon": "filter",
            "tone": "good",
        },
        search_placeholder="Search refused fingerprints",
        notice=notice,
    )


async def _ignored_table(view: PageView) -> dict[str, Any]:
    spec = security_api.IGNORED_SPEC
    tq, notice = table_query(view, spec, address=False)
    rows = await security_api.ignored_rows(view.ctx)
    answer = security_api.listed_page(spec, tq, rows, search_keys=("name", "note"))

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        return {"note": {"text": item.get("note"), "caller": True} if item.get("note") else None}

    return _fingerprint_table(
        view,
        "ignored",
        spec,
        answer,
        cells=cells,
        row_id=lambda item: f"fp-ignored-{row_key(item.get('name'))}",
        drawer=lambda item: view.fragment_url("fingerprints", part="header", name=str(item["name"])),
        drawer_title=lambda item: f"Header {item['name']}",
        export_url=view.api_url("security/fingerprints/ignored", time=False),
        caption="Headers whose values are not recorded",
        empty={
            "title": "Every header's values are being recorded",
            "body": "A header whose value is different on nearly every request (a trace id, a timestamp) is better "
            "not recorded: its count is kept, its values are not.",
            "icon": "inbox",
        },
        search_placeholder="Search ignored headers",
        notice=notice,
    )


TAB_BUILDERS: Final = {
    "headers": _headers_table,
    "agents": _agents_table,
    "blocked": _blocked_table,
    "ignored": _ignored_table,
}


async def _header_drawer(view: PageView, *, blocked: bool) -> dict[str, Any]:
    """One header name in the drawer: its counts and stored values, and the actions v1 offered for it."""
    raw = view.param("name", max_chars=120)
    name = raw.lower()
    if not name or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise common.not_found("Choose a header from the table; that header name is not valid.")
    if blocked:
        requests = await view.ctx.dbs.metrics.read(lambda conn: read_security.blocked_header_count(conn, name))
        return {
            "mode": "blocked-header",
            "name": name,
            "requests": int(requests),
            "remove_url": api_path("security", "fingerprints", "blocked", "headers", name),
        }

    def read(conn: Any) -> tuple[dict[str, int], dict[str, Any] | None]:
        counts = read_security.header_counts(conn, name)
        for page_number in range(HEADER_SEARCH_PAGES):  # the one exact row among the names containing it
            listing = read_security.header_names(
                conn, search=name, sort="name", descending=False, limit=250, offset=page_number * 250
            )
            found = next((item for item in listing["rows"] if item["name"] == name), None)
            if found is not None or len(listing["rows"]) < 250:
                return counts, found
        return counts, None

    counts, row = await view.ctx.dbs.metrics.read(read)
    # The rule rows themselves (control.db), not the snapshot each worker reloads within a second: right after
    # "Stop recording" the drawer must already say so.
    ignored = name in {str(item["name"]).lower() for item in await security_api.ignored_rows(view.ctx)}
    tq = TableQuery(page=1, page_size=HEADER_VALUES_SHOWN, sort="count", order="desc")
    values = await security_api.table_page(security_api.VALUE_SPEC, tq, security_api.values_fetch(view.ctx, name, tq))
    items = [{**item, "last": fmt.time_cell(item.get("last_seen"), view.tz, view.now)} for item in values["items"]]
    return {
        "mode": "header",
        "name": name,
        "row": row,
        "known": bool(counts["headers"] or counts["values"]),
        "ignored": ignored,
        "value_rows": items,
        "values_total": int(values["total"]),
        "first": fmt.time_cell(row.get("first_seen"), view.tz, view.now) if row else None,
        "last": fmt.time_cell(row.get("last_seen"), view.tz, view.now) if row else None,
        "values_export": api_path("security", "fingerprints", "headers", name, "values") + "?format=csv",
        "clear_url": api_path("security", "fingerprints", "headers", name, "values"),
        "remove_url": api_path("security", "fingerprints", "headers", name),
        "ignore_url": f"{API}/security/fingerprints/ignored",
        "record_url": api_path("security", "fingerprints", "ignored", name),
        "shown": HEADER_VALUES_SHOWN,
    }


@page.card("fingerprints", lazy=True)
async def fingerprints_card(view: PageView) -> dict[str, Any]:
    """The four fingerprint lists as tabs (all four render on the first load; a tab's own requests answer only
    that tab's table), or one header in the drawer (`part=header` / `blocked-header`)."""
    part = part_of(view)
    if part in ("header", "blocked-header"):
        return {"part": part, "drawer": await _header_drawer(view, blocked=part == "blocked-header")}
    if part in TAB_BUILDERS:
        return {"part": part, "tables": {part: await TAB_BUILDERS[part](view)}, "tabs": FINGERPRINT_TABS}
    tables = {tab: await build(view) for tab, build in TAB_BUILDERS.items()}
    return {"part": "", "tables": tables, "tabs": FINGERPRINT_TABS, **frame_extras(view, "fingerprints")}


# ============================================================================================ CSP reports


@page.card("csp-reports")
async def csp_reports_card(view: PageView) -> dict[str, Any]:
    """Content-Security-Policy violation reports in the range, grouped by what was refused (plan 9.2)."""
    spec = security_api.CSP_SPEC
    tq, notice = table_query(view, spec, address=False)
    directive = view.state_param("directive", address=False, max_chars=64)
    if directive and not all(ch.isalpha() or ch == "-" for ch in directive):
        directive, notice = "", notice or "That directive name is not valid; every report is shown."
    answer = await security_api.table_page(
        spec, tq, security_api.csp_fetch(view.ctx, view.tr, tq, directive), tr=view.tr
    )
    options = [("", "Every directive")] + [(d, d) for d in CSP_DIRECTIVES]
    if directive and directive not in CSP_DIRECTIVES:
        options.append((directive, directive))

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        return {"last_ms": ms_cell(view, item.get("last_ms"))}

    table = table_view(
        view,
        "security-csp",
        spec,
        answer,
        src=view.fragment_url("csp-reports", part="table"),
        key_columns=("directive", "blocked", "count"),
        hidden=("source", "disposition"),
        cells=cells,
        row_id=lambda item: f"csp-{row_key(item.get('directive'), item.get('blocked'), item.get('document'))}",
        filters=[filter_chip("directive", "Directive", directive, options)],
        export_url=view.api_url("security/csp-reports"),
        caption="Content-Security-Policy reports",
        empty={
            "title": "No CSP reports in this range",
            "body": "Browsers report here when Roxy's Content-Security-Policy stops something on one of Roxy's own "
            "pages (a script or style that was not Roxy's). None arrived: good news.",
            "icon": "shield",
            "tone": "good",
        },
        notice=notice,
        address=False,
    )
    table["searchable"] = False
    return {"table": table, "part": part_of(view)}


# ============================================================================================ your account


@page.card("sessions")
async def sessions_card(view: PageView) -> dict[str, Any]:
    """Your signed-in sessions (`GET /security/sessions`); the public handle is used in action URLs only."""
    answer = await security_api.sessions_answer(view.request, view.principal)
    items = [
        {
            **item,
            "created": fmt.time_cell(item.get("created_at"), view.tz, view.now),
            "seen": fmt.time_cell(item.get("last_seen_at"), view.tz, view.now),
            "expires": fmt.time_cell(item.get("expires_at"), view.tz, None),
            "revoke_url": api_path("security", "sessions", str(item["id"]), "revoke"),
        }
        for item in answer["items"]
    ]
    others = sum(1 for item in items if not item.get("current"))
    return {
        "sessions": items,
        "others": others,
        "revoke_others_url": f"{API}/security/sessions/revoke-others",
        "revoke_all_url": f"{API}/security/sessions/revoke-all",
        "idle_minutes": max(1, int(view.ctx.settings.int("admin_session_idle_timeout_s")) // 60),
        "max_hours": max(1, int(view.ctx.settings.int("admin_session_max_age_s")) // 3600),
    }


@page.card("trusted-devices")
async def trusted_devices_card(view: PageView) -> dict[str, Any]:
    """Browsers that skip the second factor (`GET /security/trusted-devices`, v1 Trusted Devices)."""
    answer = await security_api.trusted_answer(view.request, view.principal)
    items = [
        {
            **item,
            "created": fmt.time_cell(item.get("created_at"), view.tz, view.now),
            "used": fmt.time_cell(item.get("last_used_at"), view.tz, view.now),
            "expires": fmt.time_cell(item.get("expires_at"), view.tz, None),
            "revoke_url": api_path("security", "trusted-devices", str(int(item["id"])), "revoke"),
        }
        for item in answer["items"]
    ]
    return {
        "devices": items,
        "enabled": bool(answer["enabled"]),
        "this_device": answer["this_device"],
        "days": int(view.ctx.settings.int("trusted_device_days")),
        "revoke_all_url": f"{API}/security/trusted-devices/revoke-all",
    }


@page.card("passkeys")
async def passkeys_card(view: PageView) -> dict[str, Any]:
    """Your passkeys (`GET /security/passkeys`; never the key material); rename, delete and add need a fresh
    second factor, which the forms ask for."""
    answer = await security_api.passkeys_answer(view.request)
    items = [
        {
            **item,
            "created": fmt.time_cell(item.get("created_at"), view.tz, view.now),
            "used": fmt.time_cell(item.get("last_used_at"), view.tz, view.now),
            "rename_url": api_path("security", "passkeys", str(int(item["id"]))),
        }
        for item in answer["items"]
    ]
    return {
        "passkeys": items,
        "max": int(answer["max"]),
        "full": len(items) >= int(answer["max"]),
        "options_url": f"{API}/auth/passkeys/register/options",
        "verify_url": f"{API}/auth/passkeys/register/verify",
    }


@page.card("recovery-codes")
async def recovery_codes_card(view: PageView) -> dict[str, Any]:
    """How many recovery codes are left (`GET /security/recovery-codes`, never the codes); new ones are shown once,
    by the page script, from the regenerate answer."""
    answer = await security_api.recovery_answer(view.request)
    remaining, total = int(answer["remaining"]), int(answer["total"])
    tone = "bad" if remaining == 0 else ("warn" if remaining <= RECOVERY_LOW else "ok")
    return {
        "remaining": remaining,
        "total": total,
        "tone": tone,
        "regenerate_url": f"{API}/security/recovery-codes/regenerate",
    }


__all__ = ["page", "router"]
