"""Preferences API (`/admin/api/v1/prefs`): each admin's own dashboard choices, kept on the server.

What this is
    `GET /prefs` answers the signed-in admin's preferences (every key, with the defaults filled in), the stored
    keys and the allowed values. `POST /prefs` changes some of them (a JSON object, or the form fields the design
    system's `theme.js` posts); `DELETE /prefs/{name}` forgets one (back to its default) and `DELETE /prefs`
    forgets them all. The preferences (plan 6.2 `admin_prefs`, 14.4, 14.6, 14.11):
      * `theme` (`dark`, `light`, `system`; default the `ui_default_theme` setting), `density` (`comfortable`,
        `dense`), `shortcuts` (single-key shortcuts `on` or `off`, plan 14.6 with WCAG 2.1.4), `sidebar` (`open`,
        `collapsed`);
      * `timezone` (an IANA zone, or empty to follow the `ui_timezone` setting), `default_range` and `compare`
        (the time picker's defaults, plan 14.2);
      * `live_filters` (the Live page's remembered filters), `tables` (per table: page size and hidden columns,
        plan 14.5) and `panels` (per "How to read this page" panel: open or closed).

Why it exists
    v1 remembered page sizes and collapsed sections per browser only. Plan 6.2 gives each admin a server-side
    `admin_prefs` table, so the dashboard looks the same on the owner's laptop and phone, and the server can render
    the saved theme into the first paint (no flash of the wrong colors, `static/js/theme.js`).

How it works
    One `admin_prefs` row per preference (`user_id`, `key`, `value_json`, `updated_at`); a table's choices are the
    row `table:<id>` and a panel's `panel:<id>`, so one change never rewrites the others. Every value is checked by
    `PrefsUpdate` (unknown fields refused, strings and maps bounded, plan 9.9); the remembered tables and panels
    are capped (`MAX_TABLES`, `MAX_PANELS`) and the least recently changed one is forgotten first (plan P9).
    Preferences change nothing about the service, so they are neither audited nor part of `config_version`; the
    routes still need the session, and the writes the CSRF header (plan 9.6). The SQL lives here: `admin_prefs`
    has no other reader or writer.

What to read next
    `static/js/theme.js` and `static/js/dom.js` (what the browser remembers), `roxy/admin/api/common.py`.
"""

from __future__ import annotations

import json
import re
import sqlite3
import zoneinfo
from typing import Annotated, Any, Final, Literal
from urllib.parse import parse_qsl

from fastapi import Path, Request
from pydantic import Field, ValidationError, field_validator

from roxy.admin.api import common
from roxy.admin.api.common import AdminSession, ApiBody, CsrfChecked
from roxy.deps import get_ctx

router = common.area_router("prefs")

THEMES: Final = ("dark", "light", "system")
DENSITIES: Final = ("comfortable", "dense")
SWITCH: Final = ("on", "off")
SIDEBAR: Final = ("open", "collapsed")
RANGE_CHOICES: Final[tuple[str, ...]] = tuple(key for key in common.RANGE_KEYS if key != "custom")
COMPARE_CHOICES: Final[tuple[str, ...]] = common.COMPARE_KEYS
LIVE_FILTER_KEYS: Final = ("outcome", "status", "egress", "cache_state", "client", "endpoint", "reason", "method")
SCALAR_KEYS: Final = ("theme", "density", "shortcuts", "sidebar", "timezone", "default_range", "compare")
GROUP_KEYS: Final = ("live_filters", "tables", "panels")
TABLE_PREFIX: Final = "table:"
PANEL_PREFIX: Final = "panel:"
LIVE_KEY: Final = "live_filters"

MAX_TABLES: Final = 100
MAX_PANELS: Final = 200
MAX_HIDDEN_COLUMNS: Final = 50
MAX_FILTER_CHARS: Final = 200
MAX_BODY_BYTES: Final = 64 * 1024
MAX_FORM_FIELDS: Final = 16
"""Bounds of one admin's preferences and of one request (plan P9)."""

_ID_RE: Final = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,63}")
FORM_TYPE: Final = "application/x-www-form-urlencoded"
DEFAULTS: Final[dict[str, Any]] = {
    "density": "comfortable",
    "shortcuts": "on",
    "sidebar": "open",
    "timezone": "",
    "default_range": common.DEFAULT_RANGE,
    "compare": "none",
}


def _check_id(value: str, what: str) -> str:
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"A {what} id is 1 to 64 lowercase letters, digits, '_', '.', ':' or '-'.")
    return value


class TablePref(ApiBody):
    """One table's remembered page size and hidden columns."""

    page_size: int | None = None
    hidden: list[Annotated[str, Field(max_length=64)]] = Field(default_factory=list, max_length=MAX_HIDDEN_COLUMNS)

    @field_validator("page_size")
    @classmethod
    def _size(cls, value: int | None) -> int | None:
        if value is not None and value not in common.PAGE_SIZES:
            raise ValueError(f"Choose one of: {', '.join(str(size) for size in common.PAGE_SIZES)}.")
        return value

    @field_validator("hidden")
    @classmethod
    def _columns(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(_check_id(item, "column") for item in value))


class PrefsUpdate(ApiBody):
    """`POST /prefs`: the preferences to change; a field left out is unchanged. In `tables` and `panels`, a
    `null` forgets that one entry."""

    theme: Literal["dark", "light", "system"] | None = None
    density: Literal["comfortable", "dense"] | None = None
    shortcuts: Literal["on", "off"] | None = None
    sidebar: Literal["open", "collapsed"] | None = None
    timezone: str | None = Field(default=None, max_length=64)
    default_range: str | None = Field(default=None, max_length=16)
    compare: str | None = Field(default=None, max_length=16)
    live_filters: dict[str, Annotated[str, Field(max_length=MAX_FILTER_CHARS)]] | None = Field(
        default=None, max_length=len(LIVE_FILTER_KEYS)
    )
    tables: dict[str, TablePref | None] | None = Field(default=None, max_length=MAX_TABLES)
    panels: dict[str, bool | None] | None = Field(default=None, max_length=MAX_PANELS)

    @field_validator("timezone")
    @classmethod
    def _zone(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        try:
            zoneinfo.ZoneInfo(value)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            raise ValueError("Use an IANA time zone such as America/New_York, or leave it empty.") from None
        return value

    @field_validator("default_range")
    @classmethod
    def _range(cls, value: str | None) -> str | None:
        if value is not None and value not in RANGE_CHOICES:
            raise ValueError(f"Choose one of: {', '.join(RANGE_CHOICES)}.")
        return value

    @field_validator("compare")
    @classmethod
    def _compare(cls, value: str | None) -> str | None:
        if value is not None and value not in COMPARE_CHOICES:
            raise ValueError(f"Choose one of: {', '.join(COMPARE_CHOICES)}.")
        return value

    @field_validator("live_filters")
    @classmethod
    def _filters(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is None:
            return value
        unknown = sorted(set(value) - set(LIVE_FILTER_KEYS))
        if unknown:
            raise ValueError(f"Live filters are: {', '.join(LIVE_FILTER_KEYS)}.")
        return {key: text.strip() for key, text in value.items() if text.strip()}

    @field_validator("tables")
    @classmethod
    def _tables(cls, value: dict[str, TablePref | None] | None) -> dict[str, TablePref | None] | None:
        if value is not None:
            for name in value:
                _check_id(name, "table")
        return value

    @field_validator("panels")
    @classmethod
    def _panels(cls, value: dict[str, bool | None] | None) -> dict[str, bool | None] | None:
        if value is not None:
            for name in value:
                _check_id(name, "panel")
        return value


# ================================================================================================ storage


def _read_rows(conn: sqlite3.Connection, user_id: int) -> dict[str, tuple[Any, int]]:
    rows = conn.execute(
        "SELECT key, value_json, updated_at FROM admin_prefs WHERE user_id = ? ORDER BY key LIMIT ?",
        (user_id, len(SCALAR_KEYS) + 1 + MAX_TABLES + MAX_PANELS + 50),
    ).fetchall()
    out: dict[str, tuple[Any, int]] = {}
    for key, text, updated_at in rows:
        try:
            out[str(key)] = (json.loads(text), int(updated_at or 0))
        except ValueError:
            continue  # a damaged row is ignored and overwritten by the next change
    return out


def _upsert(conn: sqlite3.Connection, user_id: int, key: str, value: Any, now: int) -> None:
    conn.execute(
        "INSERT INTO admin_prefs (user_id, key, value_json, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (user_id, key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        (user_id, key, json.dumps(value, separators=(",", ":")), now),
    )


def _cap(conn: sqlite3.Connection, user_id: int, prefix: str, cap: int) -> int:
    """Forget the least recently changed `prefix` rows beyond `cap` (plan P9 eviction). Returns rows removed."""
    end = prefix + "\U0010ffff"
    count = int(
        conn.execute(
            "SELECT count(*) FROM admin_prefs WHERE user_id = ? AND key >= ? AND key < ?", (user_id, prefix, end)
        ).fetchone()[0]
    )
    if count <= cap:
        return 0
    return conn.execute(
        "DELETE FROM admin_prefs WHERE user_id = ? AND key IN (SELECT key FROM admin_prefs WHERE user_id = ? "
        "AND key >= ? AND key < ? ORDER BY updated_at, key LIMIT ?)",
        (user_id, user_id, prefix, end, count - cap),
    ).rowcount


def apply_update(conn: sqlite3.Connection, user_id: int, update: PrefsUpdate, now: int) -> int:
    """Write one validated update in the caller's transaction. Returns how many rows changed."""
    changed = 0
    for key in SCALAR_KEYS:
        value = getattr(update, key)
        if value is not None:
            _upsert(conn, user_id, key, value, now)
            changed += 1
    if update.live_filters is not None:
        _upsert(conn, user_id, LIVE_KEY, update.live_filters, now)
        changed += 1
    for name, table in (update.tables or {}).items():
        row_key = TABLE_PREFIX + name
        if table is None:
            changed += conn.execute(
                "DELETE FROM admin_prefs WHERE user_id = ? AND key = ?", (user_id, row_key)
            ).rowcount
        else:
            _upsert(conn, user_id, row_key, table.model_dump(), now)
            changed += 1
    for name, is_open in (update.panels or {}).items():
        row_key = PANEL_PREFIX + name
        if is_open is None:
            changed += conn.execute(
                "DELETE FROM admin_prefs WHERE user_id = ? AND key = ?", (user_id, row_key)
            ).rowcount
        else:
            _upsert(conn, user_id, row_key, bool(is_open), now)
            changed += 1
    _cap(conn, user_id, TABLE_PREFIX, MAX_TABLES)
    _cap(conn, user_id, PANEL_PREFIX, MAX_PANELS)
    return changed


def effective(rows: dict[str, tuple[Any, int]], *, default_theme: str) -> dict[str, Any]:
    """Every preference with the defaults filled in (stored values that no longer validate fall back)."""
    prefs: dict[str, Any] = {"theme": default_theme if default_theme in THEMES else "dark", **DEFAULTS}
    allowed: dict[str, tuple[str, ...]] = {
        "theme": THEMES,
        "density": DENSITIES,
        "shortcuts": SWITCH,
        "sidebar": SIDEBAR,
        "default_range": RANGE_CHOICES,
        "compare": COMPARE_CHOICES,
    }
    for key in SCALAR_KEYS:
        if key not in rows:
            continue
        value = rows[key][0]
        if key == "timezone":
            if isinstance(value, str):
                prefs[key] = value
        elif value in allowed[key]:
            prefs[key] = value
    live = rows.get(LIVE_KEY, ({}, 0))[0]
    prefs["live_filters"] = live if isinstance(live, dict) else {}
    prefs["tables"] = {
        key[len(TABLE_PREFIX) :]: value for key, (value, _at) in rows.items() if key.startswith(TABLE_PREFIX)
    }
    prefs["panels"] = {
        key[len(PANEL_PREFIX) :]: bool(value) for key, (value, _at) in rows.items() if key.startswith(PANEL_PREFIX)
    }
    return prefs


async def _answer(ctx: Any, user_id: int) -> dict[str, Any]:
    rows = await ctx.dbs.control.read(lambda conn: _read_rows(conn, user_id))
    default_theme = str(ctx.settings.get("ui_default_theme") or "dark")
    return {
        "prefs": effective(rows, default_theme=default_theme),
        "stored": sorted(rows),
        "defaults": {"theme": default_theme, **DEFAULTS, "live_filters": {}, "tables": {}, "panels": {}},
        "ui_timezone": str(ctx.settings.get("ui_timezone") or "UTC"),
        "options": {
            "theme": list(THEMES),
            "density": list(DENSITIES),
            "shortcuts": list(SWITCH),
            "sidebar": list(SIDEBAR),
            "default_range": list(RANGE_CHOICES),
            "compare": list(COMPARE_CHOICES),
            "live_filters": list(LIVE_FILTER_KEYS),
            "page_size": list(common.PAGE_SIZES),
        },
    }


async def parse_update(request: Request) -> PrefsUpdate:
    """The body as `PrefsUpdate`: a JSON object, or form fields for the scalar preferences (`theme.js` posts a
    form). Missing, malformed or oversized bodies are 400 (plan 9.6), invalid values 422 (plan 9.9)."""
    raw = await request.body()
    if not raw:
        raise common.bad_request("This request needs a JSON object or form fields as its body.", code="missing_body")
    if len(raw) > MAX_BODY_BYTES:
        raise common.bad_request("The preferences body is too large.", code="invalid_body")
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    data: Any
    if media == FORM_TYPE:
        try:
            pairs = parse_qsl(raw.decode("utf-8"), strict_parsing=True, max_num_fields=MAX_FORM_FIELDS)
        except (UnicodeDecodeError, ValueError):
            raise common.bad_request("The form body could not be read.", code="invalid_body") from None
        data = dict(pairs)
        group_fields = sorted(set(data) & set(GROUP_KEYS))
        if group_fields:
            raise common.validation_error(dict.fromkeys(group_fields, "Send this preference as JSON."))
    else:
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            raise common.bad_request("The request body is not valid JSON.", code="invalid_json") from None
        if not isinstance(data, dict):
            raise common.bad_request("The request body must be a JSON object.", code="invalid_body")
    try:
        return PrefsUpdate.model_validate(data)
    except ValidationError as exc:
        raise common.validation_answer(exc.errors()) from None


# ================================================================================================ routes


@router.get("")
async def get_prefs(request: Request, admin: AdminSession) -> dict[str, Any]:
    """The signed-in admin's preferences, with defaults and the allowed values."""
    return await _answer(get_ctx(request), admin.user_id)


@router.post("")
async def set_prefs(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Change some preferences (JSON object, or the form fields `theme`, `density`, ... that `theme.js` posts)."""
    update = await parse_update(request)
    ctx = get_ctx(request)
    now = int(ctx.clock.now())
    user_id = admin.user_id
    await common.run_mutation(ctx.dbs.control.write(lambda conn: apply_update(conn, user_id, update, now)))
    return await _answer(ctx, user_id)


@router.delete("")
async def reset_prefs(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Forget every preference of the signed-in admin (back to the defaults)."""
    ctx = get_ctx(request)
    user_id = admin.user_id

    def write(conn: sqlite3.Connection) -> int:
        return conn.execute("DELETE FROM admin_prefs WHERE user_id = ?", (user_id,)).rowcount

    removed = await common.run_mutation(ctx.dbs.control.write(write))
    return {**(await _answer(ctx, user_id)), "removed": removed}


@router.delete("/{name}")
async def forget_pref(
    request: Request,
    name: Annotated[str, Path(pattern=r"^[a-z_]{1,32}$")],
    admin: AdminSession,
    _csrf: CsrfChecked,
) -> dict[str, Any]:
    """Forget one preference (`theme`, ...) or one group (`tables`, `panels`, `live_filters`)."""
    if name not in SCALAR_KEYS and name not in GROUP_KEYS:
        raise common.not_found("No preference has that name.")
    ctx = get_ctx(request)
    user_id = admin.user_id

    def write(conn: sqlite3.Connection) -> int:
        if name == "tables" or name == "panels":
            prefix = TABLE_PREFIX if name == "tables" else PANEL_PREFIX
            return conn.execute(
                "DELETE FROM admin_prefs WHERE user_id = ? AND key >= ? AND key < ?",
                (user_id, prefix, prefix + "\U0010ffff"),
            ).rowcount
        return conn.execute("DELETE FROM admin_prefs WHERE user_id = ? AND key = ?", (user_id, name)).rowcount

    removed = await common.run_mutation(ctx.dbs.control.write(write))
    return {**(await _answer(ctx, user_id)), "removed": removed}


__all__ = [
    "GROUP_KEYS",
    "MAX_PANELS",
    "MAX_TABLES",
    "SCALAR_KEYS",
    "PrefsUpdate",
    "TablePref",
    "apply_update",
    "effective",
    "parse_update",
    "router",
]
