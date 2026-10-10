"""The Data page (`/admin/data`, plan 14.1, 6.6, 6.8, 6.10, 17.5): what Roxy stores, for how long, resets,
backups, VACUUM and exports.

What this is
    Seven cards from the registry (`registry.cards_for("data")`), each rendered by its own template under
    `templates/admin/pages/data/`:
      * `storage`: every database file and table with rows, bytes, oldest row and the 30 day projection (v1 "What's
        Being Stored", plan 14.1 row 37, parity rows 85 and 133), next to the measured growth the leader samples
        hourly (`metrics/read_producers.py disk_growth`, `table_growth`, `latest_table_sizes`, `rollup_rows_avg`).
        A table opens in the drawer with its limits and its own growth.
      * `retention` and `record-caps`: the catalog's retention and record cap settings (placed by the catalog's
        `data#retention` and `data#record-caps` anchors) with each table's state against its limits (finding
        parity-10: settings carry their card, tables their rule).
      * `resets`: the plan 6.8 reset form (every scope, the metric families with their narrower ones under their
        parent, a preview first, the typed phrase for a destructive full reset), the recent data operations, and
        where each of v1's 27 "Clear data" targets went (`scope: None` shows "Nothing to reset").
      * `backups`: the nightly backup as `backup.sh` recorded it, the last answered and any pending "Back up now"
        request, the snapshots on this server, and "Back up now" (the request for the root backup plus local copies
        where they fit; finding secfix-4).
      * `vacuum`: each database's size, reclaimable space and estimated time, and a typed VACUUM.
      * `exports`: every dataset as CSV or JSON for the top bar's range, the LLM export (copy, download, schema),
        and the export privacy settings (`data#exports`).

Why it exists
    Plan 14.1 "Data" and plan P6: the page reads through the same functions as `GET /admin/api/v1/data/...` and
    `/export/datasets` (`roxy/admin/api/data.py measure_storage`, `storage_rows`, `reset_catalog`,
    `retention_answer`, `backups_answer`, `vacuum_answer`; `roxy/admin/api/export.py datasets_answer`), and every
    change posts to those routes (CSRF, preview digests, typed phrases, a fresh second factor for the factory reset,
    the audit log), so the page changes nothing itself.

How it works
    `page = Page("data")`. The storage, retention, record cap and VACUUM cards are lazy (each measures databases on a
    maintenance connection; `measure_storage` caches a measurement per worker for a minute). A table's own requests
    carry `part=list` and the card template answers that table alone; `part=detail` answers the storage drawer.
    The reset flow and the progress of long operations (`GET /data/operations/{id}`) are `static/js/pages/data.js`;
    the preview's texts come from the API and are set as text, never as markup.

What to read next
    `templates/admin/pages/data.html` (layout and the page-level dialogs), `static/js/pages/data.js`,
    `roxy/admin/api/data.py`, `roxy/storage/read_sizes.py`, `roxy/metrics/read_producers.py`.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final, get_args
from urllib.parse import urlencode

from roxy.admin.api import common
from roxy.admin.api import data as data_api
from roxy.admin.api import export as export_api
from roxy.admin.api import export_llm as llm_api
from roxy.admin.api.audit import AUDIT_TABLE, audit_table
from roxy.admin.pages import fmt, registry
from roxy.admin.pages.kit import Page, PageView, table_query, table_view
from roxy.config import catalog
from roxy.metrics import read_producers

page = Page("data")
router = page.router

PART: Final = "part"
API: Final = common.API_PREFIX
DAY_S: Final = 86_400
GROWTH_DAYS: Final = 30
"""Days of hourly disk samples the storage card reads (the System page's persistence card reads the same span)."""
MAX_GROWTH_SAMPLES: Final = GROWTH_DAYS * 24 + 24
RECENT_OPERATIONS: Final = 8
BUDGET_WARN_PCT: Final = 90.0
"""Storage budget use from which the card warns (the disk alert's warning level, plan 17.7 as built)."""

SCOPE_LABELS: Final[dict[str, str]] = {
    "family": "Metric families",
    "date_range": "Metric families between two dates",
    "client": "One client (address or place)",
    "endpoint": "One endpoint template",
    "cache": "Cached answers",
    "bans": "Bans",
    "limiter": "Limiter state (strikes and allowances)",
    "upstream": "Upstream cooldowns and breakers",
    "recommendations": "Recommendation history",
    "health": "Health check history",
    "everything": "Everything (statistics)",
    "factory": "Factory reset",
}
"""Plain names of the plan 6.8 scopes (`data.SCOPES` has their descriptions)."""
SCOPE_FIELDS: Final[dict[str, tuple[str, ...]]] = {
    "families": ("family", "date_range"),
    "range": ("family", "date_range", "health"),
    "client": ("client",),
    "endpoint": ("endpoint",),
    "cache": ("cache",),
    "bans": ("bans",),
    "recommendations": ("recommendations",),
}
"""Which fieldsets of the reset form each scope uses (static/js/pages/data.js shows only those)."""
ACTION_WORDS: Final[dict[str, str]] = {
    "delete": "deletes rows",
    "clear_latency": "empties the latency histograms",
    "clear_cache_state": "clears the cache state",
}
STATUS_TEXT: Final[dict[str, tuple[str, str]]] = {
    "ok": ("Within its limits", "ok"),
    "pruning_due": ("Older rows wait for the next prune", "warn"),
    "over_cap": ("Over its row cap until the next prune", "bad"),
}
"""A table's `retention_status` in words, with a tone (never color alone: the words say it)."""


# ============================================================================================ helpers


def part_of(view: PageView) -> str:
    return view.param(PART, max_chars=16) if view.in_fragment else ""


def human_bytes(value: Any) -> str:
    """Bytes in binary units, as `components/format.html bytes` writes them ("n/a" for a missing value)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "n/a"
    size = float(value)
    for unit, step in (("TiB", 1024**4), ("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
        if abs(size) >= step:
            return f"{size / step:.1f} {unit}"
    return f"{size:,.0f} B"


def card_of(key: str) -> str | None:
    """The Data page card whose settings block holds `key`, if any (`retention` or `record-caps`)."""
    spec = catalog.CATALOG.get(key)
    if spec is None:
        return None
    for card_id in ("retention", "record-caps", "exports"):
        if registry.anchor("data", card_id) in spec.pages:
            return card_id
    return None


def setting_link(key: str | None, *, in_page: bool = True) -> dict[str, str] | None:
    """`{key, label, href}` for a setting named by a table's limit: its inline editor in a card of this page (the
    retention and record cap tables sit right above those editors), else (or from the drawer, `in_page=False`,
    which stays open over the page) the setting on the Settings page."""
    if not key:
        return None
    spec = catalog.CATALOG.get(key)
    if spec is None:
        return None
    card_id = card_of(key) if in_page else None
    href = f"#set-{card_id}-{key}" if card_id else f"/admin/settings?{urlencode({'key': key})}"
    return {"key": key, "label": spec.label, "href": href}


def age_text(seconds: Any) -> str:
    if isinstance(seconds, bool) or not isinstance(seconds, int | float):
        return "no age limit"
    if seconds <= 0:
        return "expired rows go at the next prune"
    days = seconds / DAY_S
    if days >= 1:
        return f"{days:,.0f} days" if days == int(days) else f"{days:,.1f} days"
    hours = seconds / 3600
    return f"{hours:,.0f} hours" if hours >= 1 else f"{int(seconds)} seconds"


def status_cell(status: Any) -> dict[str, str]:
    text, tone = STATUS_TEXT.get(str(status), (str(status or "n/a"), "muted"))
    return {"text": text, "tone": tone}


# ============================================================================================ storage


async def _growth(view: PageView) -> dict[str, Any]:
    """The measured growth: hourly disk samples over `GROWTH_DAYS`, the newest table sizes, rollup rows a minute."""
    now = int(view.now)
    since = now - GROWTH_DAYS * DAY_S

    def read(conn: Any) -> tuple[list[dict[str, Any]], dict[str, Any], float | None]:
        return (
            read_producers.disk_growth(conn, since, limit=MAX_GROWTH_SAMPLES),
            read_producers.latest_table_sizes(conn),
            read_producers.rollup_rows_avg(conn, now - 7 * DAY_S),
        )

    samples, tables, rollup_avg = await view.ctx.dbs.metrics.read(read)
    per_day = None
    span_days = 0.0
    if len(samples) >= 2:
        first, last = samples[0], samples[-1]
        span = max(1, int(last["at"]) - int(first["at"]))
        span_days = span / DAY_S
        if span >= 6 * 3600:  # fewer hours than that is not a daily rate
            per_day = (int(last["total_bytes"]) - int(first["total_bytes"])) * DAY_S / span
    return {
        "samples": len(samples),
        "spark": [round(int(s["total_bytes"]) / 1024**2, 2) for s in samples[-200:]],
        "latest": samples[-1] if samples else None,
        "per_day": per_day,
        "span_days": span_days,
        "table_sizes_at": tables.get("at"),
        "rollup_rows_per_min": rollup_avg,
    }


def _storage_cells(view: PageView) -> Any:
    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "db": {"text": item.get("db"), "mono": True},
            "table": {"text": item.get("table"), "mono": True},
            "bytes": {"text": human_bytes(item.get("bytes"))} if item.get("bytes") is not None else None,
            "projected_bytes": {"text": human_bytes(item.get("projected_bytes"))}
            if item.get("projected_bytes") is not None
            else None,
            "oldest": view.time_cell(item.get("oldest")),
            "retention_status": status_cell(item.get("retention_status")),
        }

    return cells


async def _storage_detail(view: PageView, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """One table for the drawer: its numbers, its limits (with links to their settings) and its own growth."""
    db = view.param("db", max_chars=16)
    table = view.param("table", max_chars=64)
    row = next((r for r in rows if r.get("db") == db and r.get("table") == table), None)
    if row is None:
        raise common.not_found("Choose a table from the list; that database and table are not measured.")
    since = int(view.now) - GROWTH_DAYS * DAY_S
    growth = await view.ctx.dbs.metrics.read(
        lambda conn: read_producers.table_growth(conn, db, table, since, limit=MAX_GROWTH_SAMPLES)
    )
    projection = row.get("projection_30d") or {}
    return {
        "row": row,
        "projection": projection,
        "oldest": fmt.time_cell(row.get("oldest"), view.tz, view.now),
        "newest": fmt.time_cell(row.get("newest"), view.tz, view.now),
        "age": age_text(row.get("max_age_s")) if row.get("max_age_s") is not None else None,
        "age_setting": setting_link(row.get("max_age_setting"), in_page=False),
        "cap_setting": setting_link(row.get("row_cap_setting"), in_page=False),
        "status": status_cell(row.get("retention_status")),
        "growth": [(fmt.local_time(at, view.tz, seconds=False), size) for at, size in growth[-12:]],
        "growth_spark": [round(size / 1024**2, 3) for _at, size in growth[-200:]],
        "human_bytes": human_bytes,
    }


@page.card("storage", lazy=True)
async def storage_card(view: PageView) -> dict[str, Any]:
    """Every database and table with its size and 30 day projection, and the measured growth (lazy: it scans)."""
    part = part_of(view)
    refresh = view.in_fragment and view.param("refresh") == "1"
    data = await common.run_mutation(data_api.measure_storage(view.ctx, refresh=refresh))
    rows = data_api.storage_rows(data)
    if part == "detail":
        return {"part": part, "detail": await _storage_detail(view, rows)}
    spec = data_api.STORAGE_TABLE
    tq, notice = table_query(view, spec, address=False)
    items, total = common.page_rows(rows, tq, search_keys=("db", "table", "label"))
    answer = common.table_answer(spec, tq, items, total)
    table = table_view(
        view,
        "data-storage",
        spec,
        answer,
        src=view.fragment_url("storage", part="list"),
        columns=(
            "label",
            "db",
            "table",
            "rows",
            "bytes",
            "rows_last_7d",
            "projected_rows",
            "projected_bytes",
            "oldest",
            "retention_status",
        ),
        key_columns=("label", "bytes", "retention_status"),
        hidden=("table", "rows_last_7d", "projected_rows", "oldest"),
        cells=_storage_cells(view),
        row_id=lambda item: f"table-{item['db']}-{item['table']}",
        drawer=lambda item: view.fragment_url("storage", part="detail", db=item["db"], table=item["table"]),
        drawer_title=lambda item: f"{item['db']}.{item['table']}",
        export_url=view.api_url("data/storage", time=False),
        caption="Tables of every database",
        empty={
            "title": "No table matches",
            "body": "Every table of Roxy's four databases is listed here; clear the search to see them all.",
            "icon": "database",
        },
        search_placeholder="Search tables",
        notice=notice,
        address=False,
    )
    if part == "list":
        return {"part": part, "table": table}
    budget = int(data.get("budget_bytes") or 0)
    total_bytes = int(data.get("total_bytes") or 0)
    used_pct = data.get("used_pct")
    projected = sum(int(r.get("projected_bytes") or 0) for r in rows)
    growth = await _growth(view)
    files = [
        {"name": name, **sizes, "total": int(sizes["bytes"]) + int(sizes["wal_bytes"]) + int(sizes["shm_bytes"])}
        for name, sizes in sorted((data.get("files") or {}).items())
    ]
    errors = [d for d in data.get("databases") or () if d.get("error")]
    budget_tone = (
        "bad" if used_pct is not None and used_pct >= 100 else "warn" if (used_pct or 0) >= BUDGET_WARN_PCT else "ok"
    )
    return {
        "part": "",
        "table": table,
        "total_bytes": total_bytes,
        "budget_bytes": budget,
        "used_pct": used_pct,
        "budget_tone": budget_tone,
        "projected_bytes": projected,
        "files": files,
        "folders": data.get("folders") or {},
        "growth": growth,
        "measured": fmt.time_cell(data.get("measured_at"), view.tz, view.now),
        "cached": bool(data.get("cached")),
        "method": data.get("projection_method") or "",
        "errors": errors,
        "refresh_url": view.fragment_url("storage", refresh="1"),
        "human_bytes": human_bytes,
    }


# ============================================================================================ retention and caps


def _limit_rows(answer: Mapping[str, Any], view: PageView) -> list[dict[str, Any]]:
    out = []
    for t in answer.get("tables") or ():
        out.append(
            {
                **t,
                "name": f"{t['db']}.{t['table']}",
                "age": age_text(t.get("max_age_s")) if t.get("max_age_s") is not None else None,
                "age_setting": setting_link(t.get("max_age_setting")),
                "cap_setting": setting_link(t.get("row_cap_setting")),
                "status_cell": status_cell(t.get("status")),
                "oldest_cell": fmt.time_cell(t.get("oldest"), view.tz, view.now),
            }
        )
    return out


@page.card("retention", lazy=True)
async def retention_card(view: PageView) -> dict[str, Any]:
    """Each table against its age and row limits (`GET /data/retention`); the settings are placed by the catalog."""
    answer = await data_api.retention_answer(view.ctx)
    rows = _limit_rows(answer, view)
    due = sum(1 for r in rows if r.get("status") != "ok")
    return {
        "rows": rows,
        "due": due,
        "audit_min_days": answer.get("audit_min_days"),
        "measured": fmt.time_cell(answer.get("measured_at"), view.tz, view.now),
        "human_bytes": human_bytes,
    }


@page.card("record-caps", lazy=True)
async def record_caps_card(view: PageView) -> dict[str, Any]:
    """The tables a record cap bounds, with their rows now; the cap settings are placed by the catalog."""
    keys = {spec.key for spec in registry.settings_for(registry.anchor("data", "record-caps"))}
    answer = await data_api.retention_answer(view.ctx)
    rows = [r for r in _limit_rows(answer, view) if r.get("row_cap_setting") in keys]
    return {"rows": rows, "human_bytes": human_bytes}


# ============================================================================================ resets


def _families(catalog_answer: Mapping[str, Any], chosen: set[str]) -> list[dict[str, Any]]:
    """Top-level families in catalog order, each with its narrower families (parity-9) under it."""
    every = [dict(f) for f in catalog_answer["families"]]
    for family in every:
        page_id, _, card_id = str(family.get("card") or "").partition("#")
        known = registry.known(page_id) and card_id in {c.id for c in registry.cards_for(page_id)}
        family["href"] = f"/admin/{page_id}#{card_id}" if known else ""
        family["card_label"] = (
            f"{registry.page(page_id).title} > {registry.card(page_id, card_id).title}" if known else ""
        )
        family["checked"] = family["name"] in chosen
        family["action_words"] = ", ".join(ACTION_WORDS.get(a, a) for a in family.get("actions") or ())
    top = [f for f in every if not f.get("parent")]
    for family in top:
        family["children"] = [f for f in every if f.get("parent") == family["name"]]
    return top


async def _recent_operations(view: PageView) -> list[dict[str, Any]]:
    tq = common.check_table_query(AUDIT_TABLE, page=1, page_size=10, sort="id", order="desc", q=None)
    answer = await audit_table(view.ctx, tq, action="data.*")
    out = []
    for item in answer["items"][:RECENT_OPERATIONS]:
        out.append(
            {
                "id": item["id"],
                "action": item.get("action"),
                "actor": item.get("actor"),
                "when": fmt.time_cell(item.get("at"), view.tz, view.now),
                "href": f"/admin/audit?{urlencode({'entry': item['id']})}",
            }
        )
    return out


@page.card("resets")
async def resets_card(view: PageView) -> dict[str, Any]:
    """The plan 6.8 reset form from `GET /data/resets` (`reset_catalog`), the recent data operations, and where
    v1's clear targets went. `?families=a,b` (the Clear buttons of other cards) and `?scope=` preselect it."""
    answer = data_api.reset_catalog()
    names = {f["name"] for f in answer["families"]}
    chosen = {name for name in view.param("families", max_chars=400).split(",") if name in names}
    scope = view.param("scope", max_chars=20)
    if scope not in data_api.SCOPES:
        scope = "family"
    targets = []
    for target, mapping in answer["v1_clear_targets"].items():
        families = [f for f in mapping.get("families") or () if f in names]
        targets.append(
            {
                "target": target,
                "scope": mapping.get("scope"),
                "scope_label": SCOPE_LABELS.get(str(mapping.get("scope")), "") if mapping.get("scope") else "",
                "families": families,
                "note": mapping.get("note") or "",
                "href": view.page_url(scope=mapping.get("scope"), families=",".join(families)) + "#resets"
                if mapping.get("scope")
                else "",
            }
        )
    return {
        "scopes": [
            {"scope": s["scope"], "label": SCOPE_LABELS.get(s["scope"], s["scope"]), "description": s["description"]}
            for s in answer["scopes"]
        ],
        "scope": scope,
        "families": _families(answer, chosen),
        "cache_kinds": answer["cache_kinds"],
        "ban_kinds": answer["ban_kinds"],
        "recommendation_kinds": answer["recommendation_kinds"],
        "scope_fields": SCOPE_FIELDS,
        "targets": targets,
        "recent": await _recent_operations(view),
        "urls": {
            "preview": f"{API}/data/resets/preview",
            "run": f"{API}/data/resets",
            "factory": f"{API}/data/resets/factory",
        },
        "tz": view.tz,
    }


# ============================================================================================ backups, vacuum


def stamp_cell(view: PageView, value: Any) -> dict[str, Any] | None:
    """A time `backup.sh` wrote (`2026-10-09T03:00:00Z`) or epoch seconds as a time cell; None when unreadable."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return fmt.time_cell(value, view.tz, view.now)
    if isinstance(value, str):
        try:
            moment = datetime.strptime(value.strip(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError:
            return None
        return fmt.time_cell(moment.timestamp(), view.tz, view.now)
    return None


REQUEST_OUTCOMES: Final[dict[str, str]] = {
    "ran": "The backup ran",
    "skipped_recent": "Skipped: a good backup was less than 10 minutes old",
    "skipped_no_database": "Skipped: no database was found to back up",
}
"""What `backup.sh` did with a "Back up now" request (`last_request.outcome`), in words."""


@page.card("backups")
async def backups_card(view: PageView) -> dict[str, Any]:
    """The nightly backup, the last answered and any pending "Back up now" request, the snapshots here."""
    answer = await data_api.backups_answer(view.ctx)
    nightly = answer.get("nightly") or {}
    success = nightly.get("last_success") or None
    failure = nightly.get("last_failure") or None
    restore = nightly.get("restore_test") or None
    last_request = answer.get("last_request") or None
    pending = answer.get("pending_request") or None
    snapshots = [
        {**item, "when": fmt.time_cell(item.get("at"), view.tz, view.now)} for item in answer.get("snapshots") or ()
    ]
    cap = int(answer.get("snapshots_max_bytes") or 0)
    used = int(answer.get("snapshots_bytes") or 0)
    return {
        "nightly": nightly,
        "success": success,
        "success_when": stamp_cell(view, success.get("at")) if success else None,
        "failure": failure,
        "failure_when": stamp_cell(view, failure.get("at")) if failure else None,
        "restore": restore,
        "restore_when": stamp_cell(view, restore.get("at")) if restore else None,
        "last_request": last_request,
        "last_request_when": stamp_cell(view, last_request.get("at")) if last_request else None,
        "last_request_asked": stamp_cell(view, last_request.get("requested_at")) if last_request else None,
        "last_request_outcome": REQUEST_OUTCOMES.get(str((last_request or {}).get("outcome")), "")
        or str((last_request or {}).get("outcome") or ""),
        "pending": pending,
        "pending_asked": stamp_cell(view, pending.get("requested_at")) if pending else None,
        "snapshots": snapshots[:50],
        "snapshot_count": len(snapshots),
        "snapshots_bytes": used,
        "snapshots_max_bytes": cap,
        "snapshots_pct": round(used * 100 / cap, 1) if cap else None,
        "keep_days": answer.get("snapshots_keep_days"),
        "note": answer.get("note") or "",
        "human_bytes": human_bytes,
    }


@page.card("vacuum", lazy=True)
async def vacuum_card(view: PageView) -> dict[str, Any]:
    """Each database's size, reclaimable space and estimated VACUUM time (`GET /data/vacuum`)."""
    answer = await data_api.vacuum_answer(view.ctx)
    return {
        "databases": answer["databases"],
        "url": f"{API}/data/vacuum",
        "human_bytes": human_bytes,
    }


# ============================================================================================ exports


@page.card("exports")
async def exports_card(view: PageView) -> dict[str, Any]:
    """Every dataset of `GET /export/datasets` (`datasets_answer`) with CSV and JSON links for this range, the LLM
    export (plan 12.2) and the export privacy settings (placed by the catalog)."""
    answer = export_api.datasets_answer()
    datasets = []
    for item in answer["datasets"]:
        path = f"export/{item['name']}"
        datasets.append(
            {
                **item,
                "csv": view.api_url(path, time=bool(item["ranged"]), format="csv"),
                "json": view.api_url(path, time=bool(item["ranged"]), format="json"),
            }
        )
    return {
        "datasets": datasets,
        "max_rows": answer["max_rows"],
        "range": view.time.view,
        "llm": {
            "url": f"{API}/export/llm",
            "schema": f"{API}/export/llm/schema",
            "windows": list(get_args(llm_api.Window)),
        },
        "include_ips": bool(view.ctx.settings.bool("export_include_ips")),
    }


__all__ = ["page", "router"]
