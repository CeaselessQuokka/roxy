"""The Settings page (`/admin/settings`, plan 14.1, 15.2; v1 Runtime Settings, parity rows 87 and 124): the full
catalog editor, the change history with revert, import and export, and the alert and public site settings.

What this is
    Five registry cards:
      * `editor`: every catalog setting with the shared setting control (the same component, validation, risk badge,
        reason, high-risk confirmation, fresh second factor and audit as every inline setting), found by search,
        group, risk, "only what I have changed" and "only with an open recommendation", paged on the server and
        grouped under the catalog's group names. Each setting says where else it can be changed (its feature cards)
        and which open recommendations propose changing it. `?key=<key>` shows one setting (the palette, the audit
        log and recommendation evidence link there; `/admin/settings#<key>` is sent there by the page script).
        Several edits can be reviewed and saved together (`static/js/pages/settings.js`, `PATCH /settings`).
      * `history`: every settings change (the API's history table, filtered by the top bar range, source and
        search); a row opens the change in the drawer with its revert form (`POST /settings/history/{id}/revert`).
      * `import-export`: download your changes as JSON (audited) and load such a file back with a preview first.
      * `alerts` and `public-site`: the settings the catalog places there, with a sentence on each.

Why it exists
    Plan 15.2's editor features, with plan P6: the listing is `settings_api.settings_listing`, the history
    `settings_api.history_answer` and `history_change`, the functions the API routes call, so the page and the API
    never disagree; every change goes through the settings API (validation, cross-field rules, risk, the fresh
    second factor, the audit log), never through a page route.

How it works
    The editor renders only one page of controls (25 by default; a control is a few kilobytes and the catalog has
    about 500 settings, plan 6.7 on the 1 GB server). Its filter form asks the editor's fragment and swaps only the
    results; the page script keeps the filters in the address bar and remembers unsaved edits across pages of
    results. The history is lazy (it loads when scrolled into view); its own requests get only the table back.

What to read next
    `roxy/admin/api/settings.py`, `templates/admin/pages/settings.html`, `templates/components/setting.html`,
    `static/js/pages/settings.js`.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.admin.api import common
from roxy.admin.api import settings as settings_api
from roxy.admin.pages import inline, registry
from roxy.admin.pages.kit import Page, PageView, filter_chip, table_query, table_view
from roxy.config import catalog
from roxy.config.catalog import NON_PAGE_HOMES
from roxy.config.spec import GROUP_LABELS, Group, Risk, SettingSpec

page = Page("settings", default_range="all")
router = page.router

EDITOR_PREFIX: Final = "set-editor"
"""DOM id prefix of the editor's controls (inline cards use `set-<card>`, so a key on two cards never clashes)."""
EDITOR_SIZES: Final[tuple[int, ...]] = (10, 25, 50, 100)
DEFAULT_EDITOR_SIZE: Final = 25
HISTORY_TABLE_ID: Final = "settings-history"
HISTORY_COLUMNS: Final = ("changed_at", "key", "old", "new", "changed_by", "source", "reason", "id")
HISTORY_KEYS: Final = ("changed_at", "key", "new")
HISTORY_HIDDEN: Final = ("id",)
MAX_VALUE_CHARS: Final = 300
TRUE_TEXTS: Final = frozenset({"1", "true", "on", "yes"})
RISK_LABELS: Final[dict[str, str]] = {"low": "Low risk", "medium": "Medium risk", "high": "High risk"}
HOME_LABELS: Final[dict[str, str]] = {
    "topbar#pause": "Top bar: Pause dialog",
    "topbar#throttle-all": "Top bar: Emergency limit dialog",
    "user-menu#preferences": "Account menu: Preferences",
}


# ============================================================================================ the editor


@dataclass(slots=True)
class EditorQuery:
    """The editor's search and filters from the URL (bad values become defaults plus a notice, never an error)."""

    q: str = ""
    group: str | None = None
    risk: str | None = None
    changed: bool = False
    has_recommendation: bool = False
    page: int = 1
    page_size: int = DEFAULT_EDITOR_SIZE
    key: str | None = None
    notices: list[str] = field(default_factory=list)

    @property
    def filtered(self) -> bool:
        return bool(self.q or self.group or self.risk or self.changed or self.has_recommendation or self.key)


def editor_query(view: PageView) -> EditorQuery:
    """Read the editor's parameters (`q`, `group`, `risk`, `changed`, `has_recommendation`, `page`, `page_size`,
    `key`) with the API's validation (`settings_api.listing_filter_problems`)."""
    query = EditorQuery(q=view.param("q", max_chars=common.MAX_SEARCH_CHARS))
    group = view.param("group", max_chars=40) or None
    risk = view.param("risk", max_chars=16) or None
    problems = settings_api.listing_filter_problems(group, risk)
    if problems:
        query.notices.append(
            "A filter in the address was not valid (" + "; ".join(problems.values()) + "), so it is off."
        )
    query.group = None if "group" in problems else group
    query.risk = None if "risk" in problems else risk
    query.changed = view.param("changed", max_chars=8).lower() in TRUE_TEXTS
    query.has_recommendation = view.param("has_recommendation", max_chars=8).lower() in TRUE_TEXTS
    query.page = view.int_param("page", 1, low=1, high=100_000)
    size = view.int_param("page_size", DEFAULT_EDITOR_SIZE, low=1, high=1000)
    if size not in EDITOR_SIZES:
        if view.param("page_size"):
            query.notices.append(f"Showing {DEFAULT_EDITOR_SIZE} settings a page; choose 10, 25, 50 or 100.")
        size = DEFAULT_EDITOR_SIZE
    query.page_size = size
    raw_key = view.param("key", max_chars=80)
    if raw_key:
        resolved = catalog.resolve_key(raw_key)
        if resolved is not None and resolved in catalog.CATALOG:
            query.key = resolved
        else:
            query.notices.append("No setting has the key in the address, so every setting is shown.")
    return query


def other_homes(spec: SettingSpec) -> list[dict[str, str | None]]:
    """Where else a setting can be changed (its catalog anchors other than the Settings page), as links."""
    homes: list[dict[str, str | None]] = []
    for anchor in spec.pages:
        page_id, _, card_id = anchor.partition("#")
        if page_id == "settings":
            continue
        if anchor in NON_PAGE_HOMES:
            homes.append({"label": HOME_LABELS.get(anchor, anchor), "href": None})
            continue
        if not registry.known(page_id):
            continue
        page_spec = registry.page(page_id)
        card = next((c for c in registry.cards_for(page_id) if c.id == card_id), None)
        if card is None:
            continue
        if card.fragment_only:
            homes.append({"label": f"{page_spec.title}: {card.title}", "href": page_spec.href})
        else:
            homes.append({"label": f"{page_spec.title}: {card.title}", "href": f"{page_spec.href}#{card.id}"})
    return homes


def _latest_of(entries: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """The last change of each listed entry, in the shape `inline.setting_entry` reads."""
    return {str(entry["key"]): dict(entry["last_change"]) for entry in entries if entry.get("last_change")}


def editor_items(view: PageView, entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The controls of one page of listing entries, grouped under their catalog group (in catalog order)."""
    snapshot = view.ctx.settings.snapshot()
    latest = _latest_of(entries)
    groups: list[dict[str, Any]] = []
    for item in entries:
        spec = catalog.CATALOG[str(item["key"])]
        if not groups or groups[-1]["id"] != spec.group.value:
            groups.append(
                {"id": spec.group.value, "label": GROUP_LABELS.get(spec.group, spec.group.value), "items": []}
            )
        groups[-1]["items"].append(
            {
                "key": spec.key,
                "control": inline.setting_entry(spec, snapshot, latest, tz=view.tz, prefix=EDITOR_PREFIX),
                "homes": other_homes(spec),
                "recommendations": list(item.get("open_recommendations") or ()),
                "renamed_from": spec.renamed_from,
                "arm_only": settings_api.ARM_ONLY_SETTINGS.get(spec.key),
                "changed": bool(item.get("changed")),
            }
        )
    return groups


def group_options() -> list[tuple[str, str]]:
    counts = Counter(spec.group for spec in catalog.CATALOG.values())
    return [("", f"All groups ({len(catalog.CATALOG)})")] + [
        (group.value, f"{GROUP_LABELS.get(group, group.value)} ({counts[group]})") for group in Group if counts[group]
    ]


def risk_options() -> list[tuple[str, str]]:
    return [("", "Any risk")] + [(risk.value, RISK_LABELS[risk.value]) for risk in Risk]


@page.card("editor")
async def editor_card(view: PageView) -> dict[str, Any]:
    """One page of the catalog editor (`settings_listing`, the API's own listing)."""
    query = editor_query(view)
    listing = await settings_api.settings_listing(
        view.ctx,
        q=query.key or query.q,
        group=None if query.key else query.group,
        risk=None if query.key else query.risk,
        changed=False if query.key else query.changed,
        has_recommendation=False if query.key else query.has_recommendation,
        include_text=False,
    )
    entries = [entry for group in listing["groups"] for entry in group["settings"]]
    if query.key:
        entries = [entry for entry in entries if entry["key"] == query.key]
    elif listing.get("ranked_keys"):
        order = {key: index for index, key in enumerate(listing["ranked_keys"])}
        entries.sort(key=lambda entry: (order.get(entry["key"], len(order)),))
    total = len(entries)
    pages = max(1, -(-total // query.page_size))
    if query.page > pages:
        query.page = pages
    start = (query.page - 1) * query.page_size
    shown = entries[start : start + query.page_size]
    return {
        "query": query,
        "groups": editor_items(view, shown),
        "total": total,
        "catalog_total": listing["total"],
        "changed_count": listing["changed_count"],
        "with_recommendation_count": listing["with_recommendation_count"],
        "first": start + 1 if total else 0,
        "last": start + len(shown),
        "pages": pages,
        "sizes": EDITOR_SIZES,
        "group_options": group_options(),
        "risk_options": risk_options(),
        "cross_rules": listing.get("cross_field_rules") or [],
        "ranked": bool(listing.get("ranked_keys")) and not query.key,
        "key_spec": catalog.CATALOG.get(query.key) if query.key else None,
        "src": view.fragment_url("editor"),
        "preview_url": f"{common.API_PREFIX}/settings/preview",
        "save_url": f"{common.API_PREFIX}/settings",
    }


# ============================================================================================ history


def value_text(value: Any) -> str:
    """A setting value as one line of text (lists joined, documents as JSON); bounded."""
    if value is None:
        return "not set"
    if isinstance(value, bool):
        return "On" if value else "Off"
    if isinstance(value, list | tuple):
        return ", ".join(str(item) for item in value)[: MAX_VALUE_CHARS * 2] or "empty"
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)[: MAX_VALUE_CHARS * 2]
    return str(value)[: MAX_VALUE_CHARS * 2]


def _history_cells(view: PageView) -> Any:
    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        key = str(item.get("key"))
        spec = catalog.CATALOG.get(key)
        old_default = item.get("old") is None
        new_default = item.get("new") is None
        reason = item.get("reason")
        return {
            "id": {"text": f"#{item.get('id')}", "mono": True},
            "changed_at": view.time_cell(item.get("changed_at")),
            "key": {
                "text": spec.label if spec else key,
                "sub": key,
                "href": f"/admin/settings?key={key}" if spec else None,
            },
            "old": {
                "text": value_text(item.get("old_effective")),
                "caller": True,
                "sub": "the default" if old_default else None,
            },
            "new": {
                "text": value_text(item.get("new_effective")),
                "caller": True,
                "sub": "the default" if new_default else None,
            },
            "changed_by": {"text": item.get("changed_by"), "caller": True},
            "source": {"text": item.get("source"), "mono": True},
            "reason": {"text": reason, "caller": True} if reason else None,
        }

    return cells


def _source_options(sources: Sequence[Mapping[str, Any]], current: str | None) -> list[tuple[str, str]]:
    options = [("", "Any source")] + [
        (str(row["source"]), f"{row['source']} ({int(row['count']):,})") for row in sources if row.get("source")
    ]
    if current and current not in {value for value, _ in options}:
        options.insert(1, (current, current))
    return options[:60]


def history_window(view: PageView) -> tuple[int | None, int | None]:
    """The history's time filter: the top bar range, or none at all for "All" (the page opens there)."""
    if view.time.view.get("range") == "all":
        return None, None
    return int(view.tr.window.start), int(view.tr.window.end)


async def change_drawer(view: PageView, raw: str) -> dict[str, Any]:
    """One settings change for the drawer (`history_change`), with what reverting it would do."""
    if not raw.isdigit() or not 1 <= int(raw) <= common.MAX_ROW_ID:
        raise common.not_found("Choose a change from the history; that change number is not valid.")
    item = await settings_api.history_change(view.ctx, int(raw))
    if item is None:
        raise common.not_found("No settings change has that number. It may have been pruned by the retention settings.")
    key = str(item["key"])
    spec = catalog.CATALOG.get(key)
    arm_route = settings_api.ARM_ONLY_SETTINGS.get(key)
    arming = bool(arm_route) and not item.get("old_effective") and bool(view.ctx.settings.get(key))
    return {
        "change": item,
        "spec": spec,
        "when": view.time_cell(item.get("changed_at")),
        "before": value_text(item.get("old_effective")),
        "after": value_text(item.get("new_effective")),
        "before_default": item.get("old") is None,
        "after_default": item.get("new") is None,
        "revert_url": item.get("revert_url") if not arming else None,
        "arming": arming,
        "needs_fresh_mfa": bool(spec and settings_api.needs_fresh_mfa(spec)),
        "high_risk": bool(spec and spec.risk is Risk.HIGH),
        "max_value_chars": MAX_VALUE_CHARS,
        "history_url": f"/admin/audit?target=setting:{key}",
    }


@page.card("history", lazy=True)
async def history_card(view: PageView) -> dict[str, Any]:
    """The settings history (`history_answer`), or one change for the drawer (`?change=<id>`)."""
    raw = view.param("change", max_chars=24) if view.in_fragment else ""
    if raw or (view.in_fragment and "change" in view.query):
        return await change_drawer(view, raw)
    tq, notice = table_query(view, settings_api.HISTORY_TABLE, address=False)
    source = view.state_param("source", address=False, max_chars=80) or None
    since, until = history_window(view)
    answer = await settings_api.history_answer(view.ctx, tq, source=source, since=since, until=until)
    filters = [filter_chip("source", "Source", source or "", _source_options(answer.get("sources") or (), source))]
    export = f"{common.API_PREFIX}/settings/history"
    if since is not None and view.time.view.get("range") != "custom":
        export += f"?from={since}&to={until}"
    table = table_view(
        view,
        HISTORY_TABLE_ID,
        settings_api.HISTORY_TABLE,
        answer,
        src=view.fragment_url("history"),
        columns=HISTORY_COLUMNS,
        key_columns=HISTORY_KEYS,
        hidden=HISTORY_HIDDEN,
        cells=_history_cells(view),
        row_id=lambda item: f"change-{item.get('id')}",
        drawer=lambda item: view.fragment_url("history", change=item.get("id")),
        drawer_title=lambda item: f"Settings change #{item.get('id')}",
        filters=filters,
        export_url=export,
        caption="Settings history",
        empty={
            "title": "No settings changes match",
            "body": "Every change made here, on a feature page, by a recommendation or by an import is listed as "
            "it happens. Try another range in the top bar, or clear the search and the source filter.",
            "icon": "history",
        },
        search_placeholder="Search keys, reasons and who changed them",
        notice=notice,
        address=False,
    )
    return {
        "table": table,
        "table_only": view.in_fragment and view.request.headers.get("HX-Target") == HISTORY_TABLE_ID,
        "total": answer["total"],
        "whole": since is None,
        "range_description": view.time.view.get("description"),
    }


# ============================================================================================ import and export


@page.card("import-export")
async def import_export_card(view: PageView) -> dict[str, Any]:
    """Export your changes (audited) and import a file with a preview first (the page script calls the API)."""
    snapshot = view.ctx.settings.snapshot()
    overridden = sum(1 for key in catalog.CATALOG if snapshot.is_overridden(key))
    return {
        "export_url": f"{common.API_PREFIX}/settings/export",
        "preview_url": f"{common.API_PREFIX}/settings/import/preview",
        "import_url": f"{common.API_PREFIX}/settings/import",
        "overridden": overridden,
        "catalog_version": catalog.CATALOG_VERSION,
    }


@page.card("alerts")
async def alerts_card(view: PageView) -> dict[str, Any]:
    """The alert settings (placed by the catalog), with where the channels are configured."""
    return {}


@page.card("public-site")
async def public_site_card(view: PageView) -> dict[str, Any]:
    """The public site settings (placed by the catalog), with links to the pages they change."""
    return {}


__all__ = [
    "EDITOR_SIZES",
    "EditorQuery",
    "editor_items",
    "editor_query",
    "other_homes",
    "page",
    "router",
    "value_text",
]
