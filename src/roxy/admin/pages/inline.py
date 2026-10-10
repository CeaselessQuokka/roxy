"""Inline settings: the catalog settings a card shows, ready for `components/setting.html` in API mode.

What this is
    `setting_entry(spec, snapshot, latest, tz=, prefix=)` builds one control's context (spec, current value, last
    change, the settings API URL it saves to and the fragment URL that re-renders it); `card_settings(anchor,
    snapshot, latest, tz=)` does it for every setting the catalog places on a card (`registry.settings_for`).
    `read_latest(conn, keys)` is the one control.db read the last-change lines need.

Why it exists
    Plan 14.1 and 15.6: "settings relevant to a feature are editable inline on that feature's page, same component
    as the Settings page, same validation and audit", and placement is data (the `pages` field of each
    `SettingSpec`), never a second hand-written list. Every card gets its settings from here, and every control
    saves through `PUT /admin/api/v1/settings/{key}` (the settings API's validation, risk rules, fresh second factor
    and audit), so a page route never writes a setting itself.

How it works
    Values come from the worker's settings snapshot (`shown` from the settings API: a sensitive value is
    `[redacted]`), the last change from `config/read_settings.latest_changes` (the API's read model). The control's
    DOM id prefix is per card (`set-<card>-<key>`) because one key may sit on two cards of the same page.

What to read next
    `templates/components/setting.html` (the control), `static/js/settings_api.js` (review, save, re-render),
    `roxy/admin/api/settings.py` (the writer).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, Final
from urllib.parse import urlencode

from roxy.admin.api.common import API_PREFIX
from roxy.admin.api.settings import needs_fresh_mfa, shown
from roxy.admin.pages import fmt, registry
from roxy.config import read_settings
from roxy.config.spec import Risk, SettingSpec

SETTING_FRAGMENT_PATH: Final = "/admin/ui/setting"
"""`GET /admin/ui/setting/{key}?prefix=` re-renders one control (after a save, or when another admin changed it)."""

_PREFIX_RE: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")


def clean_prefix(prefix: str) -> str:
    """A safe DOM id prefix (`set-cache-settings`); anything else falls back to `set`."""
    return prefix if _PREFIX_RE.fullmatch(prefix or "") else "set"


def card_prefix(card_id: str) -> str:
    return clean_prefix(f"set-{card_id}")


def setting_entry(
    spec: SettingSpec,
    snapshot: Any,
    latest: Mapping[str, Mapping[str, Any]],
    *,
    tz: str,
    prefix: str = "set",
) -> dict[str, Any]:
    """The context of one inline control (see the module docstring)."""
    prefix = clean_prefix(prefix)
    value = shown(spec, snapshot[spec.key])
    last = latest.get(spec.key)
    meta = None
    if last is not None:
        meta = {
            "changed_at": fmt.local_time(last.get("changed_at"), tz, seconds=False),
            "changed_by": str(last.get("changed_by") or ""),
            "reason": last.get("reason") or "",
        }
    return {
        "spec": spec,
        "value": value,
        "meta": meta,
        "prefix": prefix,
        "api_url": f"{API_PREFIX}/settings/{spec.key}",
        "fragment_url": f"{SETTING_FRAGMENT_PATH}/{spec.key}?{urlencode({'prefix': prefix})}",
        "history_url": f"/admin/audit?{urlencode({'target': f'setting:{spec.key}'})}",
        "needs_fresh_mfa": needs_fresh_mfa(spec),
        "always_risky": spec.risk is Risk.HIGH,
    }


def card_settings(
    anchor: str,
    snapshot: Any,
    latest: Mapping[str, Mapping[str, Any]],
    *,
    tz: str,
    prefix: str | None = None,
) -> list[dict[str, Any]]:
    """Every setting the catalog places on `anchor` (`cache#settings`), in key order, as control contexts."""
    card_id = anchor.split("#", 1)[1] if "#" in anchor else anchor
    chosen = prefix or card_prefix(card_id)
    return [setting_entry(spec, snapshot, latest, tz=tz, prefix=chosen) for spec in registry.settings_for(anchor)]


def read_latest(conn: Any, keys: Iterable[str]) -> dict[str, dict[str, Any]]:
    """The newest settings history row of each of `keys` (one indexed read; empty when `keys` is empty)."""
    wanted = list(keys)
    if not wanted:
        return {}
    return read_settings.latest_changes(conn, wanted)


__all__ = ["SETTING_FRAGMENT_PATH", "card_prefix", "card_settings", "clean_prefix", "read_latest", "setting_entry"]
