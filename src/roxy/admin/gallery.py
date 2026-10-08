"""Development-only component gallery: every dashboard component on one page, with live sample data.

What this is
    `router` serves `/admin/_gallery` (the gallery page) and a few small endpoints its demos talk to: a server-side
    paged and sorted table, the setting control's save (validated by the real settings catalog), a sample SSE stream
    that honors Last-Event-ID, a heartbeat counter, a 401 for the session-expired overlay, a slow fragment for the
    htmx indicator, and a CSV export. `include_gallery(target, env)` adds the router only when ROXY_ENV is
    "development"; every route also answers 404 outside development, so a mistaken include cannot expose it.
    `load_glossary()` reads docs/glossary.yml and `diff_lines()` builds the input of the line diff viewer; the
    dashboard pages (P11 part two) use both too. `find_glossary()` locates the glossary in a source checkout and
    in a release installed with `uv sync --no-editable` (see "How it works").

Why it exists
    The design system (templates/components, static/css, static/js) is built before the pages that use it. The
    gallery is where it is reviewed by eye in both themes and at phone width, checked with axe-core, and where the
    CSP spike proves the whole stack runs under the strict policy of plan 9.2 (tests/e2e). Nothing here touches
    real data: every number is generated from a fixed seed, and the save endpoints change nothing. It is not
    behind admin login because it holds no data and exists only in development; the admin router (P9) includes it
    through `include_gallery`, and the security route discovery test lists it as development-only.

How it works
    Plain FastAPI routes rendering Jinja templates through `request.app.state.templates` (roxy/core/templating.py,
    which adds the CSP nonce and hashed asset URLs). Sample data is built once per process from `random.Random(7)`.
    The SSE demo sends 20 events per connection and then closes, so the browser must reconnect and resume from
    Last-Event-ID (the e2e test checks this). Counters for the tests live in a small bounded dict on `app.state`.
    The glossary is not inside the package: it is `docs/glossary.yml` at the top of the tree (plan 14.7 keeps it
    with the other docs). `find_glossary` looks for `docs/glossary.yml` in the nearest directory at or above the
    roxy package: `<repo>/docs` for a checkout or editable install (2 levels up), `<release>/docs` for a release
    that deploy/deploy.sh installed into `<release>/.venv/lib/python3.12/site-packages` (5 levels up; `git
    archive` ships docs/), and a copy packaged inside roxy itself would win if a build ever adds one. This is the
    same rule `roxy/public/pages.py` uses for docs/USER_GUIDE.md, so a release has one convention for its docs.

What to read next
    templates/admin/_gallery/index.html (the page), templates/admin/base.html (the shell contract),
    templates/components/*.html (the macros), tests/e2e/test_design_system.py and tests/e2e/test_csp_spike.py.
"""

from __future__ import annotations

import asyncio
import csv
import difflib
import io
import json
import math
import random
import secrets
import time
from collections import deque
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

from roxy import __version__
from roxy.config.catalog import CATALOG, SettingValidationError, validate_value
from roxy.config.spec import SettingSpec

GALLERY_PREFIX: Final = "/admin/_gallery"
PACKAGE_DIR: Final = Path(__file__).resolve().parents[1]
"""The installed `roxy` package: `<repo>/src/roxy` in a checkout, `.../site-packages/roxy` in a release."""
GLOSSARY_RELATIVE_PATH: Final = Path("docs") / "glossary.yml"
GLOSSARY_SEARCH_PARENTS: Final = 5
"""How far above the package `find_glossary` looks: far enough for `<release>/.venv/lib/python3.12/site-packages/
roxy` (the release is the 5th parent) and no further, so an unrelated file higher up is never used."""


def find_glossary(package_dir: Path = PACKAGE_DIR) -> Path | None:
    """`docs/glossary.yml` in the nearest directory at or above the roxy package, or None when there is none."""
    for directory in (package_dir, *package_dir.parents[:GLOSSARY_SEARCH_PARENTS]):
        candidate = directory / GLOSSARY_RELATIVE_PATH
        if candidate.is_file():
            return candidate
    return None


GLOSSARY_PATH: Final = find_glossary() or PACKAGE_DIR.parents[1] / GLOSSARY_RELATIVE_PATH
"""The glossary this process reads. When no copy exists it names where a checkout keeps it, and `load_glossary`
raises FileNotFoundError naming that path (a release without docs/ fails loudly, never with silent blanks)."""
THEMES: Final = ("dark", "light", "system")
EVENTS_PER_CONNECTION: Final = 20
EVENT_INTERVAL_S: Final = 0.25
MAX_EVENT_ID: Final = 1_000_000
STATS_LIMIT: Final = 50
"""Most recent items kept per counter list (plan P9: bounded everything)."""

SAMPLE_SETTING_KEYS: Final[tuple[str, ...]] = (
    "cache_ttl_seconds",
    "cache_memory_bytes",
    "cache_enabled",
    "cache_eviction_policy",
    "rotator_hard_stop_pct",
    "direct_weight",
    "strict_host_allowlist",
    "roblox_egress_cidrs",
    "ui_timezone",
)
SAMPLE_VALUES: Final[dict[str, Any]] = {"cache_ttl_seconds": 300, "rotator_hard_stop_pct": 150}
"""Gallery values that differ from the defaults: one changed setting and one high-risk value."""


# ------------------------------------------------------------------------------------------- guards


def require_development(request: Request) -> None:
    """404 unless this app runs with ROXY_ENV=development (the gallery never exists in production)."""
    env = getattr(request.app.state, "env", None)
    if not getattr(env, "is_development", False):
        raise HTTPException(status_code=404, detail="Not Found")


router = APIRouter(prefix=GALLERY_PREFIX, include_in_schema=False, dependencies=[Depends(require_development)])


def include_gallery(target: FastAPI | APIRouter, env: Any) -> bool:
    """Include the gallery router in `target` only in development. Returns whether it was included."""
    if not getattr(env, "is_development", False):
        return False
    target.include_router(router)
    return True


# ------------------------------------------------------------------------------------------- shared helpers


@dataclass(frozen=True, slots=True)
class GlossaryEntry:
    """One glossary term: shown text, plain definition, and where it came from (plan, dashboard, roxy)."""

    id: str
    term: str
    definition: str
    source: str


@lru_cache(maxsize=4)
def _load_glossary_cached(path: str, mtime_ns: int) -> dict[str, GlossaryEntry]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries: dict[str, GlossaryEntry] = {}
    for item in raw.get("terms", []):
        entry = GlossaryEntry(
            id=str(item["id"]),
            term=str(item["term"]),
            definition=" ".join(str(item["definition"]).split()),
            source=str(item.get("source", "roxy")),
        )
        if entry.id in entries:
            raise ValueError(f"{path}: duplicate glossary id {entry.id!r}")
        entries[entry.id] = entry
    return entries


def load_glossary(path: Path = GLOSSARY_PATH) -> dict[str, GlossaryEntry]:
    """docs/glossary.yml as id -> entry, cached until the file changes (yaml.safe_load: data, never code)."""
    try:
        mtime_ns = path.stat().st_mtime_ns
    except FileNotFoundError:
        raise FileNotFoundError(
            f"the dashboard glossary {path} does not exist; docs/glossary.yml must ship next to the roxy package "
            f"(searched {GLOSSARY_SEARCH_PARENTS} levels above {PACKAGE_DIR})"
        ) from None
    return _load_glossary_cached(str(path), mtime_ns)


def diff_lines(before: str, after: str, context: int = 3) -> list[dict[str, Any]]:
    """A line diff for components/diff.html `diff_lines`: equal runs longer than 2 x context fold into one row."""
    old, new = before.splitlines(), after.splitlines()
    rows: list[dict[str, Any]] = []
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            span = i2 - i1
            hidden = span - 2 * context
            if hidden >= 2:  # folding a single line would hide nothing worth hiding
                head = range(i1, i1 + context)
                tail = range(i2 - context, i2)
                rows += [{"op": "equal", "old": i + 1, "new": j1 + (i - i1) + 1, "text": old[i]} for i in head]
                rows.append({"op": "skip", "old": None, "new": None, "text": f"{hidden} unchanged lines"})
                rows += [{"op": "equal", "old": i + 1, "new": j1 + (i - i1) + 1, "text": old[i]} for i in tail]
            else:
                rows += [{"op": "equal", "old": i + 1, "new": j1 + (i - i1) + 1, "text": old[i]} for i in range(i1, i2)]
            continue
        rows += [{"op": "delete", "old": i + 1, "new": None, "text": old[i]} for i in range(i1, i2)]
        rows += [{"op": "insert", "old": None, "new": j + 1, "text": new[j]} for j in range(j1, j2)]
    return rows


def _stats(request: Request) -> dict[str, Any]:
    """Bounded counters the e2e tests read through `/stats`."""
    stats: dict[str, Any] | None = getattr(request.app.state, "gallery_stats", None)
    if stats is None:
        stats = {
            "heartbeats": 0,
            "heartbeat_idle_ms": deque(maxlen=STATS_LIMIT),
            "last_event_ids": deque(maxlen=STATS_LIMIT),
            "csrf_headers": deque(maxlen=STATS_LIMIT),
            "actions": deque(maxlen=STATS_LIMIT),
        }
        request.app.state.gallery_stats = stats
    return stats


def _templates(request: Request) -> Any:
    templates = getattr(request.app.state, "templates", None)
    if templates is None:  # pragma: no cover - create_app always sets it
        raise HTTPException(status_code=500, detail="Templates are not configured")
    return templates


def _bounded_int(raw: str | None, low: int, high: int, default: int) -> int:
    try:
        value = int(raw) if raw is not None else default
    except ValueError:
        return default
    return min(max(value, low), high)


# ------------------------------------------------------------------------------------------- sample data


_TEMPLATES: Final[tuple[str, ...]] = (
    "games.roblox.com/v1/games/{universeId}/votes",
    "games.roblox.com/v1/games",
    "games.roblox.com/v1/games/{universeId}/favorites/count",
    "games.roblox.com/v1/games/{universeId}/servers/{serverType}",
    "games.roblox.com/v1/games/{universeId}/game-passes",
    "games.roblox.com/v2/users/{userId}/games",
    "games.roblox.com/v1/games/{universeId}/media",
    "games.roblox.com/v1/games/votes",
    "users.roblox.com/v1/users/{userId}",
    "users.roblox.com/v1/usernames/users",
    "users.roblox.com/v1/users/{userId}/username-history",
    "users.roblox.com/v1/users",
    "thumbnails.roblox.com/v1/games/icons",
    "thumbnails.roblox.com/v1/users/avatar-headshot",
    "thumbnails.roblox.com/v1/users/avatar-bust",
    "thumbnails.roblox.com/v1/assets",
    "thumbnails.roblox.com/v1/badges/icons",
    "thumbnails.roblox.com/v1/groups/icons",
    "groups.roblox.com/v1/groups/{groupId}",
    "groups.roblox.com/v2/users/{userId}/groups/roles",
    "groups.roblox.com/v1/groups/{groupId}/roles",
    "groups.roblox.com/v1/groups/{groupId}/users",
    "catalog.roblox.com/v1/catalog/items/details",
    "catalog.roblox.com/v1/search/items",
    "economy.roblox.com/v1/assets/{assetId}/resellers",
    "economy.roblox.com/v2/assets/{assetId}/details",
    "badges.roblox.com/v1/badges/{badgeId}",
    "badges.roblox.com/v1/universes/{universeId}/badges",
    "badges.roblox.com/v1/users/{userId}/badges/awarded-dates",
    "presence.roblox.com/v1/presence/users",
    "friends.roblox.com/v1/users/{userId}/friends/count",
    "friends.roblox.com/v1/users/{userId}/followers/count",
    "inventory.roblox.com/v1/users/{userId}/items/{itemType}/{itemId}",
    "inventory.roblox.com/v2/users/{userId}/inventory/{assetTypeId}",
    "avatar.roblox.com/v1/users/{userId}/avatar",
    "avatar.roblox.com/v1/users/{userId}/currently-wearing",
    "develop.roblox.com/v1/universes/{universeId}",
    "develop.roblox.com/v1/universes/multiget",
    "apis.roblox.com/universes/v1/places/{placeId}/universe",
    "apis.roblox.com/cloud/v2/universes/{universeId}",
    "followings.roblox.com/v1/users/{userId}/universes",
    "translations.roblox.com/v1/supported-locales",
    "locale.roblox.com/v1/locales",
    "premiumfeatures.roblox.com/v1/users/{userId}/validate-membership",
)

_COLUMNS: Final[list[dict[str, Any]]] = [
    {
        "key": "endpoint",
        "label": "Endpoint template",
        "mono": True,
        "key_col": True,
        "help": "The Roblox path with ids replaced by placeholders, so every request of one kind is counted together.",
    },
    {"key": "host", "label": "Host", "hidden": True},
    {
        "key": "requests",
        "label": "Requests",
        "num": True,
        "key_col": True,
        "help": "Caller requests for this endpoint in the selected range.",
    },
    {
        "key": "hit_ratio",
        "label": "Hit ratio",
        "num": True,
        "help": "Share of requests answered from the cache without asking Roblox.",
    },
    {"key": "upstream", "label": "Upstream calls", "num": True},
    {"key": "r429", "label": "Roblox 429s", "num": True, "key_col": True},
    {"key": "p95", "label": "p95 latency", "num": True},
]


@lru_cache(maxsize=1)
def _endpoint_rows() -> tuple[dict[str, Any], ...]:
    rng = random.Random(7)  # fixed seed: the gallery and its screenshots look the same on every run
    rows = []
    for index, template in enumerate(_TEMPLATES):
        requests = int(rng.lognormvariate(9.5, 1.3))
        hit = round(rng.uniform(0.05, 0.97), 3)
        upstream = max(1, int(requests * (1 - hit)))
        r429 = int(upstream * rng.choice([0, 0, 0, 0.001, 0.004, 0.02]))
        rows.append(
            {
                "id": f"ep{index}",
                "endpoint": template,
                "host": template.split(".", 1)[0],
                "requests": requests,
                "hit_ratio": hit,
                "upstream": upstream,
                "r429": r429,
                "p95": int(rng.uniform(60, 900)),
            }
        )
    return tuple(rows)


def _table_context(
    q: str = "", host: str = "", sort: str = "requests", direction: str = "desc", page: int = 1, size: int = 10
) -> dict[str, Any]:
    """One page of the sample endpoint table, filtered, sorted and paged on the server (plan 14.5)."""
    rows = [r for r in _endpoint_rows() if q.lower() in r["endpoint"].lower() and (not host or r["host"] == host)]
    keys = {c["key"] for c in _COLUMNS}
    sort = sort if sort in keys else "requests"
    rows.sort(key=lambda r: r[sort], reverse=direction != "asc")
    size = size if size in (10, 25, 50, 100, 250) else 10
    pages = max(1, math.ceil(len(rows) / size))
    page = min(max(page, 1), pages)
    shown = rows[(page - 1) * size : page * size]
    hosts = sorted({r["host"] for r in _endpoint_rows()})
    return {
        "id": "gallery-endpoints",
        "columns": _COLUMNS,
        "rows": [
            {
                "id": r["id"],
                "drawer": f"{GALLERY_PREFIX}/drawer?endpoint={r['id']}",
                "cells": {
                    "endpoint": {"text": r["endpoint"], "mono": True},
                    "host": r["host"],
                    "requests": r["requests"],
                    "hit_ratio": {"text": f"{r['hit_ratio'] * 100:.1f}%"},
                    "upstream": r["upstream"],
                    "r429": {"text": f"{r['r429']:,}", "tone": "bad" if r["r429"] else "muted"},
                    "p95": {"text": f"{r['p95']:,} ms"},
                },
            }
            for r in shown
        ],
        "src": f"{GALLERY_PREFIX}/table",
        "total": len(rows),
        "page": page,
        "size": size,
        "sort": sort,
        "dir": "asc" if direction == "asc" else "desc",
        "q": q,
        "filters": [
            {"name": "host", "label": "Host", "value": host, "options": [["", "All"], *[[h, h] for h in hosts]]},
        ],
        "export_url": f"{GALLERY_PREFIX}/export",
        "caption": "Top endpoints",
        "empty": {
            "title": "No endpoints match",
            "body": "Nothing in this range matches the search and filters.",
            "icon": "search",
        },
    }


def _series(rng: random.Random, n: int, base: float, swing: float, noise: float, phase: float = 0.0) -> list[float]:
    return [
        max(0.0, round(base + swing * math.sin((i / n) * 2 * math.pi + phase) + rng.gauss(0, noise), 2))
        for i in range(n)
    ]


def _chart_specs(now: int) -> dict[str, dict[str, Any]]:
    rng = random.Random(11)
    step = 600
    n = 144
    x = [now - (n - 1 - i) * step for i in range(n)]
    requests = _series(rng, n, 9800, 3600, 520)
    upstream = [round(v * rng.uniform(0.32, 0.4), 2) for v in requests]
    previous = _series(rng, n, 9100, 3400, 480, 0.2)
    previous_up = [round(v * rng.uniform(0.38, 0.47), 2) for v in previous]

    def note(offset_h: float, kind: str, label: str) -> dict[str, Any]:
        t = now - int(offset_h * 3600)
        when = time.strftime("%H:%M", time.gmtime(t))
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        return {"t": t, "iso": iso, "when": f"{when} UTC", "kind": kind, "label": label, "href": "/admin/audit#gallery"}

    cache_hits = [round(v * 0.58, 2) for v in requests]
    served = [round(v * 0.33, 2) for v in requests]
    refused = [round(v * rng.uniform(0.04, 0.08), 2) for v in requests]
    failed = [round(v * rng.uniform(0.0, 0.012), 2) for v in requests]
    p50 = _series(rng, n, 42, 8, 3)
    p95 = [round(v * rng.uniform(3.4, 4.2), 2) for v in p50]
    p99 = [round(v * rng.uniform(1.6, 2.2), 2) for v in p95]
    hours = [now - (23 - i) * 3600 for i in range(24)]
    r429 = [max(0, int(rng.gauss(2, 2))) if i not in (9, 10) else int(rng.uniform(25, 40)) for i in range(24)]
    return {
        "traffic": {
            "x": x,
            "series": [
                {"label": "Requests in", "values": requests, "color": 1, "kind": "line", "compare": previous},
                {"label": "Upstream calls", "values": upstream, "color": 2, "kind": "line", "compare": previous_up},
            ],
            "compare_label": "Previous 24 hours",
            "annotations": [
                note(6, "config", "cache_ttl_seconds changed from 120 to 300"),
                note(15, "incident", "Roblox 429 burst on games.roblox.com"),
            ],
            "y": {"unit": "req / 10 min", "format": "count", "min": 0},
            "summary": "Requests in and upstream calls over the last 24 hours, with the previous 24 hours dashed. "
            "Upstream calls stay near a third of requests in.",
        },
        "outcomes": {
            "x": x,
            "series": [
                {"label": "Served from cache", "values": cache_hits, "color": 3, "stack": "outcome"},
                {"label": "Served by Roblox", "values": served, "color": 1, "stack": "outcome"},
                {"label": "Refused", "values": refused, "color": 4, "stack": "outcome"},
                {"label": "Failed", "values": failed, "color": 8, "stack": "outcome"},
            ],
            "y": {"unit": "req / 10 min", "format": "count", "min": 0},
        },
        "latency": {
            "x": x,
            "series": [
                {"label": "p50", "values": p50, "color": 3},
                {"label": "p95", "values": p95, "color": 1},
                {"label": "p99", "values": p99, "color": 7},
            ],
            "y": {"unit": "ms", "format": "ms", "min": 0},
        },
        "r429": {
            "x": hours,
            "series": [{"label": "Roblox 429s", "values": r429, "color": 8, "kind": "bars"}],
            "y": {"unit": "per hour", "format": "count", "min": 0},
            "summary": "Roblox 429s per hour over the last day: a burst of about 30 per hour around 14 hours ago, "
            "otherwise a handful.",
        },
    }


def _heatmap() -> dict[str, Any]:
    rng = random.Random(3)
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    values = []
    for d in range(7):
        weekend = d >= 5
        row = []
        for h in range(24):
            daily = math.sin(((h - 9) / 24) * 2 * math.pi) * 0.5 + 0.55
            row.append(int(max(0.0, daily * (5200 if weekend else 3900) + rng.gauss(0, 260))))
        values.append(row)
    return {
        "rows": days,
        "cols": [f"{h:02d}" for h in range(24)],
        "values": values,
        "summary": "Requests by hour of day and weekday (UTC): busiest on weekend afternoons, quietest before dawn.",
    }


def _recommendations() -> list[dict[str, Any]]:
    action = f"{GALLERY_PREFIX}/action"
    return [
        {
            "id": "gal1",
            "rule_id": "UP-429-ENDPOINT",
            "family": "upstream",
            "severity": "critical",
            "confidence": "high",
            "age": "12 minutes ago",
            "safe_auto": True,
            "title": "Roblox is rate-limiting games.roblox.com/v1/games/votes on the direct path",
            "explanation": "71% of all Roblox 429s in the last hour came from this one endpoint, while only 18% of "
            "its requests were answered from the cache. Its answers rarely change, so caching it for 5 minutes and "
            "pacing it slightly slower removes most of the calls Roblox is refusing.",
            "evidence": {
                "label": "Roblox 429s per 10 minutes, last 6 hours",
                "values": [2, 3, 2, 4, 6, 9, 14, 22, 31, 36, 34, 38, 41, 37, 40, 44, 39, 42],
                "note": "212 responses with status 429 in the last hour.",
            },
            "changes": [
                {
                    "label": "Cache rule TTL",
                    "key": "rules_cache: games.roblox.com/v1/games/votes",
                    "before": None,
                    "after": "300 seconds",
                },
                {
                    "label": "Endpoint bucket rate",
                    "key": "endpoint:games.roblox.com/v1/games/votes",
                    "before": "120 per minute",
                    "after": "90 per minute",
                },
            ],
            "expected_impact": "About 1,900 fewer upstream calls per hour and roughly 90% fewer 429s here.",
            "urls": {
                "apply": action,
                "preview": f"{GALLERY_PREFIX}/drawer?preview=gal1",
                "snooze": action,
                "dismiss": action,
            },
        },
        {
            "id": "gal2",
            "rule_id": "CACHE-LOW-HIT",
            "family": "cache",
            "severity": "warn",
            "confidence": "medium",
            "age": "2 hours ago",
            "safe_auto": False,
            "title": "The cache answers only 22% of thumbnails.roblox.com requests",
            "explanation": "The size parameter differs on almost every request, so each one is a new cache key. "
            "Ignoring the format parameter (always png) would merge most of them.",
            "evidence": {
                "label": "Hit ratio per hour, last 12 hours",
                "values": [24, 23, 22, 25, 21, 20, 22, 23, 21, 22, 22, 21],
                "note": None,
            },
            "changes": [
                {"label": "Ignored parameters", "key": "cache_ignored_params", "before": "none", "after": "format"}
            ],
            "expected_impact": "The hit ratio for this host should rise to about 60%.",
            "urls": {
                "apply": action,
                "preview": f"{GALLERY_PREFIX}/drawer?preview=gal2",
                "snooze": action,
                "dismiss": action,
            },
        },
        {
            "id": "gal3",
            "rule_id": "SEC-ADMIN-ALLOWLIST",
            "family": "security",
            "severity": "info",
            "confidence": "low",
            "age": "1 day ago",
            "safe_auto": False,
            "title": "Every admin login in 30 days came from two networks",
            "explanation": "An admin IP allowlist would hide the login page from everyone else. Turn it on only if "
            "you never log in from new places, such as a phone on mobile data.",
            "evidence": None,
            "changes": [],
            "expected_impact": None,
            "urls": {"apply": action, "preview": None, "snooze": action, "dismiss": action},
        },
    ]


_DIFF_BEFORE: Final = json.dumps(
    {
        "pattern": "games.roblox.com/v1/games/votes",
        "type": "glob",
        "ttl": 60,
        "stale_ttl": 30,
        "note": "added by owner",
        "enabled": True,
        "methods": ["GET"],
    },
    indent=2,
)
_DIFF_AFTER: Final = json.dumps(
    {
        "pattern": "games.roblox.com/v1/games/votes",
        "type": "glob",
        "ttl": 300,
        "stale_ttl": 120,
        "note": "recommended by UP-429-ENDPOINT",
        "enabled": True,
        "methods": ["GET"],
    },
    indent=2,
)


def _setting_meta(key: str) -> dict[str, str] | None:
    if key == "cache_ttl_seconds":
        return {"changed_at": "Oct 7, 14:02", "changed_by": "owner", "reason": "Fewer 429s on votes"}
    return None


def _sample_settings() -> list[dict[str, Any]]:
    settings = []
    for key in SAMPLE_SETTING_KEYS:
        spec = CATALOG.get(key)
        if spec is None:  # pragma: no cover - the catalog test pins these keys
            continue
        settings.append({"spec": spec, "value": SAMPLE_VALUES.get(key, spec.default), "meta": _setting_meta(key)})
    return settings


def _live_event(event_id: int) -> dict[str, Any]:
    rng = random.Random(event_id)
    template = _TEMPLATES[rng.randrange(len(_TEMPLATES))]
    outcome = rng.choices(["served_cache", "served_upstream", "refused", "failed"], [58, 33, 7, 2])[0]
    status = {
        "served_cache": 200,
        "served_upstream": rng.choice([200, 200, 200, 404, 429]),
        "refused": rng.choice([429, 403, 404]),
        "failed": rng.choice([502, 503, 504]),
    }[outcome]
    return {
        "id": f"req{event_id:07d}",
        "t": time.time(),
        "status": status,
        "outcome": outcome,
        "reason": {
            "served_cache": "cache_hit",
            "served_upstream": "upstream_ok",
            "refused": "throttle",
            "failed": "upstream_5xx",
        }[outcome],
        "egress": "none" if outcome in ("served_cache", "refused") else rng.choice(["direct", "direct", "rotator"]),
        "cache": "HIT" if outcome == "served_cache" else rng.choice(["MISS", "OFF", "STALE"]),
        "latency_ms": round(rng.uniform(2, 40) if outcome == "served_cache" else rng.uniform(60, 900), 1),
        "client": f"192.0.2.{rng.randrange(1, 254)}",  # TEST-NET-1 (RFC 5737): never a real address
        "place": str(rng.choice([1000001, 2000002, 3000003])) if rng.random() < 0.7 else "",  # made-up place ids
        "method": "GET",
        "endpoint": template,
    }


# ------------------------------------------------------------------------------------------- page context


def _page_context(request: Request) -> dict[str, Any]:
    query = request.query_params
    theme = query.get("theme", "")
    if theme not in THEMES:
        theme = str(CATALOG["ui_default_theme"].default)
    density = "dense" if query.get("density") == "dense" else "comfortable"
    heartbeat_s = _bounded_int(query.get("hb"), 1, 600, int(CATALOG["admin_heartbeat_interval_s"].default))
    window_s = _bounded_int(query.get("aw"), 1, 900, int(CATALOG["admin_activity_window_s"].default))
    now = int(time.time()) // 600 * 600
    specs = _chart_specs(now)
    action = f"{GALLERY_PREFIX}/action"
    return {
        "page": {
            "id": "gallery",
            "title": "Component gallery",
            "purpose": "Every dashboard component with sample data, for design review and the accessibility and CSP "
            "checks. Development only.",
        },
        "admin": {"username": "owner"},
        "csrf_token": secrets.token_urlsafe(48),  # a stand-in: the real one is masked per response by admin/auth/csrf
        "session": {
            "heartbeat_s": heartbeat_s,
            "activity_window_s": window_s,
            "heartbeat_url": f"{GALLERY_PREFIX}/heartbeat",
            "login_url": "/admin",
        },
        "theme": theme,
        "density": density,
        "time": {"range": query.get("range", "24h"), "compare": query.get("compare", "prev")},
        "status": {"paused": False, "throttle_all": False},
        "sample_status": {
            "paused": True,
            "paused_since": "14:02 UTC, 12 minutes ago",
            "pause_reason": "Back in about 10 minutes.",
            "pause_drops": 1843,
            "throttle_all": True,
            "throttle_all_since": "13:40 UTC, 34 minutes ago",
            "throttle_limit": 30,
            "throttle_period": 60,
            "throttle_reason": "High load; please slow down.",
            "throttle_drops": 412,
        },
        "recs": {"open": 3, "critical": 1},
        "urls": {
            "pause": action,
            "throttle_all": action,
            "stream": f"{GALLERY_PREFIX}/stream",
            "palette": f"{GALLERY_PREFIX}/palette",
            "health_run": action,
            "prefs": f"{GALLERY_PREFIX}/prefs",
            "logout": action,
        },
        "glossary": load_glossary(),
        "env_name": "development",
        "version": __version__,
        "kpis": _kpis(),
        "charts": specs,
        "heatmap": _heatmap(),
        "table": _table_context(),
        "recommendations": _recommendations(),
        "diff_rows": [
            {"label": "Cache lifetime", "key": "cache_ttl_seconds", "before": "120 seconds", "after": "300 seconds"},
            {
                "label": "Serve expired for",
                "key": "cache_stale_seconds",
                "before": "60 seconds",
                "after": "120 seconds",
                "note": "Proposed by UP-429-ENDPOINT",
            },
            {"label": "Rotator hard stop", "key": "rotator_hard_stop_pct", "before": "100%", "after": None},
        ],
        "diff_lines": diff_lines(_DIFF_BEFORE, _DIFF_AFTER, context=1),
        "settings": _sample_settings(),
        "setting_url": f"{GALLERY_PREFIX}/setting",
        "action_url": action,
    }


def _kpis() -> list[dict[str, Any]]:
    rng = random.Random(5)

    def spark(base: float, swing: float) -> list[float]:
        return _series(rng, 24, base, swing, swing / 4)

    return [
        {
            "label": "Requests",
            "value": "1.42M",
            "delta": 8.2,
            "good": "neutral",
            "spark": spark(60, 20),
            "spark_compare": spark(55, 18),
            "href": "/admin/traffic",
            "help": "Every proxy request Roxy handled in the selected range, served or refused.",
        },
        {
            "label": "Avoided upstream calls",
            "value": "61.4",
            "unit": "%",
            "delta": 3.1,
            "good": "up",
            "status": "ok",
            "status_label": "Healthy",
            "spark": spark(60, 4),
            "href": "/admin/cache",
            "help": "Caller requests minus the upstream calls made for them. Higher is kinder to Roblox.",
        },
        {
            "label": "Roblox 429s",
            "value": "38",
            "delta": -72.0,
            "good": "down",
            "status": "ok",
            "status_label": "Low",
            "spark": spark(8, 6),
            "baseline": "v1 had 579",
            "href": "/admin/upstream",
            "help": "Responses where Roblox said too many requests.",
        },
        {
            "label": "429s per 10,000 requests",
            "value": "0.27",
            "delta": -98.1,
            "good": "down",
            "baseline": "v1 baseline 116",
            "spark": spark(0.3, 0.1),
            "href": "/admin/upstream",
            "help": "Roblox 429s per 10,000 caller requests, the headline number for kindness to Roblox.",
        },
        {
            "label": "p95 latency",
            "value": "182",
            "unit": "ms",
            "delta": 12.4,
            "good": "down",
            "status": "warn",
            "status_label": "Slower than usual",
            "spark": spark(170, 25),
            "href": "/admin/traffic",
            "help": "95% of requests finished within this time.",
        },
        {
            "label": "Caller 5xx",
            "value": "12",
            "delta": 0.0,
            "good": "down",
            "spark": spark(1, 1),
            "href": "/admin/traffic",
            "help": "Server errors returned to callers, from Roblox or from Roxy.",
        },
        {
            "label": "Rotator bytes today",
            "value": "312",
            "unit": "MiB",
            "delta": None,
            "good": "neutral",
            "spark": spark(13, 5),
            "href": "/admin/egress",
            "help": "Bytes through DataImpulse today; they cost money.",
        },
        {
            "label": "Active bans",
            "value": "4",
            "status": "info",
            "status_label": "2 automatic",
            "delta": None,
            "href": "/admin/protection",
            "help": "Clients refused right now by a temporary or permanent ban.",
        },
    ]


# ------------------------------------------------------------------------------------------- routes


@router.get("", response_class=HTMLResponse)
async def gallery_page(request: Request) -> HTMLResponse:
    """The gallery page itself."""
    response: HTMLResponse = _templates(request).render(request, "admin/_gallery/index.html", _page_context(request))
    return response


def _fragment(request: Request, kind: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    html = _templates(request).render_to_string(request, "admin/_gallery/fragment.html", {"kind": kind, **context})
    return HTMLResponse(html, status_code=status_code)


@router.get("/table", response_class=HTMLResponse)
async def gallery_table(request: Request) -> HTMLResponse:
    """The endpoint table, one page (server-side search, filter, sort and paging)."""
    query = request.query_params
    table = _table_context(
        q=query.get("q", "")[:200],
        host=query.get("host", "")[:40],
        sort=query.get("sort", "requests"),
        direction=query.get("dir", "desc"),
        page=_bounded_int(query.get("page"), 1, 10_000, 1),
        size=_bounded_int(query.get("size"), 1, 250, 10),
    )
    return _fragment(request, "table", table=table)


@router.get("/drawer", response_class=HTMLResponse)
async def gallery_drawer(request: Request) -> HTMLResponse:
    """A details fragment for the drawer (a table row or a recommendation dry run)."""
    endpoint_id = request.query_params.get("endpoint", "")
    row = next((r for r in _endpoint_rows() if r["id"] == endpoint_id), None)
    preview = request.query_params.get("preview")
    return _fragment(request, "drawer", row=row, preview=preview)


@router.get("/slow", response_class=HTMLResponse)
async def gallery_slow(request: Request) -> HTMLResponse:
    """A fragment that takes a moment, so the htmx loading indicator is visible."""
    await asyncio.sleep(0.6)
    return _fragment(request, "slow", at=time.strftime("%H:%M:%S"))


async def _form_fields(request: Request) -> dict[str, list[str]]:
    form = await request.form()
    fields: dict[str, list[str]] = {}
    for name, value in form.multi_items():
        if isinstance(value, str):
            fields.setdefault(name, []).append(value[:2000])
    return fields


def _high_risk_reason(spec: SettingSpec, value: Any) -> str | None:
    for condition in spec.high_risk_if:
        if condition.matches(value):
            return condition.why
    return None


@router.post("/setting", response_class=HTMLResponse)
async def gallery_setting(request: Request) -> HTMLResponse:
    """Validate a setting control save with the real catalog; nothing is stored (the gallery changes nothing)."""
    _stats(request)["csrf_headers"].append(bool(request.headers.get("x-csrf-token")))
    fields = await _form_fields(request)
    key = (fields.get("key") or [""])[-1]
    spec = CATALOG.get(key)
    if spec is None or key not in SAMPLE_SETTING_KEYS:
        raise HTTPException(status_code=404, detail="Not Found")
    raw = (fields.get("value") or [""])[-1]  # a switch posts a hidden "0" then the checkbox "1": the last wins
    reason = (fields.get("reason") or [""])[-1].strip()
    confirmed = (fields.get("confirm_high_risk") or [""])[-1] == "1"
    previous = SAMPLE_VALUES.get(key, spec.default)
    try:
        value = validate_value(key, raw)
    except SettingValidationError as error:
        return _fragment(
            request,
            "setting",
            422,
            spec=spec,
            value=previous,
            error=error.message,
            submitted=raw,
            setting_url=f"{GALLERY_PREFIX}/setting",
        )
    risky = _high_risk_reason(spec, value)
    if risky and not (reason and confirmed):
        return _fragment(
            request,
            "setting",
            422,
            spec=spec,
            value=previous,
            submitted=raw,
            error="This is a high-risk value: give a reason and tick I understand the risk.",
            setting_url=f"{GALLERY_PREFIX}/setting",
        )
    meta = {"changed_at": "just now", "changed_by": "owner (gallery, not stored)", "reason": reason}
    response = _fragment(
        request, "setting", spec=spec, value=value, saved=True, meta=meta, setting_url=f"{GALLERY_PREFIX}/setting"
    )
    response.headers["HX-Trigger"] = json.dumps(
        {"roxy:toast": {"message": f"{spec.label} saved (gallery only)", "tone": "ok"}}
    )
    return response


@router.post("/action")
async def gallery_action(request: Request) -> Response:
    """Every gallery button that would change something: refuses without the CSRF header, else answers a toast."""
    has_token = bool(request.headers.get("x-csrf-token"))
    stats = _stats(request)
    stats["csrf_headers"].append(has_token)
    if not has_token:
        return JSONResponse("Forbidden", status_code=403)
    fields = await _form_fields(request)
    stats["actions"].append(sorted(fields))
    response = Response(status_code=204)
    response.headers["HX-Trigger"] = json.dumps(
        {"roxy:toast": {"message": "Done. This is the gallery, so nothing changed.", "tone": "ok"}}
    )
    return response


@router.post("/prefs")
async def gallery_prefs(request: Request) -> Response:
    """Theme and density preferences (accepted and forgotten)."""
    _stats(request)["csrf_headers"].append(bool(request.headers.get("x-csrf-token")))
    return Response(status_code=204)


@router.post("/heartbeat")
async def gallery_heartbeat(request: Request) -> JSONResponse:
    """Counts heartbeats so the e2e test can prove they are sent only after real input."""
    stats = _stats(request)
    stats["heartbeats"] += 1
    try:
        body = json.loads(await request.body() or b"{}")
    except ValueError:
        body = {}
    idle = body.get("idle_ms") if isinstance(body, dict) else None
    stats["heartbeat_idle_ms"].append(idle if isinstance(idle, int) else None)
    return JSONResponse({"OK": True, "Extended": True})


@router.get("/unauthorized")
async def gallery_unauthorized() -> JSONResponse:
    """Always 401, to show the session-expired overlay."""
    return JSONResponse("Session expired", status_code=401)


@router.get("/stats")
async def gallery_stats(request: Request) -> JSONResponse:
    """The counters above, for tests."""
    stats = _stats(request)
    return JSONResponse({key: list(value) if isinstance(value, deque) else value for key, value in stats.items()})


@router.get("/chart.json")
async def gallery_chart(request: Request) -> JSONResponse:
    """A chart spec fetched by URL (the `src` form of components/chart.html)."""
    return JSONResponse(_chart_specs(int(time.time()) // 600 * 600)["latency"])


@router.get("/palette")
async def gallery_palette(request: Request) -> JSONResponse:
    """Command palette search results: matching settings and endpoints (at most 20)."""
    q = request.query_params.get("q", "").strip().lower()[:100]
    results: list[dict[str, str]] = []
    if len(q) >= 2:
        for spec in CATALOG.values():
            if q in spec.key or q in spec.label.lower():
                results.append(
                    {
                        "group": "Settings",
                        "label": spec.label,
                        "hint": spec.key,
                        "href": f"/admin/settings?q={spec.key}",
                        "icon": "sliders",
                    }
                )
            if len(results) >= 10:
                break
        for row in _endpoint_rows():
            if q in row["endpoint"].lower():
                results.append(
                    {
                        "group": "Endpoints",
                        "label": row["endpoint"],
                        "hint": f"{row['requests']:,} requests",
                        "href": f"/admin/endpoints?template={row['id']}",
                        "icon": "endpoints",
                    }
                )
            if len(results) >= 20:
                break
    return JSONResponse(results[:20])


def _csv_cell(value: Any) -> str:
    """Spreadsheet formula guard (parity row 88): a cell starting with = + - @ or a control character is quoted."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@router.get("/export")
async def gallery_export(request: Request) -> Response:
    """CSV or JSON export of the sample table (all matching rows, not just one page)."""
    q = request.query_params.get("q", "")[:200].lower()
    rows = [r for r in _endpoint_rows() if q in r["endpoint"].lower()]
    if request.query_params.get("format") == "json":
        return JSONResponse(rows, headers={"Content-Disposition": 'attachment; filename="endpoints.json"'})
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
    writer.writerow([c["label"] for c in _COLUMNS])
    for r in rows:
        writer.writerow([_csv_cell(r[c["key"]]) for c in _COLUMNS])
    return Response(
        buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="endpoints.csv"'},
    )


def _sse_frames(start_id: int, count: int) -> Iterable[tuple[int, str]]:
    for event_id in range(start_id, min(start_id + count, MAX_EVENT_ID)):
        payload = json.dumps(_live_event(event_id), separators=(",", ":"))
        yield event_id, f"id: {event_id}\nevent: live\ndata: {payload}\n\n"


@router.get("/stream")
async def gallery_stream(request: Request) -> StreamingResponse:
    """Sample SSE stream: resumes after Last-Event-ID, sends 20 events, then closes so the client reconnects."""
    header = request.headers.get("last-event-id", "")
    _stats(request)["last_event_ids"].append(header or None)
    start = _bounded_int(header, 0, MAX_EVENT_ID, 0) + 1 if header.isdigit() else 1

    async def frames() -> AsyncIterator[str]:
        yield "retry: 800\n: gallery stream\n\n"  # a comment line, like the real stream's keepalive
        for _event_id, frame in _sse_frames(start, EVENTS_PER_CONNECTION):
            if await request.is_disconnected():
                return
            yield frame
            await asyncio.sleep(EVENT_INTERVAL_S)

    return StreamingResponse(
        frames(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def gallery_routes() -> Sequence[str]:
    """Every path the gallery serves (the security route discovery test lists them as development-only)."""
    return tuple(sorted({getattr(route, "path", "") for route in router.routes}))


def glossary_terms(entries: Mapping[str, GlossaryEntry]) -> list[GlossaryEntry]:
    """Entries sorted by term, case-insensitive (the order of the Help page glossary)."""
    return sorted(entries.values(), key=lambda entry: entry.term.lower())
