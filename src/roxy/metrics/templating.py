"""Endpoint templates: collapse ids in Roblox paths so `users/29371917/outfits` and `users/1/outfits` group.

What this is
    `templatize(path)` is v1's `_templatize` reproduced exactly (same id tests, same placeholder names, same
    output for every input), `template_for(host, path)` builds the `host/path` template the rest of Roxy uses
    (the `endpoint_template` dimension of every metric, `ProxyRequest.template`), and `TEMPLATE_VERSION` says
    which version of the algorithm produced a template (stored in every `dims` row, plan 14.3). `VocabularyGate`
    keeps the number of distinct templates (and hosts) a worker writes bounded (plan 6.2: top 2,000 templates,
    the rest as `other`).

Why it exists
    Popular-endpoint charts, per-endpoint latency and 429 counts only make sense per route, not per concrete URL
    (parity row 74). The algorithm is a heuristic, and changing it changes which rows charts compare, so it is
    frozen to v1's behavior and versioned: a future change bumps `TEMPLATE_VERSION` and ships a data migration
    that maps old templates to new ones (plan 14.3).

How it works
    - A path is split on `/` (no lowercasing, no stripping). A segment is an id when it is all digits
      (`str.isdigit`, so non-ASCII digits count too, exactly as in v1), a UUID, at least 16 hex characters, or an
      opaque token (at least 24 characters of `[A-Za-z0-9_-]` with at least one digit). An id segment becomes
      `{name}`, where the name comes from the previous raw segment lowercased (`users` gives `{userId}`,
      `games` gives `{gameId}`, anything else `{id}`). The table is `_ID_COLLECTION_NAMES` below.
    - `template_for` drops the query, strips leading and trailing slashes like v1's `log_endpoint`, and caps the
      result at `MAX_TEMPLATE_CHARS` so an attacker-made path cannot produce an unbounded dimension value.
    - `VocabularyGate(limit)` admits new values while it has room and maps everything else to `other`. Each
      worker refreshes its gate every hour from the trailing 24 h of rollups (`queries.top_templates`), so the
      busiest templates keep their names, values with no traffic for a day free their place, and a flood of
      made-up paths cannot grow the `dims` table past `limit` names per worker.

What to read next
    `roxy/metrics/recorder.py` (where templates become dimensions), `.remake/v1notes/diagnostics.md` section 5
    (the v1 examples the tests replay).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterable

TEMPLATE_VERSION = 1
"""Version of the templating algorithm. Bump it only together with a data migration (plan 14.3)."""

OTHER = "other"
"""The value every template or host that does not fit the bounded vocabulary is written as (plan 6.2)."""

MAX_TEMPLATES = 2000
"""Distinct endpoint templates a worker keeps under their own name (plan 6.2: top 2,000 over 24 h)."""

MAX_HOSTS = 64
"""Distinct hosts a worker keeps under their own name (plan 6.2 bounds hosts at about 40 allowed hosts)."""

MAX_TEMPLATE_CHARS = 255
"""Longest template stored; longer ones are cut (only attacker-made paths are this long)."""

# Map an id's parent collection segment to a friendly placeholder (v1 diagnostics.py:14-36, verbatim).
_ID_COLLECTION_NAMES: dict[str, str] = {
    "users": "userId",
    "user": "userId",
    "games": "gameId",
    "universes": "universeId",
    "universe": "universeId",
    "places": "placeId",
    "place": "placeId",
    "groups": "groupId",
    "group": "groupId",
    "assets": "assetId",
    "asset": "assetId",
    "badges": "badgeId",
    "badge": "badgeId",
    "bundles": "bundleId",
    "outfits": "outfitId",
    "items": "itemId",
    "passes": "passId",
    "gamepasses": "gamePassId",
    "servers": "serverId",
    "thumbnails": "thumbnailId",
}
# The same expressions as v1 (diagnostics.py:37-39), used with re.match like v1, so `$` keeps v1's meaning.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def is_id_segment(seg: str) -> bool:
    """Does this path segment look like a volatile id rather than a route word? (v1 `_is_id_segment`)."""
    if seg.isdigit():
        return True
    if _UUID_RE.match(seg):
        return True
    if len(seg) >= 16 and _HEX_RE.match(seg):  # long hex hash or token
        return True
    # An opaque token: long, URL-safe characters only, and at least one digit (so long words are not ids).
    return bool(len(seg) >= 24 and _TOKENISH_RE.match(seg) and any(c.isdigit() for c in seg))


def templatize(path: str) -> str:
    """Collapse id-like path segments into placeholders, exactly like v1's `_templatize`.

    `avatar.roblox.com/v2/avatar/users/29371917/outfits` becomes
    `avatar.roblox.com/v2/avatar/users/{userId}/outfits`.
    """
    segments = path.split("/")
    out: list[str] = []
    for i, seg in enumerate(segments):
        if is_id_segment(seg):
            previous = segments[i - 1].lower() if i > 0 else ""
            out.append("{" + _ID_COLLECTION_NAMES.get(previous, "id") + "}")
        else:
            out.append(seg)
    return "/".join(out)


def clean_path(path: str) -> str:
    """v1's normalization before templating: drop the query, strip leading and trailing slashes."""
    return path.split("?", 1)[0].strip("/")


def template_for(host: str, path: str) -> str:
    """The endpoint template of a request to `host` + `path` (`ProxyRequest.template`, plan 6.2 dimension).

    `path` may start with `/` and may carry a query; both are removed as in v1. A path that already starts
    with the host (v1 passed `dst`, the whole `host/path`) is not doubled.
    """
    cleaned = clean_path(path)
    host = host.strip().strip("/")
    if host and cleaned != host and not cleaned.startswith(host + "/"):
        cleaned = f"{host}/{cleaned}" if cleaned else host
    return templatize(cleaned)[:MAX_TEMPLATE_CHARS]


def remap_templates(examples: dict[str, str]) -> dict[str, str]:
    """For a future data migration: old template -> new template, by re-templating one concrete example of each
    (plan 14.3). Templates whose example produces the same text map to themselves."""
    return {old: templatize(clean_path(example))[:MAX_TEMPLATE_CHARS] for old, example in examples.items()}


class VocabularyGate:
    """A bounded set of names: values beyond `limit` distinct names are reported as `other` (plan P9, 6.2).

    `admit(value)` returns the value itself when it is already known or there is room, else `OTHER`. `reset`
    replaces the known set (the hourly refresh with the busiest names of the last 24 h). Thread safe; `admit`
    takes a lock only when a new name is added.
    """

    def __init__(self, limit: int, initial: Iterable[str] = ()) -> None:
        self.limit = max(1, int(limit))
        self._known: set[str] = set()
        self._lock = threading.Lock()
        self.rejected = 0
        self.reset(initial)

    def admit(self, value: str) -> str:
        if value in self._known:
            return value
        with self._lock:
            if value in self._known:
                return value
            if len(self._known) >= self.limit:
                self.rejected += 1
                return OTHER
            self._known.add(value)
            return value

    def reset(self, names: Iterable[str]) -> None:
        """Keep at most `limit` of `names` (in the given order, busiest first) as the known set."""
        fresh: set[str] = set()
        for name in names:
            if len(fresh) >= self.limit:
                break
            if name and name != OTHER:
                fresh.add(name)
        with self._lock:
            self._known = fresh

    def __len__(self) -> int:
        return len(self._known)

    def __contains__(self, value: object) -> bool:
        return value in self._known
