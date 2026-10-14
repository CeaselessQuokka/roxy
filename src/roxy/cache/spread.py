"""Key spread: find endpoints whose cache keys split on a parameter that changes on every request.

What this is
    `compute_spread(rows, ...)` groups cached entries by `METHOD host/path`, counts how many distinct values each
    query parameter takes inside a group, and flags groups that look "Suspect": many entries, one parameter
    that is different almost every time, and almost no hits. `CacheService.key_spread()` runs it over cache.db.
    The result is the evidence of the CACHE-KEYSPLIT recommendation (parity row 65), whose one-click fix is to
    add the parameter to the ignored set (or a `sort_csv` normalization rule for id lists).

Why it exists
    A caller that appends a cache buster (`?t=<timestamp>`) makes every request a new key: the cache stores
    constantly and never hits, and every request still goes to Roblox. v1 had this diagnostic as a table on the
    Cache page; v2 turns it into a recommendation with an apply button.

How it works
    v1 `key_spread` exactly, with one fix:
    - Group key: `METHOD host/path` (v2 hosts are already lowercase, so case variants no longer split groups).
    - Per entry and parameter, the value signature is the entry's values for that name joined with NUL.
    - A group is Suspect when all hold: it has a parameter; `entries >= insight_cache_keysplit_min_entries` (5);
      the most varied parameter's distinct values reach `insight_cache_keysplit_distinct_pct` (80) percent of
      the entries; and hits are at most `insight_cache_keysplit_max_hit_pct` (10) percent of the entries.
    - Fix for v1 bug B9: v1 stopped counting distinct values at 501, so a group of 627 or more entries could
      never be Suspect, hiding the worst offenders. Here, once a parameter has more than `MAX_SPREAD_VALUES`
      distinct values, its ratio is measured on the entries seen up to that point (a sample), not the whole
      group.
    - Groups are sorted Suspect first, then by entry count; a few sample values (truncated) go with each
      parameter as evidence. Negative 429 markers are not entries and are left out.
    - Bounded in bytes, not only in rows (plan P9, finding memory-5): a batch endpoint keyed by its id list (100
      ids, about 1 KiB of query) is exactly the key split this looks for, and 100,000 such rows held raw and
      decoded were about 300 MiB. So the read (`collect_rows`, used by both `read_spread.spread_rows` and
      `SharedTier.spread_rows`) walks the cursor newest first and stops at `SPREAD_BYTES_BUDGET` of estimated
      memory, and a long `params_json` is compacted as it is read: a value longer than `LONG_VALUE_CHARS` is kept
      as its first `SAMPLE_TEXT_MAX` characters plus a 64-bit digest of the whole value (`compact_value`), and a
      row keeps at most `MAX_PARAMS_PER_ROW` parameters. The grouping needs nothing more: two values are the same
      signature exactly when their prefixes and digests are, and the samples shown are the same first characters.

What to read next
    `roxy/cache/keys.py` (ignored parameters and normalization flags), then the CACHE-KEYSPLIT rule in
    `roxy/insights/`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from roxy.config.constants import MAX_SPREAD_VALUES, MIN_SPREAD_ENTRIES

MAX_VARYING: Final = 4
"""Parameters listed per group (v1 kept the top 4)."""
MAX_SAMPLES: Final = 3
SAMPLE_TEXT_MAX: Final = 40
"""Sample values are cut to this many characters: they are caller input shown in the dashboard and the export."""
DEFAULT_MAX_ROWS: Final = 100_000
"""Most recent entries read for one spread report (bounds the query, plan P9)."""
SPREAD_BYTES_BUDGET: Final = 8 * 1024 * 1024
"""Estimated memory one spread read may hold, rows and decoded parameters together (`row_cost`; finding memory-5).
About 10,000 entries of a 100-id batch query, 14,000 of short queries: the newest entries, which the diagnostic is
about. A safety bound for the 1 GB server, not a tuning knob."""
ROW_COST_BYTES: Final = 450
"""Estimated bytes one kept row costs before its parameter text (the tuples, the `SpreadRow`, the numbers)."""
TEXT_COST_FACTOR: Final = 3
"""Estimated bytes per character of (compacted) parameter text: the text itself plus its decoded strings."""
COMPACT_ABOVE_CHARS: Final = 512
"""A `params_json` longer than this is compacted as it is read (`compact_params_json`); shorter ones cost nothing."""
LONG_VALUE_CHARS: Final = 64
"""A parameter value longer than this is kept as its first `SAMPLE_TEXT_MAX` characters plus a digest."""
MAX_PARAMS_PER_ROW: Final = 32
"""Parameters one row keeps for the spread (Roblox endpoints take a handful; the rest is junk a caller added)."""
MAX_NAME_CHARS: Final = 64
"""Longest parameter name kept."""
_DIGEST_MARK: Final = "\x01"
"""Separates a compacted value's prefix from its digest (a control character no real query value carries; at worst
a crafted value would count as the same signature as one other value)."""

SpreadTuple = tuple[str, str, str, str | None, int, int]
"""`(method, host, path, params_json, hits, bytes)` of one cache.db entry, as the spread reads it."""


class SettingsReader(Protocol):
    def get(self, key: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class SpreadRow:
    """One cached entry as the spread needs it."""

    method: str
    host: str
    path: str
    params: tuple[tuple[str, str], ...]
    hits: int
    bytes: int


@dataclass(frozen=True, slots=True)
class VaryingParam:
    name: str
    values: int
    """Distinct value signatures counted (at most `MAX_SPREAD_VALUES + 1`)."""
    ratio: float
    """Distinct values per entry carrying the parameter, as a fraction (see the module docstring)."""
    saturated: bool
    samples: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SpreadGroup:
    key: str
    method: str
    host: str
    path: str
    entries: int
    hits: int
    bytes: int
    varying: tuple[VaryingParam, ...]
    suspect: bool
    suspect_param: str

    def as_dict(self) -> dict[str, Any]:
        """v1 row shape (`Key`, `Entries`, `Varying`, `Suspect`, `SuspectParam`...), for the admin API."""
        return {
            "Key": self.key,
            "Method": self.method,
            "Path": f"{self.host}/{self.path}" if self.path else self.host,
            "Entries": self.entries,
            "Hits": self.hits,
            "Bytes": self.bytes,
            "Varying": [
                {"Name": v.name, "Values": v.values, "Ratio": round(v.ratio, 3), "Samples": list(v.samples)}
                for v in self.varying
            ],
            "Suspect": self.suspect,
            "SuspectParam": self.suspect_param,
        }


@dataclass(slots=True)
class _ParamCounter:
    values: set[str] = field(default_factory=set)
    seen_while_counting: int = 0
    samples: list[str] = field(default_factory=list)

    def add(self, signature: str, limit: int) -> None:
        if len(self.values) > limit:
            return  # saturated: the ratio is taken from the sample counted so far
        self.seen_while_counting += 1
        if signature not in self.values:
            self.values.add(signature)
            if len(self.samples) < MAX_SAMPLES:
                self.samples.append(signature.replace("\0", ",")[:SAMPLE_TEXT_MAX])


@dataclass(slots=True)
class _Group:
    method: str
    host: str
    path: str
    entries: int = 0
    hits: int = 0
    bytes: int = 0
    params: dict[str, _ParamCounter] = field(default_factory=dict)


def compute_spread(
    rows: Iterable[SpreadRow],
    *,
    min_entries: float = MIN_SPREAD_ENTRIES,
    distinct_pct: float = 80.0,
    max_hit_pct: float = 10.0,
    max_values: int = MAX_SPREAD_VALUES,
    limit: int = 25,
) -> list[SpreadGroup]:
    """Group, count and flag (module docstring); the top `limit` groups, Suspect first."""
    groups: dict[str, _Group] = {}
    for row in rows:
        key = f"{row.method or 'GET'} {row.host}/{row.path}" if row.path else f"{row.method or 'GET'} {row.host}"
        group = groups.get(key)
        if group is None:
            group = groups[key] = _Group(row.method or "GET", row.host, row.path)
        group.entries += 1
        group.hits += max(0, row.hits)
        group.bytes += max(0, row.bytes)
        by_name: dict[str, list[str]] = {}
        for name, value in row.params:
            by_name.setdefault(name, []).append(value)
        for name, values in by_name.items():
            counter = group.params.get(name)
            if counter is None:
                counter = group.params[name] = _ParamCounter()
            counter.add("\0".join(values), max_values)
    result: list[SpreadGroup] = []
    for key, group in groups.items():
        varying: list[VaryingParam] = []
        for name, counter in group.params.items():
            saturated = len(counter.values) > max_values
            denominator = counter.seen_while_counting if saturated else group.entries
            ratio = len(counter.values) / denominator if denominator else 0.0
            varying.append(VaryingParam(name, len(counter.values), ratio, saturated, tuple(counter.samples)))
        varying.sort(key=lambda item: (-item.values, -item.ratio))  # stable: ties keep first-seen order (v1)
        top = varying[0] if varying else None
        suspect = bool(
            top is not None
            and group.entries >= min_entries
            and top.ratio * 100 >= distinct_pct
            and group.hits * 100 <= group.entries * max_hit_pct
        )
        result.append(
            SpreadGroup(
                key=key,
                method=group.method,
                host=group.host,
                path=group.path,
                entries=group.entries,
                hits=group.hits,
                bytes=group.bytes,
                varying=tuple(varying[:MAX_VARYING]),
                suspect=suspect,
                suspect_param=top.name if top is not None else "",  # v1: the top parameter, Suspect or not
            )
        )
    result.sort(key=lambda g: (g.suspect, g.entries), reverse=True)
    return result[: max(1, int(limit))]


def compact_value(value: str) -> str:
    """`value` when it is at most `LONG_VALUE_CHARS` long, else its first `SAMPLE_TEXT_MAX` characters, a mark and
    a 64-bit digest of the whole value: distinct values stay distinct, and the sample shown is unchanged."""
    if len(value) <= LONG_VALUE_CHARS:
        return value
    digest = hashlib.blake2b(value.encode("utf-8", "surrogatepass"), digest_size=8).hexdigest()
    return f"{value[:SAMPLE_TEXT_MAX]}{_DIGEST_MARK}{digest}"


def _params_of(params_json: str) -> tuple[tuple[str, str], ...]:
    """The `(name, value)` pairs of one `params_json`, compacted and capped (`()` when it is not readable)."""
    try:
        doc = json.loads(params_json)
        pairs = doc.get("params", ())
        return tuple(
            (str(name)[:MAX_NAME_CHARS], compact_value(str(value))) for name, value in list(pairs)[:MAX_PARAMS_PER_ROW]
        )
    except (ValueError, TypeError, AttributeError):
        return ()


def compact_params_json(params_json: str | None) -> str | None:
    """`params_json` as the spread keeps it: unchanged when short, else re-encoded from its compacted parameters
    (same JSON shape, `{"params": [[name, value], ...]}`). An unreadable long one becomes "" (no parameters)."""
    if params_json is None or len(params_json) <= COMPACT_ABOVE_CHARS:
        return params_json
    params = _params_of(params_json)
    if not params:
        return ""
    return json.dumps({"params": [list(pair) for pair in params]}, separators=(",", ":"))


def row_cost(params_json: str | None) -> int:
    """Estimated bytes one kept row costs (raw tuple and decoded `SpreadRow` together, see `SPREAD_BYTES_BUDGET`)."""
    return ROW_COST_BYTES + TEXT_COST_FACTOR * len(params_json or "")


def collect_rows(
    rows: Iterable[Sequence[Any]], max_rows: int, *, budget_bytes: int = SPREAD_BYTES_BUDGET
) -> list[SpreadTuple]:
    """The spread's input from a cursor of `(method, host, path, params_json, hits, bytes)` rows, newest first.

    Stops at `max_rows` rows or `budget_bytes` of estimated memory, whichever comes first; long parameter text is
    compacted as it is read (module docstring). The repeated method, host and path strings are shared, so a
    thousand entries of one endpoint hold one copy of each.
    """
    limit = max(1, int(max_rows))
    shared: dict[str, str] = {}
    kept: list[SpreadTuple] = []
    spent = 0
    for raw in rows:
        params_json = compact_params_json(raw[3])
        cost = row_cost(params_json)
        if kept and spent + cost > budget_bytes:
            break
        spent += cost
        method, host, path = (shared.setdefault(text, text) for text in (str(raw[0]), str(raw[1]), str(raw[2])))
        kept.append((method, host, path, params_json, int(raw[4] or 0), int(raw[5] or 0)))
        if len(kept) >= limit:
            break
    return kept


def rows_from_db(raw: Sequence[SpreadTuple]) -> list[SpreadRow]:
    """Turn `spread_rows` tuples into `SpreadRow`s (decoding `params_json`, compacted and capped as the read does,
    parameter names shared between rows)."""
    names: dict[str, str] = {}
    rows: list[SpreadRow] = []
    for method, host, path, params_json, hits, size in raw:
        params: tuple[tuple[str, str], ...] = ()
        if params_json:
            params = tuple((names.setdefault(name, name), value) for name, value in _params_of(params_json))
        rows.append(SpreadRow(method, host, path, params, hits, size))
    return rows


def thresholds(settings: SettingsReader) -> dict[str, float]:
    """The CACHE-KEYSPLIT parameters from the live settings (plan 15.3 J2), with the v1 defaults as fallback."""

    def read(key: str, default: float) -> float:
        try:
            return float(settings.get(key))
        except (KeyError, LookupError, TypeError, ValueError):
            return default

    return {
        "min_entries": read("insight_cache_keysplit_min_entries", MIN_SPREAD_ENTRIES),
        "distinct_pct": read("insight_cache_keysplit_distinct_pct", 80.0),
        "max_hit_pct": read("insight_cache_keysplit_max_hit_pct", 10.0),
    }


__all__ = [
    "COMPACT_ABOVE_CHARS",
    "DEFAULT_MAX_ROWS",
    "LONG_VALUE_CHARS",
    "MAX_PARAMS_PER_ROW",
    "SPREAD_BYTES_BUDGET",
    "SpreadGroup",
    "SpreadRow",
    "SpreadTuple",
    "VaryingParam",
    "collect_rows",
    "compact_params_json",
    "compact_value",
    "compute_spread",
    "row_cost",
    "rows_from_db",
    "thresholds",
]
