"""The insight fixture harness: turns a `roxy.insight_fixture/1` file into a real state and checks one rule on it.

What this is
    `run_fixture(name)` loads one fixture file from `tests/fixtures/insights/` by name (the file stem, with or
    without `.yaml`, or a path), builds temporary databases from it, checks its `data_checks`, evaluates the rule
    under test through the engine's per-rule entry point (`InsightsEngine.evaluate_rule`, the leader's own path:
    switches, severity override, evidence minimum, fingerprint) and compares the result with `expect`; then it runs
    each variant the same way. `fixture_ids()` lists `(stem, case)` pairs for pytest ids `<stem>` and
    `<stem>[<case>]`. Rule authors call `run_case(stem, case)` from their tests.

Why it exists
    Plan 19.10 row 11: every rule has independent fixtures written before the rule. The format is documented in
    `tests/fixtures/insights/README.md`; this module is its loader. The data goes through production code wherever
    production has a writer (the metrics recorder and its flush, `config/audit.record`, the schema's own tables),
    so a rule reads exactly what it would read in production.

How it works
    1. Parse with `yaml.safe_load`, reject unknown keys at every level (keys starting with `x_` go to the providers),
       validate enums, settings (`catalog.validate_value` and `validate_cross`) and table columns (`PRAGMA
       table_info`), the traffic consistency rules and the 250,000 event cap.
    2. Copy a migrated template of the four databases (migrated once per process) into a temporary directory and
       run `seed_defaults` when asked.
    3. Set a `FakeClock` to `now`; apply `settings`, `tables`, `state`, `events`, then `traffic` through
       `MetricsRecorder.record_outcome` (the clock moved to each event), flushing as it goes; bump
       `config_version` once.
    4. Check `data_checks` against the expanded events, and again through `metrics/queries.py` where the filters
       are rollup dimensions.
    5. Evaluate the rule at `now` and compare with `expect` (constraint grammar of the README); on failure the
       message lists every returned recommendation and the first constraint that did not hold.
    6. Variants rewrite the settings rows (file settings merged with the variant's), reload the settings snapshot
       and evaluate again on the same data.
    Data without a table in production goes where production will put it: the schema version 2 history tables
    (bucket history, worker minutes, cache stores and evictions, rule hits, error occurrences, upstream attempts,
    the provider byte figure) or, for the rest, `FixtureProviders` (disk, DNS, tarpit, bot scores, the UA
    experiment, the metrics drop counter, metering mode, `x_` sections and `x_` columns).

What to read next
    `tests/fixtures/insights/README.md` (the format), `tests/insights/test_rules_core.py` (how tests use this),
    `roxy/insights/engine.py`.
"""

from __future__ import annotations

import asyncio
import atexit
import copy
import hashlib
import ipaddress
import itertools
import json
import math
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Final

import yaml

from roxy.config import audit, catalog
from roxy.config.audit import Actor
from roxy.config.defaults import seed_defaults
from roxy.config.insight_params import INSIGHT_RULES
from roxy.config.runtime import RuntimeSettings, bump_config_version, load_runtime_settings
from roxy.core.clock import FakeClock
from roxy.core.iphash import ip_hash
from roxy.core.reasons import (
    FAILURE_REASONS,
    REFUSAL_REASONS,
    SERVED_REASONS,
    AuthClass,
    CacheState,
    Egress,
    Outcome,
    ReasonCode,
    Source,
)
from roxy.core.redact import fingerprint
from roxy.insights.context import InsightProviders
from roxy.insights.engine import InsightsEngine, RuleOutcome
from roxy.insights.models import Recommendation, iso
from roxy.metrics import queries, security_events
from roxy.metrics.live import RateGate
from roxy.metrics.queries import Window
from roxy.metrics.recorder import KNOWN_STATUSES, MetricsRecorder, OutcomeEvent
from roxy.metrics.samples import SampleRow
from roxy.rules.match import compile_pattern
from roxy.rules.store import build_rules_snapshot
from roxy.storage.db import DB_NAMES, Databases, open_databases
from roxy.storage.migrate import migrate_paths

FIXTURE_DIR: Final = Path(__file__).resolve().parents[1] / "fixtures" / "insights"
FORMAT: Final = "roxy.insight_fixture/1"
MAX_EVENTS: Final = 250_000
FLUSH_EVERY: Final = 5_000
TEST_KEY: Final = hashlib.sha256(b"roxy insight fixtures: test ip hash key").digest()
"""The keyed hash key of the fixtures (client hashes, fingerprints). A test value, never a real key."""
GOLDEN: Final = 0.6180339887498949

TOP_KEYS: Final = frozenset(
    {
        "format",
        "rule",
        "case",
        "description",
        "now",
        "seed_defaults",
        "settings",
        "tables",
        "traffic_defaults",
        "profiles",
        "traffic",
        "events",
        "state",
        "expect",
        "variants",
    }
)
ALLOWED_TABLES: Final = frozenset(
    {
        "rules_endpoint_block",
        "rules_endpoint_limit",
        "rules_cache",
        "rules_user_agent",
        "rules_header",
        "rules_routing",
        "upstream_limits",
        "credential_allowlist",
        "throttle_tiers",
        "cache_ignored_params",
        "ignored_value_headers",
        "ignored_paths",
        "access_list",
        "bans",
    }
)
TABLE_PKS: Final = {
    "rules_user_agent": "id",
    "rules_header": "id",
    "upstream_limits": "bucket_key",
    "throttle_tiers": "position",
    "cache_ignored_params": "name",
    "ignored_value_headers": "name",
    "ignored_paths": "pattern",
}
GENERATOR_FIELDS: Final = frozenset(
    {
        "name",
        "window",
        "per_minute",
        "total",
        "series",
        "profile",
        "endpoint_template",
        "host",
        "method",
        "egress",
        "outcome",
        "reason",
        "status",
        "source",
        "cache_state",
        "auth_class",
        "upstream_calls",
        "latency_ms",
        "queue_wait_ms",
        "upstream_ms",
        "bytes",
        "client_ip",
        "clients",
        "place_id",
        "places",
        "user_agent",
        "user_agents",
        "bypass",
        "error",
        "request_id",
        "upstream_status",
        "upstream_429",
        "samples",
        "path",
        "paths",
    }
)
PROFILE_EXCLUDED: Final = frozenset({"name", "window", "per_minute", "total", "series"})
COUNT_KEYS: Final = ("per_minute", "total", "series")
ROW_COUNT_KEYS: Final = ("per_minute", "total", "series", "every")
EVENT_SECTIONS: Final = frozenset(
    {
        "upstream_429",
        "security",
        "errors",
        "request_samples",
        "change_observations",
        "anomalies",
        "annotations",
        "internal_calls",
        "upstream_attempts",
    }
)
STATE_SECTIONS: Final = frozenset(
    {
        "cooldowns",
        "breakers",
        "buckets",
        "credential",
        "egress",
        "workers",
        "leader",
        "disk",
        "dns",
        "health",
        "settings_history",
        "admin_logins",
        "service_state",
        "cache",
        "client_scores",
        "tarpit",
        "ua_experiment",
        "metrics_pipeline",
        "raw",
    }
)
SECURITY_TYPES: Final = frozenset(
    {
        security_events.PROBE,
        security_events.LOGIN,
        security_events.CRAWL,
        security_events.THROTTLED,
        "spam_detected",
        "spam_would_ban",
        "spam_ban",
        "spam_throttle",
        "spam_tarpit",
        "credential_rotated",
        "credential_replaced",
        "credential_cooldown",
        "credential_probe",
        "credential_comparison",
        "leak_guard",
        "leak_blocked",
        "auth_smuggling_blocked",
        "rotator_parked",
        "abuse_degraded",
        "breaker_open",
        "breaker_half_open",
        "breaker_closed",
    }
)
"""Event types `events.security` may use: the recorder's security types and the abuse, egress and credential event
types their modules write (`abuse/spam.py`, `egress/credential.py`, `egress/rotator.py`, `upstream/service.py`),
plus `leak_guard` (README: provisional until the egress module names its leak-trip event), `leak_blocked` (the name
`egress/clients.py` writes) and `credential_comparison` (the 18.4 comparison events CRED-UNUSED reads)."""
IP_DETAIL_TYPES: Final = frozenset(
    {security_events.PROBE, security_events.LOGIN, security_events.CRAWL, security_events.THROTTLED}
)
EXPECT_KEYS: Final = frozenset({"data_checks", "fires", "others", "recommendations"})
MATCHER_KEYS: Final = frozenset(
    {
        "rule_id",
        "subject",
        "subject_contains",
        "title_contains",
        "severity",
        "confidence",
        "risk",
        "family",
        "safe_auto",
        "change_kinds_required",
        "change_kinds_forbidden",
        "changes_required",
        "changes_forbidden",
        "exact_changes",
        "evidence",
        "dry_run",
    }
)
CHECK_MEASURES: Final = frozenset(
    {
        "requests",
        "upstream_calls",
        "avoided_calls",
        "roblox_429",
        "served_upstream",
        "served_cache",
        "refused",
        "failed",
        "stale_after_failure",
        "errors",
        "by_reason",
    }
)
CHECK_WHERE: Final = frozenset(
    {
        "endpoint_template",
        "host",
        "method",
        "egress",
        "outcome",
        "reason",
        "status",
        "source",
        "cache_state",
        "auth_class",
        "client_ip",
        "place_id",
    }
)
OPERATORS: Final = frozenset(
    {
        "eq",
        "ne",
        "lt",
        "lte",
        "gt",
        "gte",
        "between",
        "in",
        "not_in",
        "contains",
        "contains_all",
        "regex",
        "present",
        "matches_targets",
        "not_matches_targets",
    }
)
_TIME_RE = re.compile(r"^([+-]?)(\d+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86_400}
_MISSING: Final = object()


class FixtureError(AssertionError):
    """The fixture file is malformed, or its data does not say what its `data_checks` claim."""


class ExpectationFailed(AssertionError):
    """The rule's result does not match `expect`."""


# =============================================================================================== time grammar


def parse_time(value: Any, now: float, *, where: str = "time") -> float:
    """README "Times": `now`, `<sign><int><unit>`, ISO 8601 with `Z`, a date (UTC midnight), or a bare integer."""
    if isinstance(value, bool):
        raise FixtureError(f"{where}: a boolean is not a time")
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or UTC).timestamp()
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC).timestamp()
    text = str(value).strip()
    if text == "now":
        return now
    match = _TIME_RE.match(text)
    if match and (match.group(1) or int(match.group(2)) == 0):  # "0m" needs no sign (README: "0m" for now)
        sign = -1 if match.group(1) == "-" else 1
        return now + sign * int(match.group(2)) * _UNITS[match.group(3)]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        day = date.fromisoformat(text)
        return datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp()
    if text.endswith("Z"):
        try:
            return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
        except ValueError:
            pass
    raise FixtureError(f"{where}: {value!r} is not a time (now, -60m, an ISO time with Z, a date, or an integer)")


def parse_duration(value: Any, *, where: str) -> float:
    """`every`: the time grammar without a sign (`30m`, `1d`, `200s`)."""
    match = re.fullmatch(r"(\d+)([smhd])", str(value).strip())
    if not match:
        raise FixtureError(f"{where}: {value!r} is not a duration such as 30m")
    return int(match.group(1)) * _UNITS[match.group(2)]


def parse_window(value: Any, now: float, *, where: str, whole_minutes: bool = False) -> tuple[float, float]:
    if not isinstance(value, list) or len(value) != 2:
        raise FixtureError(f"{where}: a window is a two-item list [start, end]")
    start, end = (parse_time(v, now, where=where) for v in value)
    if end <= start:
        raise FixtureError(f"{where}: the window ends before it starts")
    if whole_minutes and (start % 60 or end % 60):
        raise FixtureError(f"{where}: traffic windows start and end on whole minutes")
    return start, end


def time_column(name: str) -> bool:
    return name.endswith(("_at", "_ms", "_until", "_seen")) or name in ("at", "day", "window_start", "until", "expires")


def column_value(column: str, value: Any, now: float, *, where: str) -> Any:
    """A value for a table column: time columns accept the time grammar (ms for `_ms` columns, else seconds)."""
    if value is None or not time_column(column) or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value  # a bare integer is written unchanged (escape hatch)
    seconds = parse_time(value, now, where=f"{where}.{column}")
    return round(seconds * 1000) if column.endswith("_ms") else int(seconds)


# ================================================================================================ distributions


def distribution(value: Any, n: int, *, where: str) -> float:
    """README "Distributions": a constant, or percentile points read at quantile frac((n + 1) * golden)."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, Mapping) or not value:
        raise FixtureError(f"{where}: expected a number or percentile points such as {{p50: 180}}")
    points: list[tuple[float, float]] = []
    for key, number in value.items():
        match = re.fullmatch(r"p(\d{1,3})", str(key))
        if not match or int(match.group(1)) > 100:
            raise FixtureError(f"{where}: unknown percentile key {key!r}")
        points.append((int(match.group(1)) / 100, float(number)))
    points.sort()
    if points[0][0] > 0:
        points.insert(0, (0.0, points[0][1]))
    if points[-1][0] < 1:
        points.append((1.0, points[-1][1]))
    q = math.modf((n + 1) * GOLDEN)[0]
    for (q0, v0), (q1, v1) in itertools.pairwise(points):
        if q0 <= q <= q1:
            fraction = 0.0 if q1 == q0 else (q - q0) / (q1 - q0)
            return round(v0 + (v1 - v0) * fraction, 1)
    return round(points[-1][1], 1)


def pool(spec: Any, *, where: str) -> list[str]:
    """README "Pools": a fixed value, `{cidr, count}` (first host addresses, network address skipped), `{list}`."""
    if isinstance(spec, Mapping):
        if set(spec) == {"list"}:
            items = [str(v) for v in spec["list"]]
        elif set(spec) == {"cidr", "count"}:
            network = ipaddress.ip_network(str(spec["cidr"]), strict=False)
            items = []
            for address in network.hosts():
                items.append(str(address))
                if len(items) >= int(spec["count"]):
                    break
        else:
            raise FixtureError(f"{where}: a pool is {{cidr, count}} or {{list}}")
        if not items:
            raise FixtureError(f"{where}: an empty pool")
        return items
    if isinstance(spec, list):
        return [str(v) for v in spec]
    return [str(spec)]


# ============================================================================================ placement


def placements(gen: Mapping[str, Any], start: float, end: float, *, where: str, rows: bool = False) -> list[int]:
    """Event times in ms for one generator (README "Counts and placement"; `every` for row generators)."""
    keys = [k for k in (ROW_COUNT_KEYS if rows else COUNT_KEYS) if k in gen]
    if len(keys) != 1:
        raise FixtureError(f"{where}: exactly one of {', '.join(ROW_COUNT_KEYS if rows else COUNT_KEYS)} is needed")
    key = keys[0]
    if key == "every":
        step = parse_duration(gen["every"], where=where)
        spaced: list[int] = []
        t = start
        while t < end:
            spaced.append(round(t * 1000))
            t += step
        return spaced
    minutes = int((end - start) // 60)
    if minutes <= 0 or (end - start) % 60:
        raise FixtureError(f"{where}: count windows hold whole minutes")
    if key == "per_minute":
        counts = [int(gen["per_minute"])] * minutes
    elif key == "total":
        total = int(gen["total"])
        counts = [total // minutes + (1 if i < total % minutes else 0) for i in range(minutes)]
    else:
        counts = [int(v) for v in gen["series"]]
        if len(counts) != minutes:
            raise FixtureError(f"{where}: series has {len(counts)} entries for {minutes} minutes")
    times: list[int] = []
    for i, k in enumerate(counts):
        t0 = round((start + 60 * i) * 1000)
        times += [t0 + (2 * j + 1) * 30_000 // k for j in range(k)]
    return times


def expand_rows(items: Any, now: float, *, where: str, timed: bool = True) -> list[dict[str, Any]]:
    """README "events": single rows (with `at` when timed) or row generators (`window` and a count key)."""
    if items is None:
        return []
    if not isinstance(items, list):
        raise FixtureError(f"{where}: expected a list")
    out: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        label = f"{where}[{index}]"
        if not isinstance(item, Mapping):
            raise FixtureError(f"{label}: expected a mapping")
        if "window" in item:
            start, end = parse_window(item["window"], now, where=label)
            base = {k: v for k, v in item.items() if k not in ("window", *ROW_COUNT_KEYS)}
            for at_ms in placements(item, start, end, where=label, rows=True):
                out.append({**base, "at": at_ms / 1000})
        else:
            row = dict(item)
            if timed:
                if "at" not in row:
                    raise FixtureError(f"{label}: a single row needs `at` (or a `window` and a count)")
                row["at"] = parse_time(row["at"], now, where=f"{label}.at")
            out.append(row)
    return out


# =============================================================================================== providers


class FixtureProviders(InsightProviders):
    """The provider seams filled from a fixture (README "Provider seams")."""

    def __init__(self) -> None:
        self.disk_data: dict[str, Any] | None = None
        self.dns_data: dict[str, dict[str, Any]] = {}
        self.tarpit_data: dict[str, Any] | None = None
        self.scores: dict[str, float] = {}
        self.ua_data: dict[str, Any] | None = None
        self.pipeline: dict[str, Any] | None = None
        self.metering: dict[str, Any] = {"metering_mode": "socket"}
        self.extras: dict[str, list[dict[str, Any]]] = {}
        self.row_extras: dict[tuple[str, str], dict[str, Any]] = {}

    async def disk(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.disk_data)

    async def dns(self, host: str) -> dict[str, Any] | None:
        found = self.dns_data.get(host)
        return copy.deepcopy(found) if found is not None else None

    def classify_address(self, address: str) -> str:
        """Documentation ranges count as public in tests (README `dns`); private ranges stay private."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return "private"
        documentation = (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("2001:db8::/32"),
        )
        if any(ip in net for net in documentation if net.version == ip.version):
            return "public"
        return super().classify_address(address)

    async def tarpit(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.tarpit_data)

    async def client_scores(self) -> dict[str, float]:
        return dict(self.scores)

    async def ua_experiment(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.ua_data)

    async def metrics_pipeline(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.pipeline)

    async def egress_metering(self) -> dict[str, Any]:
        return dict(self.metering)

    async def extra(self, name: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self.extras.get(name, []))

    async def row_extra(self, table: str, key: Any) -> dict[str, Any]:
        return dict(self.row_extras.get((table, str(key)), {}))


# =============================================================================================== the loaded state


@dataclass
class TrafficEvent:
    """One expanded OutcomeEvent plus the fixture-only fields the checks need."""

    event: OutcomeEvent
    generator: str
    order: int
    n: int
    spec: dict[str, Any]


@dataclass
class LoadedFixture:
    """A fixture loaded into temporary databases, ready for evaluation (reused by its variants)."""

    name: str
    path: Path
    data: dict[str, Any]
    now: float
    workdir: Path
    dbs: Databases
    clock: FakeClock
    runtime: RuntimeSettings
    engine: InsightsEngine
    providers: FixtureProviders
    base_settings: dict[str, Any]
    history_times: dict[str, float]
    traffic: list[TrafficEvent] = field(default_factory=list)
    rows_429: list[dict[str, Any]] = field(default_factory=list)

    @property
    def rule(self) -> str:
        return str(self.data["rule"])

    def close(self) -> None:
        self.dbs.close_all_sync()
        shutil.rmtree(self.workdir, ignore_errors=True)


# ============================================================================================== loading


_TEMPLATE_DIR: Path | None = None
_SESSION_DIR: Path | None = None


def _session_dir() -> Path:
    global _SESSION_DIR
    if _SESSION_DIR is None:
        _SESSION_DIR = Path(tempfile.mkdtemp(prefix="roxy-insight-fixtures-"))
        atexit.register(shutil.rmtree, _SESSION_DIR, True)
    return _SESSION_DIR


def _template_dir() -> Path:
    """Four freshly migrated databases, built once per process and copied for every fixture."""
    global _TEMPLATE_DIR
    if _TEMPLATE_DIR is None:
        directory = _session_dir() / "template"
        directory.mkdir(mode=0o750)
        migrate_paths({name: directory / f"{name}.db" for name in DB_NAMES}, contract=True)
        _TEMPLATE_DIR = directory
    return _TEMPLATE_DIR


def fixture_path(name: str | Path) -> Path:
    """A fixture file from its stem (`up_429_endpoint__before_after_11_6`), file name or path."""
    path = Path(name)
    if path.suffix != ".yaml":
        path = path.with_suffix(".yaml") if path.name else path
    if not path.is_absolute() and not path.exists():
        path = FIXTURE_DIR / path.name
    if not path.exists():
        raise FixtureError(f"no fixture named {name!r} in {FIXTURE_DIR}")
    return path


def read_fixture(name: str | Path) -> tuple[Path, dict[str, Any]]:
    """Parse and validate the top level of one fixture file."""
    path = fixture_path(name)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise FixtureError(f"{path.name}: the document is not a mapping")
    unknown = sorted(k for k in data if k not in TOP_KEYS and not str(k).startswith("x_"))
    if unknown:
        raise FixtureError(f"{path.name}: unknown top-level keys {unknown}")
    for key in ("format", "rule", "case", "description", "now", "expect"):
        if key not in data:
            raise FixtureError(f"{path.name}: missing required key {key!r}")
    if data["format"] != FORMAT:
        raise FixtureError(f"{path.name}: format must be {FORMAT}")
    if data["rule"] not in INSIGHT_RULES:
        raise FixtureError(f"{path.name}: unknown rule {data['rule']!r}")
    slug = INSIGHT_RULES[data["rule"]].slug
    if path.stem != f"{slug}__{data['case']}":
        raise FixtureError(f"{path.name}: the file name must be {slug}__{data['case']}.yaml")
    now = parse_time(data["now"], 0, where="now")
    if now % 60:
        raise FixtureError(f"{path.name}: now must be on a whole minute")
    for index, variant in enumerate(data.get("variants") or []):
        extra = set(variant) - {"case", "description", "settings", "expect"}
        if extra:
            raise FixtureError(f"{path.name}: variants[{index}] has keys {sorted(extra)} (settings only)")
    return path, data


def fixture_ids(prefix: str | Iterable[str] = "") -> list[tuple[str, str | None]]:
    """`(stem, case)` for every fixture (case None for the file's own case), optionally only some rule slugs."""
    prefixes = (prefix,) if isinstance(prefix, str) else tuple(prefix)
    out: list[tuple[str, str | None]] = []
    for path in sorted(FIXTURE_DIR.glob("*.yaml")):
        if prefixes and not any(path.stem.startswith(p) for p in prefixes):
            continue
        out.append((path.stem, None))
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for variant in (data or {}).get("variants") or []:
            out.append((path.stem, str(variant["case"])))
    return out


def validate_settings(values: Mapping[str, Any], *, where: str) -> dict[str, Any]:
    """Every value through `catalog.validate_value`, the merged set through `validate_cross`."""
    canonical: dict[str, Any] = {}
    for key, raw in (values or {}).items():
        spec = catalog.CATALOG.get(str(key))
        if spec is None:
            raise FixtureError(f"{where}: unknown setting {key!r}")
        if isinstance(raw, bool) and spec.type.value == "enum":
            raise FixtureError(f"{where}.{key}: a boolean where an enum string is expected (quote it)")
        try:
            canonical[str(key)] = catalog.validate_value(str(key), raw)
        except catalog.SettingValidationError as exc:
            raise FixtureError(f"{where}.{key}: {exc}") from None
    issues = catalog.validate_cross(canonical)
    if issues:
        raise FixtureError(f"{where}: cross-field rules broken: {[issue.message for issue in issues]}")
    return canonical


async def load(name: str | Path, *, workdir: Path | None = None) -> LoadedFixture:
    """Steps 1 to 3 of the module docstring: a fixture as a loaded state (call `close()` when done)."""
    path, data = read_fixture(name)
    now = parse_time(data["now"], 0, where="now")
    base = Path(tempfile.mkdtemp(prefix=f"{path.stem[:40]}-", dir=workdir or _session_dir()))
    for db_name in DB_NAMES:
        shutil.copyfile(_template_dir() / f"{db_name}.db", base / f"{db_name}.db")
    dbs = open_databases({"ROXY_STATE_DIR": str(base)})
    clock = FakeClock(now)
    providers = FixtureProviders()
    settings = validate_settings(data.get("settings") or {}, where=f"{path.name}: settings")
    loader = _Loader(path.name, data, now, dbs, clock, providers)
    try:
        if data.get("seed_defaults"):
            dbs.control.write_sync(lambda conn: seed_defaults(conn, int(now)))
        history_times = loader.settings_history_times(settings)
        loader.write_settings(settings, history_times)
        runtime = await load_runtime_settings(dbs, clock)
        loader.tables()
        await loader.state()
        await loader.events(runtime)
        await loader.traffic(runtime)
        dbs.control.write_sync(lambda conn: bump_config_version(conn, int(now)))
        await runtime.reload()
        snapshot = dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, now))
        clock.set(now)
        engine = InsightsEngine(dbs=dbs, settings=runtime, rules=snapshot, clock=clock, providers=providers)
    except BaseException:
        dbs.close_all_sync()
        shutil.rmtree(base, ignore_errors=True)
        raise
    return LoadedFixture(
        name=path.stem,
        path=path,
        data=data,
        now=now,
        workdir=base,
        dbs=dbs,
        clock=clock,
        runtime=runtime,
        engine=engine,
        providers=providers,
        base_settings=settings,
        history_times=history_times,
        traffic=loader.expanded,
        rows_429=loader.rows_429,
    )


class _Loader:
    """Writes one fixture's sections into the databases (README "How the loader and harness run a file")."""

    def __init__(
        self, name: str, data: dict[str, Any], now: float, dbs: Databases, clock: FakeClock, providers: FixtureProviders
    ) -> None:
        self.name = name
        self.data = data
        self.now = now
        self.dbs = dbs
        self.clock = clock
        self.providers = providers
        self.expanded: list[TrafficEvent] = []
        self.rows_429: list[dict[str, Any]] = []
        self.history_keys: set[str] = set()

    def err(self, where: str, message: str) -> FixtureError:
        return FixtureError(f"{self.name}: {where}: {message}")

    # ---- settings ----

    def settings_history_times(self, settings: Mapping[str, Any]) -> dict[str, float]:
        times: dict[str, float] = {}
        entries = ((self.data.get("state") or {}).get("settings_history")) or []
        for index, entry in enumerate(entries):
            at = parse_time(entry.get("at"), self.now, where=f"state.settings_history[{index}].at")
            key = str(entry.get("key"))
            if key not in catalog.CATALOG:
                raise self.err(f"state.settings_history[{index}]", f"unknown setting {key!r}")
            times[key] = max(times.get(key, at), at)
        return times

    def write_settings(self, settings: Mapping[str, Any], history_times: Mapping[str, float]) -> None:
        rows = [
            (key, json.dumps(value), int(history_times.get(key, self.now - 86_400)), "fixture")
            for key, value in settings.items()
        ]

        def write(conn: sqlite3.Connection) -> None:
            conn.execute("DELETE FROM settings")
            conn.executemany("INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)", rows)

        self.dbs.control.write_sync(write)

    # ---- tables ----

    def tables(self) -> None:
        tables = self.data.get("tables") or {}
        for table, rows in tables.items():
            if table not in ALLOWED_TABLES:
                raise self.err(f"tables.{table}", "not an allowed table (README: tables)")
            self.insert_rows("control", table, rows or [], where=f"tables.{table}")

    def table_info(self, db: str, table: str) -> dict[str, tuple[bool, bool, bool]]:
        """`{column: (not_null, has_default, integer_primary_key)}` from `PRAGMA table_info`."""
        database = getattr(self.dbs, db)
        rows = database.read_sync(lambda conn: conn.execute(f"PRAGMA table_info({table})").fetchall())
        if not rows:
            raise self.err(f"{db}.{table}", "no such table")
        return {str(r[1]): (bool(r[3]), r[4] is not None, bool(r[5]) and str(r[2]).upper() == "INTEGER") for r in rows}

    def insert_rows(self, db: str, table: str, rows: Sequence[Mapping[str, Any]], *, where: str) -> None:
        info = self.table_info(db, table)
        prepared: list[dict[str, Any]] = []
        extras: list[tuple[dict[str, Any], dict[str, Any]]] = []
        next_id = 1
        for index, raw in enumerate(rows):
            label = f"{where}[{index}]"
            row: dict[str, Any] = {}
            x_cols: dict[str, Any] = {}
            for column, value in raw.items():
                if str(column).startswith("x_"):
                    x_cols[str(column)] = value
                    continue
                if column not in info:
                    raise self.err(label, f"unknown column {column!r} of {table}")
                row[str(column)] = column_value(str(column), value, self.now, where=label)
            for column, (not_null, has_default, pk) in info.items():
                if column in row:
                    continue
                if column == "id" and pk and table not in TABLE_PKS:
                    row["id"] = next_id  # README: the next integer for `id`
                elif has_default or not not_null:
                    continue
                elif column.endswith("_at"):
                    row[column] = int(self.now - 86_400)
                elif column.endswith("_by"):
                    row[column] = "fixture"
                else:
                    raise self.err(label, f"column {column!r} of {table} is required")
            if isinstance(row.get("id"), int):
                next_id = max(next_id, int(row["id"]) + 1)
            prepared.append(row)
            extras.append((row, x_cols))

        def write(conn: sqlite3.Connection) -> None:
            for row in prepared:
                columns = list(row)
                names = ", ".join(f'"{c}"' for c in columns)  # quoted: `limit` is a column name and an SQL keyword
                conn.execute(
                    f"INSERT INTO {table} ({names}) VALUES ({', '.join('?' for _ in columns)})",
                    [row[c] for c in columns],
                )

        getattr(self.dbs, db).write_sync(write)
        hits: list[tuple[str, str, int]] = []
        for row, x_cols in extras:
            if not x_cols:
                continue
            key = str(row.get(TABLE_PKS.get(table, "id")))
            for column, value in x_cols.items():
                if column == "x_last_hit_at":
                    if value is not None:
                        hits.append((table, key, int(parse_time(value, self.now, where=f"{where}.x_last_hit_at"))))
                    continue
                self.providers.row_extras.setdefault((table, key), {})[column] = value
        if hits:
            self.dbs.metrics.write_sync(
                lambda conn: conn.executemany(
                    "INSERT INTO rule_hits (table_name, rule_key, hits, first_hit_at, last_hit_at) "
                    "VALUES (?, ?, 1, ?, ?) "
                    "ON CONFLICT (table_name, rule_key) DO UPDATE SET last_hit_at = excluded.last_hit_at",
                    [(t, k, at, at) for t, k, at in hits],
                )
            )

    # ---- state ----

    async def state(self) -> None:
        state = self.data.get("state") or {}
        for key in state:
            if key not in STATE_SECTIONS and not str(key).startswith("x_"):
                raise self.err(f"state.{key}", "unknown state section")
        now_ms = int(self.now * 1000)
        for key, value in state.items():
            if str(key).startswith("x_"):
                self.providers.extras[str(key)] = expand_rows(value, self.now, where=f"state.{key}", timed=False)
        if "cooldowns" in state:
            rows = [
                {
                    "key": r["key"],
                    "until_ms": r.get("until"),
                    "source": r.get("source", "retry_after"),
                    "set_at": r.get("set_at", "now"),
                    "hits": r.get("hits", 0),
                }
                for r in state["cooldowns"]
            ]
            self.insert_rows("hot", "cooldown", rows, where="state.cooldowns")
        if "breakers" in state:
            await self.breakers(state["breakers"])
        if "buckets" in state:
            self.buckets(state["buckets"], now_ms)
        if "credential" in state:
            await self.credential(state["credential"])
        if "egress" in state:
            self.egress(state["egress"])
        if "workers" in state:
            self.workers(state["workers"])
        if "leader" in state:
            self.leader(state["leader"])
        if "disk" in state:
            self.providers.disk_data = copy.deepcopy(state["disk"])
            for point in self.providers.disk_data.get("growth") or []:
                point["at"] = parse_time(point.get("at"), self.now, where="state.disk.growth")
        if "dns" in state:
            self.providers.dns_data = {str(h): dict(v or {}) for h, v in (state["dns"] or {}).items()}
        if "health" in state:
            self.health(state["health"])
        if "settings_history" in state:
            self.settings_history(state["settings_history"])
        if "admin_logins" in state:
            self.admin_logins(state["admin_logins"])
        if "service_state" in state:
            self.service_state(state["service_state"])
        if "cache" in state:
            self.cache(state["cache"])
        if "client_scores" in state:
            for index, item in enumerate(state["client_scores"] or []):
                addresses = (
                    pool(item["clients"], where=f"state.client_scores[{index}]")
                    if "clients" in item
                    else [str(item["ip"])]
                )
                for address in addresses:
                    self.providers.scores[address] = float(item["bot_score"])
        if "tarpit" in state:
            self.providers.tarpit_data = dict(state["tarpit"] or {})
        if "ua_experiment" in state:
            self.providers.ua_data = copy.deepcopy(state["ua_experiment"])
        if "metrics_pipeline" in state:
            self.providers.pipeline = dict(state["metrics_pipeline"] or {})
        if "raw" in state:
            for db, tables in (state["raw"] or {}).items():
                if db not in DB_NAMES:
                    raise self.err(f"state.raw.{db}", "unknown database")
                for table, rows in (tables or {}).items():
                    self.insert_rows(db, table, rows or [], where=f"state.raw.{db}.{table}")

    async def breakers(self, items: Sequence[Mapping[str, Any]]) -> None:
        rows = []
        openings: list[tuple[float, str]] = []
        for index, item in enumerate(items):
            row = {k: v for k, v in item.items() if k != "openings"}
            rows.append(row)
            for opened in expand_rows(
                [o if isinstance(o, Mapping) else {"at": o} for o in item.get("openings") or []],
                self.now,
                where=f"state.breakers[{index}].openings",
            ):
                openings.append((opened["at"], str(item["key"])))
        self.insert_rows("hot", "breaker", rows, where="state.breakers")
        self.dbs.metrics.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO events (at_ms, type, severity, reason_code, endpoint_template, detail_json) "
                "VALUES (?, 'breaker_open', 'warning', 'upstream_cooldown', NULL, ?)",
                [
                    (int(at * 1000), json.dumps({"key": key, "from": "closed", "reason": "fixture"}))
                    for at, key in openings
                ],
            )
        )

    def buckets(self, items: Sequence[Mapping[str, Any]], now_ms: int) -> None:
        bucket_rows = []
        history: list[tuple[int, str, int, int, float]] = []
        for index, item in enumerate(items):
            per_min, burst = float(item["per_min"]), int(item["burst"])
            fill = float(item.get("fill_pct", 0))
            bucket_rows.append(
                (
                    str(item["bucket_key"]),
                    now_ms + fill / 100 * burst * (60_000 / per_min),
                    burst,
                    per_min / 60,
                    int(self.now),
                )
            )
            for h_index, stretch in enumerate(item.get("history") or []):
                label = f"state.buckets[{index}].history[{h_index}]"
                start, end = parse_window(stretch["window"], self.now, where=label, whole_minutes=True)
                minutes = list(range(int(start), int(end), 60))
                # A stretch's totals are spread over its minutes like a traffic `total` (README "Counts").
                spread = {
                    name: [
                        int(stretch.get(name, 0)) // len(minutes)
                        + (1 if i < int(stretch.get(name, 0)) % len(minutes) else 0)
                        for i in range(len(minutes))
                    ]
                    for name in ("attempts", "rejections")
                }
                for i, minute in enumerate(minutes):
                    history.append(
                        (
                            minute,
                            str(item["bucket_key"]),
                            spread["attempts"][i],
                            spread["rejections"][i],
                            float(stretch.get("fill_pct_peak", 0)),
                        )
                    )
        self.dbs.hot.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO upstream_bucket (bucket_key, tat_ms, burst, rate_per_s, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                bucket_rows,
            )
        )
        self.dbs.metrics.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO bucket_minute (bucket_start, bucket_key, attempts, rejections, fill_pct_peak) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (bucket_start, bucket_key) DO UPDATE SET "
                "attempts = attempts + excluded.attempts, rejections = rejections + excluded.rejections, "
                "fill_pct_peak = max(fill_pct_peak, excluded.fill_pct_peak)",
                history,
            )
        )

    async def credential(self, item: Mapping[str, Any]) -> None:
        if not item.get("present", True):
            return
        probes = expand_rows(item.get("probes") or [], self.now, where="state.credential.probes")
        probes.sort(key=lambda p: p["at"])
        last = probes[-1] if probes else None
        account = item.get("account_id")
        row = {
            "id": 1,
            "fingerprint": fingerprint("fixture-credential", TEST_KEY),
            "masked": "...fixtur",
            "account_id_fingerprint": fingerprint(str(account), TEST_KEY) if account is not None else None,
            "set_at": item.get("set_at", "-30d"),
            "set_by": "fixture",
            "status": item.get("status", "active"),
            "status_at": item.get("status_at", "now"),
            "last_probe_at": int(last["at"]) if last else None,
            "last_probe_result": json.dumps(
                {"result": last.get("result"), "kind": last.get("kind"), "status": last.get("status")}
            )
            if last
            else None,
        }
        self.insert_rows("control", "credential_meta", [row], where="state.credential")
        self.dbs.metrics.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO events (at_ms, type, severity, reason_code, detail_json) "
                "VALUES (?, 'credential_probe', 'info', 'credential', ?)",
                [
                    (
                        int(p["at"] * 1000),
                        json.dumps({"kind": p.get("kind"), "status": p.get("status"), "result": p.get("result")}),
                    )
                    for p in probes
                ],
            )
        )

    def egress(self, item: Mapping[str, Any]) -> None:
        from roxy.metrics.rollups import bucket_floor

        rows = []
        for row in expand_rows(item.get("usage") or [], self.now, where="state.egress.usage"):
            granularity = str(row["granularity"])
            start = bucket_floor(row["at"], granularity, None if granularity in ("minute", "hour") else UTC_ZONE)
            rows.append(
                (
                    start,
                    str(row["egress"]),
                    granularity,
                    int(row.get("requests", 0)),
                    int(row.get("req_bytes", 0)),
                    int(row.get("resp_bytes", 0)),
                    int(row.get("overhead_bytes", 0)),
                )
            )
        self.dbs.metrics.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO egress_usage (bucket_start, egress, granularity, requests, req_bytes, resp_bytes, "
                "overhead_bytes) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (bucket_start, egress, granularity) DO UPDATE "
                "SET requests = requests + excluded.requests, req_bytes = req_bytes + excluded.req_bytes, "
                "resp_bytes = resp_bytes + excluded.resp_bytes, "
                "overhead_bytes = overhead_bytes + excluded.overhead_bytes",
                rows,
            )
        )
        self.providers.metering = {"metering_mode": str(item.get("metering_mode", "socket"))}
        if "provider_reported_bytes" in item:
            at = parse_time(
                item.get("provider_reported_at", "now"), self.now, where="state.egress.provider_reported_at"
            )
            reported = int(item["provider_reported_bytes"])
            self.providers.metering.update(provider_reported_bytes=reported, provider_reported_at=at)
            self.dbs.metrics.write_sync(
                lambda conn: conn.execute(
                    "INSERT INTO egress_provider_reports (at, reported_bytes, entered_by) VALUES (?, ?, 'fixture')",
                    (int(at), reported),
                )
            )

    def workers(self, items: Sequence[Mapping[str, Any]]) -> None:
        rows = []
        minutes: list[tuple[int, str, int, float, float | None, float | None, int | None]] = []
        for index, item in enumerate(items):
            row = {k: v for k, v in item.items() if k not in ("history",) and not str(k).startswith("x_")}
            rows.append(row)
            worker = str(item.get("worker_id") or item.get("pid"))
            if "x_cpu_pct" in item:
                self.providers.row_extras.setdefault(("worker_heartbeat", worker), {})["x_cpu_pct"] = item["x_cpu_pct"]
            for h_index, stretch in enumerate(item.get("history") or []):
                start, end = parse_window(
                    stretch["window"], self.now, where=f"state.workers[{index}].history[{h_index}]", whole_minutes=True
                )
                for minute in range(int(start), int(end), 60):
                    cpu = stretch.get("cpu_pct")
                    minutes.append(
                        (
                            minute,
                            worker,
                            1 if cpu is not None else 0,
                            float(cpu or 0.0),
                            cpu,
                            stretch.get("loop_lag_ms_p99"),
                            stretch.get("open_conns"),
                        )
                    )
        self.insert_rows("metrics", "worker_heartbeat", rows, where="state.workers")
        self.dbs.metrics.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO worker_minute (bucket_start, worker_id, samples, cpu_pct_sum, cpu_pct_max, "
                "loop_lag_ms_p99, open_conns) VALUES (?, ?, ?, ?, ?, ?, ?)",
                minutes,
            )
        )

    def leader(self, item: Mapping[str, Any]) -> None:
        row = {
            "name": "leader",
            "holder": item.get("holder", "fixture"),
            "expires_ms": item.get("expires", "+15s"),
            "epoch": int(item.get("epoch", 1)),
        }
        self.insert_rows("hot", "lease", [row], where="state.leader")
        if item.get("job_runs"):
            self.insert_rows("hot", "job_runs", item["job_runs"], where="state.leader.job_runs")

    def health(self, item: Mapping[str, Any]) -> None:
        for index, run in enumerate(item.get("runs") or []):
            started = int(parse_time(run["started_at"], self.now, where=f"state.health.runs[{index}]"))
            results = run.get("results") or []
            summary = {"pass": 0, "warn": 0, "fail": 0}
            for result in results:
                status = str(result.get("status"))
                if status in summary:
                    summary[status] += 1

            def write(
                conn: sqlite3.Connection,
                run: Mapping[str, Any] = run,
                started: int = started,
                results: Sequence[Mapping[str, Any]] = results,
                summary: dict[str, int] = summary,
            ) -> None:
                cursor = conn.execute(
                    "INSERT INTO health_runs (started_at, finished_at, trigger, summary, version) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (started, started + 1, str(run.get("trigger", "manual")), json.dumps(summary), "fixture"),
                )
                run_id = cursor.lastrowid
                for result in results:
                    conn.execute(
                        "INSERT INTO health_results (run_id, check_id, status, value, threshold, explanation, "
                        "fix_link) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            run_id,
                            result["check_id"],
                            result["status"],
                            _text(result.get("value")),
                            _text(result.get("threshold")),
                            result.get("explanation"),
                            result.get("fix_link"),
                        ),
                    )

            self.dbs.metrics.write_sync(write)

    def settings_history(self, entries: Sequence[Mapping[str, Any]]) -> None:
        final: dict[str, tuple[float, Any]] = {}
        settings = self.data.get("settings") or {}
        for index, entry in enumerate(entries):
            key = str(entry["key"])
            at = parse_time(entry["at"], self.now, where=f"state.settings_history[{index}].at")
            if key not in final or at >= final[key][0]:
                final[key] = (at, entry.get("new"))
        for key, (_at, new) in final.items():
            expected = catalog.validate_value(key, settings[key]) if key in settings else catalog.DEFAULTS[key]
            if catalog.validate_value(key, new) != expected:
                raise self.err("state.settings_history", f"the last `new` of {key} ({new!r}) is not its setting value")
        actor_kinds = {"admin", "cli", "system", "auto_apply", "recommendation", "import"}

        def write(conn: sqlite3.Connection) -> list[tuple[int, int, str]]:
            notes = []
            for index, entry in enumerate(entries):
                at = int(parse_time(entry["at"], self.now, where=f"state.settings_history[{index}].at"))
                key = str(entry["key"])
                who = str(entry.get("changed_by") or "admin")
                kind = who if who in actor_kinds else "admin"
                conn.execute(
                    "INSERT INTO settings_history (key, old_json, new_json, changed_at, changed_by, reason, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        key,
                        json.dumps(entry.get("old")),
                        json.dumps(entry.get("new")),
                        at,
                        f"{kind}:fixture",
                        entry.get("reason"),
                        str(entry.get("source") or "admin"),
                    ),
                )
                audit_id = audit.record(
                    conn,
                    Actor(kind, "fixture"),  # type: ignore[arg-type]
                    "setting.update",
                    f"setting:{key}",
                    {"value": entry.get("old")},
                    {"value": entry.get("new")},
                    entry.get("reason"),
                    None,
                    at=at,
                    secret=False,
                )
                notes.append((at, audit_id, f"{key}: {entry.get('old')} to {entry.get('new')}"[:200]))
            return notes

        notes = self.dbs.control.write_sync(write)
        self.dbs.metrics.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO annotations (at, kind, label, audit_id) VALUES (?, 'config_change', ?, ?)",
                [(at, label, audit_id) for at, audit_id, label in notes],
            )
        )

    def admin_logins(self, items: Any) -> None:
        rows = []
        for row in expand_rows(items, self.now, where="state.admin_logins"):
            ip = str(row.get("ip") or "unknown")
            successful = bool(row.get("successful", True))
            detail = security_events.login_detail(ip, successful, row.get("username"), str(row.get("method") or ""))
            rows.append(
                (
                    int(row["at"] * 1000),
                    "info" if successful else "warn",
                    "success" if successful else "failure",
                    ip_hash(ip, TEST_KEY) if ip != "unknown" else None,
                    json.dumps(detail),
                )
            )
        self.dbs.metrics.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, detail_json) "
                "VALUES (?, 'login', ?, ?, ?, ?)",
                rows,
            )
        )

    def service_state(self, item: Mapping[str, Any]) -> None:
        rows = [(str(k), json.dumps(v), int(self.now)) for k, v in (item or {}).items()]
        self.dbs.control.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE "
                "SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                rows,
            )
        )

    def cache(self, item: Mapping[str, Any]) -> None:
        from roxy.cache.store import encode_body

        unknown = set(item or {}) - {"entries", "stores", "evictions", "passes"}
        if unknown:
            raise self.err("state.cache", f"unknown keys {sorted(unknown)}")
        entries = []
        for entry in item.get("entries") or []:
            row = dict(entry)
            size = row.pop("x_body_size", None)
            if size is not None:
                row["body"] = encode_body(b"0" * int(size), False)
                row.setdefault("body_len", int(size))
            entries.append(row)
        if entries:
            self.insert_rows("cache", "entries", entries, where="state.cache.entries")
        minutes: dict[int, list[float]] = {}
        for row in expand_rows(item.get("stores") or [], self.now, where="state.cache.stores"):
            minutes.setdefault(int(row["at"]) // 60 * 60, [0, 0, 0, 0.0, 0.0])[0] += int(row.get("count", 1))
        for row in expand_rows(item.get("evictions") or [], self.now, where="state.cache.evictions"):
            acc = minutes.setdefault(int(row["at"]) // 60 * 60, [0, 0, 0, 0.0, 0.0])
            count, age = int(row.get("count", 1)), float(row["age_s"])
            acc[1] += count
            acc[3] += age * count
            if age < float(row["ttl_s"]):
                acc[2] += count
                acc[4] += age * count
        passes = [
            (int(r["at"]), int(r["entries_before"]), int(r["bytes_before"]), int(r["evicted"]), int(r["freed_bytes"]))
            for r in expand_rows(item.get("passes") or [], self.now, where="state.cache.passes")
        ]

        def write(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "INSERT INTO cache_minute (bucket_start, stores, evictions, young_evictions, evicted_age_s_sum, "
                "young_age_s_sum) VALUES (?, ?, ?, ?, ?, ?)",
                [(m, *v) for m, v in sorted(minutes.items())],
            )
            conn.executemany(
                "INSERT INTO cache_eviction_passes (at, entries_before, bytes_before, evicted, freed_bytes) "
                "VALUES (?, ?, ?, ?, ?)",
                passes,
            )

        self.dbs.metrics.write_sync(write)

    # ---- events ----

    async def events(self, runtime: RuntimeSettings) -> None:
        events = self.data.get("events") or {}
        for key in events:
            if key not in EVENT_SECTIONS:
                raise self.err(f"events.{key}", "unknown events section")
        recorder = self.recorder(runtime)
        for row in expand_rows(events.get("upstream_429"), self.now, where="events.upstream_429"):
            template = str(row["endpoint_template"])
            self.clock.set(row["at"])
            at_ms = round(row["at"] * 1000)
            host = str(row.get("host") or template.split("/", 1)[0])
            item: dict[str, Any] = {
                "at_ms": at_ms,
                "endpoint_template": template,
                "host": host,
                "egress": str(row["egress"]),
            }
            self.rows_429.append(item)
            recorder.record_upstream_429(
                endpoint_template=template,
                host=item["host"],
                egress=item["egress"],
                retry_after_s=row.get("retry_after_s"),
                ratelimit_headers=row.get("ratelimit_headers"),
                request_id=row.get("request_id"),
                at_ms=item["at_ms"],
            )
        security_rows = []
        for index, row in enumerate(expand_rows(events.get("security"), self.now, where="events.security")):
            event_type = str(row.get("type"))
            if event_type not in SECURITY_TYPES:
                raise self.err(f"events.security[{index}]", f"unknown event type {event_type!r}")
            detail = dict(row.get("detail") or {})
            ip = row.get("ip")
            if ip and event_type in IP_DETAIL_TYPES:
                detail.setdefault("ip", str(ip))
            security_rows.append(
                (
                    round(row["at"] * 1000),
                    event_type,
                    str(row.get("severity") or "info"),
                    row.get("reason_code"),
                    ip_hash(str(ip), TEST_KEY) if ip else None,
                    row.get("place"),
                    row.get("endpoint_template"),
                    json.dumps(detail) if detail else None,
                )
            )
        for item in events.get("errors") or []:
            self.error(item)
        if events.get("request_samples"):
            self.insert_rows("metrics", "request_samples", events["request_samples"], where="events.request_samples")
        if events.get("change_observations"):
            self.insert_rows(
                "cache", "change_observations", events["change_observations"], where="events.change_observations"
            )
        if events.get("anomalies"):
            self.insert_rows("metrics", "anomalies", events["anomalies"], where="events.anomalies")
        if events.get("annotations"):
            self.insert_rows("metrics", "annotations", events["annotations"], where="events.annotations")
        for row in expand_rows(events.get("internal_calls"), self.now, where="events.internal_calls"):
            status = int(row.get("status", 200))
            egress = str(row.get("egress", "direct"))
            template = str(row.get("endpoint_template") or "")
            self.clock.set(row["at"])
            recorder.record_internal_call(
                str(row["purpose"]),
                ok=status < 400,
                status=status,
                endpoint_template=template,
                host=template.split("/", 1)[0],
                egress=egress,
                auth_class=AuthClass.CRED if egress == "credential" else AuthClass.ANON,
                trigger=str(row.get("trigger") or ""),
                at_ms=round(row["at"] * 1000),
            )
        for row in expand_rows(events.get("upstream_attempts"), self.now, where="events.upstream_attempts"):
            recorder.record_attempt(
                endpoint_template=str(row["endpoint_template"]),
                egress=str(row["egress"]),
                attempt=int(row.get("attempt", 1)),
                kind=str(row["kind"]),
                status=row.get("status"),
                challenge=bool(row.get("challenge", False)),
                html_body=bool(row.get("html_body", False)),
                exit_id=str(row.get("exit_id") or ""),
                at_ms=round(row["at"] * 1000),
            )
        await recorder.aclose(budget_s=60.0)
        if recorder.batch.dropped:
            raise self.err("events", f"the recorder dropped {recorder.batch.dropped} items")
        if security_rows:
            self.dbs.metrics.write_sync(
                lambda conn: conn.executemany(
                    "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, "
                    "detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    security_rows,
                )
            )

    def error(self, item: Mapping[str, Any]) -> None:
        signature = str(item["signature"])
        row = {
            "signature": signature,
            "count": int(item.get("count", 0)),
            "first_seen": item["first_seen"],
            "last_seen": item["last_seen"],
            "source": item.get("source", "roxy"),
            "last_detail": item.get("last_detail"),
            "module_line": item.get("module_line"),
            "traceback_redacted": item.get("traceback_redacted"),
        }
        self.insert_rows("metrics", "errors", [row], where=f"events.errors[{signature}]")
        counts: dict[int, int] = {}
        for occurrence in expand_rows(item.get("occurrences") or [], self.now, where=f"events.errors[{signature}]"):
            minute = int(occurrence["at"]) // 60 * 60
            counts[minute] = counts.get(minute, 0) + 1
        self.dbs.metrics.write_sync(
            lambda conn: conn.executemany(
                "INSERT INTO error_minute (signature, bucket_start, count) VALUES (?, ?, ?)",
                [(signature, minute, n) for minute, n in sorted(counts.items())],
            )
        )

    # ---- traffic ----

    def recorder(self, runtime: RuntimeSettings) -> MetricsRecorder:
        # Samples come only from the fixture's `samples` side outputs (README), so the recorder's own sampling is off;
        # except for the rules of `RECORDER_SAMPLED_RULES` (extension hook below), which read production samples.
        view: Any = runtime if recorder_samples(self.data) else _NoAutoSamples(runtime)
        recorder = MetricsRecorder(self.dbs, view, self.clock, ip_hash_key=TEST_KEY, rng=lambda: 0.0)
        # The Live feed rows (`events` type `live`, kept 15 minutes for the Live page) are not read by any rule and
        # cost half of a load (each row is redacted like a log line), so the fixture recorder writes none.
        recorder._live_gate = RateGate(0.0, 0.0, self.clock.monotonic)
        return recorder

    def expand_traffic(self) -> list[TrafficEvent]:
        defaults = dict(self.data.get("traffic_defaults") or {})
        profiles = dict(self.data.get("profiles") or {})
        for name, profile in profiles.items():
            bad = set(profile) - (GENERATOR_FIELDS - PROFILE_EXCLUDED)
            if bad:
                raise self.err(f"profiles.{name}", f"keys not allowed in a profile: {sorted(bad)}")
        bad_defaults = set(defaults) - (GENERATOR_FIELDS - PROFILE_EXCLUDED)
        if bad_defaults:
            raise self.err("traffic_defaults", f"unknown keys {sorted(bad_defaults)}")
        out: list[TrafficEvent] = []
        names: set[str] = set()
        for order, gen in enumerate(self.data.get("traffic") or []):
            name = str(gen.get("name") or "")
            where = f"traffic[{name or order}]"
            if not name or name in names:
                raise self.err(where, "every generator needs a unique name")
            names.add(name)
            unknown = set(gen) - GENERATOR_FIELDS
            if unknown:
                raise self.err(where, f"unknown keys {sorted(unknown)}")
            spec: dict[str, Any] = dict(defaults)
            chosen = gen.get("profile") or []
            for profile_name in [chosen] if isinstance(chosen, str) else chosen:
                if profile_name not in profiles:
                    raise self.err(where, f"unknown profile {profile_name!r}")
                spec.update(profiles[profile_name])
            spec.update({k: v for k, v in gen.items() if k != "profile"})
            start, end = parse_window(spec["window"], self.now, where=where, whole_minutes=True)
            make = self.event_maker(spec, where)
            for n, at_ms in enumerate(placements(spec, start, end, where=where)):
                out.append(TrafficEvent(make(n, at_ms), name, order, n, spec))
            if len(out) > MAX_EVENTS:
                raise self.err("traffic", f"more than {MAX_EVENTS} events")
        out.sort(key=lambda e: (e.event.at_ms, e.order, e.n))
        return out

    def event_maker(self, spec: Mapping[str, Any], where: str) -> Callable[[int, int], OutcomeEvent]:
        """Validate one generator once; return `make(n, at_ms)` that builds its events (README "traffic")."""

        def enum(cls: Any, key: str, default: Any = _MISSING) -> Any:
            value = spec.get(key, default)
            if value is _MISSING:
                raise self.err(where, f"{key} is required")
            if isinstance(value, bool):
                raise self.err(where, f"{key}: a boolean where an enum string is expected (quote it)")
            try:
                return cls(str(value))
            except ValueError:
                raise self.err(where, f"{key}: unknown value {value!r}") from None

        template = str(spec.get("endpoint_template") or "")
        if not template:
            raise self.err(where, "endpoint_template is required")
        egress = enum(Egress, "egress")
        outcome = enum(Outcome, "outcome")
        reason = enum(ReasonCode, "reason")
        source = enum(Source, "source")
        cache_state = enum(CacheState, "cache_state")
        auth = enum(AuthClass, "auth_class", "anon")
        calls = int(spec.get("upstream_calls", 0 if egress is Egress.NONE else 1))
        if (egress is Egress.NONE) != (calls == 0):
            raise self.err(where, "egress none if and only if upstream_calls 0")
        if auth is AuthClass.CRED and egress is not Egress.CREDENTIAL:
            raise self.err(where, "auth_class cred only with egress credential")
        if reason in REFUSAL_REASONS and outcome is not Outcome.REFUSED:
            raise self.err(where, f"refusal reason {reason} needs outcome refused")
        if reason in FAILURE_REASONS and outcome is not Outcome.FAILED:
            raise self.err(where, f"failure reason {reason} needs outcome failed")
        if reason in SERVED_REASONS and outcome not in (Outcome.SERVED_UPSTREAM, Outcome.SERVED_CACHE):
            raise self.err(where, f"served reason {reason} needs a served outcome")
        if "status" not in spec:
            raise self.err(where, "status is required")
        size = dict(spec.get("bytes") or {})
        unknown = set(size) - {"caller_in", "caller_out", "upstream_in", "upstream_out"}
        if unknown:
            raise self.err(where, f"bytes: unknown keys {sorted(unknown)}")
        status = int(spec["status"])
        upstream_status = spec.get("upstream_status", status if source is Source.RELAY else None)
        if "client_ip" in spec:
            clients = pool(spec["client_ip"], where=where)
        elif "clients" in spec:
            clients = pool(spec["clients"], where=where)
        else:
            raise self.err(where, "client_ip or clients is required")
        places: list[str | None] = (
            list(pool(spec["places"], where=where))
            if "places" in spec
            else ([str(spec["place_id"])] if spec.get("place_id") is not None else [None])
        )
        agents = pool(spec["user_agents"], where=where) if "user_agents" in spec else [str(spec.get("user_agent", ""))]
        paths = pool(spec["paths"], where=where) if "paths" in spec else [str(spec.get("path", ""))]
        name = str(spec.get("name"))
        host = str(spec.get("host") or template.split("/", 1)[0])
        method = str(spec.get("method", "GET"))
        latency_spec, queue_spec = spec.get("latency_ms", 0), spec.get("queue_wait_ms", 0)
        upstream_spec = spec.get("upstream_ms")
        fixed_id = spec.get("request_id")
        case = self.data["case"]

        def make(n: int, at_ms: int) -> OutcomeEvent:
            latency = distribution(latency_spec, n, where=f"{where}.latency_ms")
            queue = distribution(queue_spec, n, where=f"{where}.queue_wait_ms")
            if upstream_spec is not None:
                upstream_ms = distribution(upstream_spec, n, where=f"{where}.upstream_ms")
            else:
                upstream_ms = max(0.0, latency - queue) if calls > 0 else 0.0
            return OutcomeEvent(
                at_ms=at_ms,
                request_id=str(fixed_id or f"{case}-{name}-{n}"),
                endpoint_template=template,
                host=host,
                method=method,
                egress=egress,
                outcome=outcome,
                reason=reason,
                status=status,
                source=source,
                cache_state=cache_state,
                auth_class=auth,
                caller_bytes_in=int(size.get("caller_in", 0)),
                caller_bytes_out=int(size.get("caller_out", 0)),
                upstream_calls=calls,
                upstream_bytes_in=int(size.get("upstream_in", 0)) * calls,
                upstream_bytes_out=int(size.get("upstream_out", 0)) * calls,
                latency_ms=latency,
                queue_wait_ms=queue,
                upstream_ms=upstream_ms,
                client_ip=clients[n % len(clients)],
                place_id=places[n % len(places)],
                user_agent=agents[n % len(agents)],
                bypass=bool(spec.get("bypass", False)),
                error=bool(spec.get("error", False)),
                path=paths[n % len(paths)],
                upstream_status=None if upstream_status is None else int(upstream_status),
            )

        return make

    def sample_rows(self, events: Sequence[TrafficEvent]) -> list[SampleRow]:
        """README "Side output samples"."""
        spaces: dict[str, list[TrafficEvent]] = {}
        for item in events:
            spec = item.spec.get("samples")
            if not spec:
                continue
            unknown = set(spec) - {"key_space", "keys", "body_change_interval_s", "every"}
            if unknown:
                raise self.err(f"traffic[{item.generator}].samples", f"unknown keys {sorted(unknown)}")
            if item.n % int(spec.get("every", 1)) == 0:
                spaces.setdefault(str(spec["key_space"]), []).append(item)
        rows: list[SampleRow] = []
        for space, members in spaces.items():
            members.sort(key=lambda e: (e.event.at_ms, e.order, e.n))
            for position, item in enumerate(members):
                spec = item.spec["samples"]
                keys = int(spec["keys"])
                index = position % keys
                interval = spec.get("body_change_interval_s")
                ev = item.event
                body_hash = None
                if ev.upstream_calls >= 1 and ev.source is Source.RELAY and 200 <= ev.status <= 299:
                    if interval:
                        period = int(interval) * 1000
                        phase = (index * period) // keys
                        epoch = (ev.at_ms - phase) // period
                    else:
                        epoch = 0
                    body_hash = hashlib.sha256(f"{space}:{index}:{epoch}".encode()).hexdigest()[:16]
                rows.append(
                    SampleRow(
                        at_ms=ev.at_ms,
                        key_id=hashlib.sha256(f"{space}:{index}".encode()).hexdigest()[:24],
                        endpoint_template=ev.endpoint_template,
                        method=ev.method,
                        client_hash=ip_hash(ev.client_ip, TEST_KEY),
                        place=ev.place_id,
                        cache_state=str(ev.cache_state),
                        upstream_status=ev.upstream_status,
                        egress=str(ev.egress),
                        body_hash=body_hash,
                        bytes=ev.caller_bytes_out,
                        auth_class=str(ev.auth_class),
                    )
                )
        return rows

    async def traffic(self, runtime: RuntimeSettings) -> None:
        self.expanded = self.expand_traffic()
        if not self.expanded:
            return
        recorder = self.recorder(runtime)
        samples = sorted(self.sample_rows(self.expanded), key=lambda r: r.at_ms)
        sample_index = 0
        for count, item in enumerate(self.expanded, start=1):
            ev = item.event
            self.clock.set(ev.at_ms / 1000)
            recorder.record_outcome(ev)
            side = item.spec.get("upstream_429")
            if side:
                unknown = set(side) - {"egress", "retry_after_s", "ratelimit_headers", "offset_ms"}
                if unknown:
                    raise self.err(f"traffic[{item.generator}].upstream_429", f"unknown keys {sorted(unknown)}")
                at = ev.at_ms + int(side.get("offset_ms", 0))
                self.rows_429.append(
                    {
                        "at_ms": at,
                        "endpoint_template": ev.endpoint_template,
                        "host": ev.host,
                        "egress": str(side["egress"]),
                    }
                )
                recorder.record_upstream_429(
                    endpoint_template=ev.endpoint_template,
                    host=ev.host,
                    egress=str(side["egress"]),
                    retry_after_s=side.get("retry_after_s"),
                    ratelimit_headers=side.get("ratelimit_headers"),
                    request_id=ev.request_id,
                    at_ms=at,
                )
            while sample_index < len(samples) and samples[sample_index].at_ms <= ev.at_ms:
                recorder.record_sample(samples[sample_index])
                sample_index += 1
            if count % FLUSH_EVERY == 0:
                await recorder.flush()
        for row in samples[sample_index:]:
            recorder.record_sample(row)
        await recorder.aclose(budget_s=120.0)
        if recorder.batch.dropped:
            raise self.err("traffic", f"the recorder dropped {recorder.batch.dropped} items (raise FLUSH_EVERY)")


UTC_ZONE: Final = __import__("zoneinfo").ZoneInfo("UTC")


class _NoAutoSamples:
    """The settings view the fixture recorder reads: the run's settings with `request_sample_pct` at 0."""

    def __init__(self, runtime: RuntimeSettings) -> None:
        self.runtime = runtime

    @property
    def version(self) -> int:
        return self.runtime.version

    def get(self, key: str) -> Any:
        return 0 if key == "request_sample_pct" else self.runtime.get(key)


# ============================================================== extension hook: recorder sampling (rules_abuse_system)
# Added by the rules_abuse_system author (P10), README "Extensions (added by the rules_abuse_system author)". The
# rest of the loader is unchanged; this hook only decides which settings view the fixture recorder gets.

RECORDER_SAMPLED_RULES: Final = frozenset({"PLACE-HEAVY", "THROTTLE-TUNE"})
"""Rules that read the request samples production writes for every proxied request (`request_sample_pct`, catalog
default 100): PLACE-HEAVY's upstream share per place and THROTTLE-TUNE's upstream share per client. Their fixtures
load with the recorder's own sampling at the fixture's `request_sample_pct`, exactly as production records them, so
the rules read real `request_samples` rows instead of a fixture-only provider. No fixture of these rules uses a
`samples` side output, so the two sources never mix."""


def recorder_samples(data: Mapping[str, Any]) -> bool:
    """Whether a fixture loads with the recorder's own request sampling on (the hook above)."""
    return str(data.get("rule")) in RECORDER_SAMPLED_RULES


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


# ============================================================================================ data checks


def _event_where(item: TrafficEvent, where: Mapping[str, Any]) -> bool:
    ev = item.event
    values: dict[str, Any] = {
        "endpoint_template": ev.endpoint_template,
        "host": ev.host,
        "method": ev.method,
        "egress": str(ev.egress),
        "outcome": str(ev.outcome),
        "reason": str(ev.reason),
        "status": ev.status,
        "source": str(ev.source),
        "cache_state": str(ev.cache_state),
        "auth_class": str(ev.auth_class),
        "client_ip": ev.client_ip,
        "place_id": ev.place_id,
    }
    for key, wanted in where.items():
        have = values[key]
        if key == "status":
            if int(have) != int(wanted):
                return False
        elif str(have) != str(wanted):
            return False
    return True


def run_data_checks(state: LoadedFixture, checks: Sequence[Mapping[str, Any]]) -> None:
    """README `data_checks`: against the expanded events, then through `metrics/queries.py` (step 4)."""
    for index, check in enumerate(checks or []):
        label = f"{state.name}: data_checks[{index}]"
        unknown = set(check) - CHECK_MEASURES - {"window", "where"}
        if unknown:
            raise FixtureError(f"{label}: unknown keys {sorted(unknown)}")
        start, end = parse_window(check["window"], state.now, where=label)
        where = dict(check.get("where") or {})
        bad = set(where) - CHECK_WHERE
        if bad:
            raise FixtureError(f"{label}: unknown where keys {sorted(bad)}")
        lo, hi = int(start * 1000), int(end * 1000)
        events = [e for e in state.traffic if lo <= e.event.at_ms < hi and _event_where(e, where)]
        found = {
            "requests": len(events),
            "upstream_calls": sum(e.event.upstream_calls for e in events),
            "served_upstream": sum(1 for e in events if e.event.outcome is Outcome.SERVED_UPSTREAM),
            "served_cache": sum(1 for e in events if e.event.outcome is Outcome.SERVED_CACHE),
            "refused": sum(1 for e in events if e.event.outcome is Outcome.REFUSED),
            "failed": sum(1 for e in events if e.event.outcome is Outcome.FAILED),
            "stale_after_failure": sum(1 for e in events if e.event.reason is ReasonCode.CACHE_STALE_ERROR),
            "errors": sum(1 for e in events if e.event.error),
        }
        found["avoided_calls"] = found["requests"] - found["upstream_calls"]
        where_429 = {k: v for k, v in where.items() if k in ("endpoint_template", "host", "egress")}
        found["roblox_429"] = sum(
            1
            for row in state.rows_429
            if lo <= row["at_ms"] < hi and all(str(row[k]) == str(v) for k, v in where_429.items())
        )
        reasons: dict[str, int] = {}
        for e in events:
            reasons[str(e.event.reason)] = reasons.get(str(e.event.reason), 0) + 1
        for measure in CHECK_MEASURES & set(check):
            if measure == "by_reason":
                for reason, expected in check["by_reason"].items():
                    if reasons.get(str(reason), 0) != int(expected):
                        raise FixtureError(
                            f"{label}: by_reason.{reason} is {reasons.get(str(reason), 0)}, the file says {expected}"
                        )
            elif found[measure] != int(check[measure]):
                raise FixtureError(f"{label}: {measure} is {found[measure]}, the file says {check[measure]}")
        if getattr(state, "dbs", None) is not None:
            _read_model_check(state, label, start, end, where, check)


_READ_MODEL: Final = {
    "requests": "requests",
    "upstream_calls": "upstream_calls",
    "served_cache": "served_cache",
    "refused": "refused",
    "failed": "failed",
    "stale_after_failure": "errors_hidden",
}


def _read_model_check(
    state: LoadedFixture,
    label: str,
    start: float,
    end: float,
    where: Mapping[str, Any],
    check: Mapping[str, Any],
) -> None:
    """The same numbers through the rollups, where the filters are rollup dimensions with Roblox hosts."""
    if set(where) & {"client_ip", "place_id"}:
        return
    if "status" in where and int(where["status"]) not in KNOWN_STATUSES:
        return
    for key in ("endpoint_template", "host"):
        value = str(where.get(key) or "")
        host = value.split("/", 1)[0] if value else ""
        if value and not (host == "roblox.com" or host.endswith(".roblox.com")):
            return
    filters = {("reason_code" if k == "reason" else k): v for k, v in where.items()}
    window = Window(int(start), int(end), "minute", "UTC")
    totals = state.dbs.metrics.read_sync(lambda conn: queries.totals_sync(conn, window, filters=filters))
    for measure, column in _READ_MODEL.items():
        if measure in check and int(totals.get(column) or 0) != int(check[measure]):
            raise FixtureError(
                f"{label}: the rollups say {measure} = {totals.get(column)}, the file says {check[measure]}"
            )
    filterable_429 = set(where) <= {"endpoint_template", "host", "egress"}
    if "roblox_429" in check and filterable_429 and int(totals.get("roblox_429") or 0) != int(check["roblox_429"]):
        raise FixtureError(f"{label}: the 429 log says {totals.get('roblox_429')}, the file says {check['roblox_429']}")


# ============================================================================================= constraints


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, str)


def _num_eq(a: Any, b: Any) -> bool:
    return abs(float(a) - float(b)) <= 1e-9


def check(value: Any, constraint: Any, *, parent: Mapping[str, Any] | None = None, path: str = "value") -> str | None:
    """README "Constraint grammar": None when `value` satisfies `constraint`, else the first failure."""
    if constraint is None:
        return None if value is _MISSING or value is None else f"{path}: expected null, got {value!r}"
    if isinstance(constraint, Mapping):
        if constraint and all(str(k) in OPERATORS for k in constraint):
            for op, arg in constraint.items():
                problem = _operator(value, str(op), arg, parent, path)
                if problem:
                    return problem
            return None
        if value is _MISSING or not isinstance(value, Mapping):
            return f"{path}: expected a mapping, got {'nothing' if value is _MISSING else repr(value)}"
        for key, sub in constraint.items():
            problem = check(value.get(key, _MISSING), sub, parent=value, path=f"{path}.{key}")
            if problem:
                return problem
        return None
    if value is _MISSING:
        return f"{path}: missing (expected {constraint!r})"
    if isinstance(constraint, list):
        if not isinstance(value, list | tuple) or len(value) != len(constraint):
            return f"{path}: expected the list {constraint!r}, got {value!r}"
        for index, (item, sub) in enumerate(zip(value, constraint, strict=True)):
            problem = check(item, sub, path=f"{path}[{index}]")
            if problem:
                return problem
        return None
    if _is_number(constraint) or isinstance(constraint, bool):
        if (_is_number(value) or isinstance(value, bool)) and _num_eq(value, constraint):
            return None
        return f"{path}: expected {constraint!r}, got {value!r}"
    return None if value == constraint else f"{path}: expected {constraint!r}, got {value!r}"


def _items(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip().lower() for part in value.split(",") if part.strip()]
    if isinstance(value, list | tuple):
        return [str(v).lower() for v in value]
    return []


def _operator(value: Any, op: str, arg: Any, parent: Mapping[str, Any] | None, path: str) -> str | None:
    if op == "present":
        present = value is not _MISSING and value is not None
        return None if present == bool(arg) else f"{path}: present is {present}, expected {arg}"
    if value is _MISSING:
        return f"{path}: missing (needed for {op})"
    fail = f"{path}: {value!r} does not satisfy {op} {arg!r}"
    if op == "eq":
        return check(value, arg, path=path)
    if op == "ne":
        return None if check(value, arg, path=path) is not None else fail
    if op in ("lt", "lte", "gt", "gte", "between"):
        if not (_is_number(value) or isinstance(value, bool)):
            return fail
        number = float(value)
        if op == "between":
            ok = float(arg[0]) - 1e-9 <= number <= float(arg[1]) + 1e-9
        else:
            ok = {
                "lt": number < float(arg) - 1e-9,
                "lte": number <= float(arg) + 1e-9,
                "gt": number > float(arg) + 1e-9,
                "gte": number >= float(arg) - 1e-9,
            }[op]
        return None if ok else fail
    if op in ("in", "not_in"):
        inside = any(check(value, option) is None for option in arg)
        return None if inside == (op == "in") else fail
    if op == "contains":
        if isinstance(value, str):
            return None if str(arg) in value else fail
        if isinstance(value, list | tuple):
            return None if any(check(item, arg) is None for item in value) else fail
        return fail
    if op == "contains_all":
        have = _items(value)
        return None if all(str(item).lower() in have for item in arg) else fail
    if op == "regex":
        return None if isinstance(value, str) and re.search(str(arg), value) else fail
    if op in ("matches_targets", "not_matches_targets"):
        kind = str((parent or {}).get("type") or "glob")
        compiled = compile_pattern(str(value), kind)
        for target in arg:
            matched = compiled.matches(str(target))
            if matched != (op == "matches_targets"):
                return f"{path}: pattern {value!r} ({kind}) {'does not match' if not matched else 'matches'} {target!r}"
        return None
    return f"{path}: unknown operator {op}"


# ============================================================================================ rec matching


def _change_matches(change: Mapping[str, Any], matcher: Mapping[str, Any]) -> str | None:
    if "any_of" in matcher:
        problems = [_change_matches(change, option) for option in matcher["any_of"]]
        return None if any(p is None for p in problems) else f"no alternative matched ({problems[0]})"
    if "kind" not in matcher:
        return "a change matcher needs kind"
    return check(change, dict(matcher), path="change")


def _assign(changes: Sequence[Mapping[str, Any]], matchers: Sequence[Mapping[str, Any]]) -> list[int] | None:
    """A distinct change for every matcher (small backtracking search), or None."""
    used: list[int] = []

    def place(i: int) -> bool:
        if i == len(matchers):
            return True
        for j, change in enumerate(changes):
            if j not in used and _change_matches(change, matchers[i]) is None:
                used.append(j)
                if place(i + 1):
                    return True
                used.pop()
        return False

    return list(used) if place(0) else None


async def rec_problem(state: LoadedFixture, rec: Recommendation, matcher: Mapping[str, Any]) -> str | None:
    """The first field of `matcher` that `rec` does not satisfy, or None."""
    unknown = set(matcher) - MATCHER_KEYS
    if unknown:
        raise FixtureError(f"{state.name}: unknown matcher keys {sorted(unknown)}")
    if rec.rule_id != str(matcher.get("rule_id", state.rule)):
        return f"rule_id is {rec.rule_id}"
    if "subject" in matcher and rec.subject != str(matcher["subject"]):
        return f"subject {rec.subject!r} is not {matcher['subject']!r}"
    if "subject_contains" in matcher and str(matcher["subject_contains"]) not in rec.subject:
        return f"subject {rec.subject!r} does not contain {matcher['subject_contains']!r}"
    if "title_contains" in matcher and str(matcher["title_contains"]) not in rec.title:
        return f"title {rec.title!r} does not contain {matcher['title_contains']!r}"
    severity = matcher.get("severity", "any")
    if severity != "any" and rec.severity != severity:
        return f"severity is {rec.severity}, expected {severity}"
    for name in ("confidence", "risk", "family", "safe_auto"):
        if name in matcher:
            problem = check(getattr(rec, name), matcher[name], path=name)
            if problem:
                return problem
    kinds = set(rec.change_kinds)
    for kind in matcher.get("change_kinds_required") or []:
        if kind not in kinds:
            return f"no change of kind {kind} (kinds: {sorted(kinds)})"
    for kind in matcher.get("change_kinds_forbidden") or []:
        if kind in kinds:
            return f"a change of forbidden kind {kind}"
    changes = [change.to_dict() for change in rec.changes]
    required = list(matcher.get("changes_required") or [])
    assignment = _assign(changes, required)
    if assignment is None:
        for item in required:
            problems = [_change_matches(change, item) for change in changes]
            if all(p is not None for p in problems):
                return f"no change matches {item!r}: {problems}"
        return "the required changes cannot each match a different change"
    for item in matcher.get("changes_forbidden") or []:
        options = item["any_of"] if isinstance(item, Mapping) and "any_of" in item else [item]
        for option in options:
            for change in changes:
                if _change_matches(change, option) is None:
                    return f"change {change!r} matches the forbidden {option!r}"
    if matcher.get("exact_changes") and len(changes) != len(assignment):
        return f"{len(changes)} changes, but exact_changes allows only the {len(assignment)} required ones"
    evidence = matcher.get("evidence")
    if evidence:
        for name, constraint in (evidence.get("metrics") or {}).items():
            value = next((m.value for m in rec.evidence.metrics if m.name == name), _MISSING)
            if value is _MISSING:
                return f"evidence metric {name} is missing (have {[m.name for m in rec.evidence.metrics]})"
            problem = check(value, constraint, path=f"evidence.{name}")
            if problem:
                return problem
        if "window" in evidence:
            for side, have in (("from", rec.evidence.window_from), ("to", rec.evidence.window_to)):
                if side in evidence["window"]:
                    wanted = parse_time(evidence["window"][side], state.now, where="evidence.window")
                    if have is None or abs(float(have) - wanted) > 1e-6:
                        return f"evidence window {side} is {iso(have)}, expected {iso(wanted)}"
    dry = matcher.get("dry_run")
    if dry:
        if "available" in dry and rec.dry_run_available != bool(dry["available"]):
            return f"dry_run available is {rec.dry_run_available}"
        measures = {k: v for k, v in dry.items() if k != "available"}
        if measures:
            report = (await state.engine.dry_run(rec)).to_dict()
            for name, constraint in measures.items():
                problem = check(report.get(name, _MISSING), constraint, path=f"dry_run.{name}")
                if problem:
                    return problem
    return None


def describe(recs: Sequence[Recommendation]) -> str:
    lines = []
    for rec in recs:
        changes = "; ".join(json.dumps(c.to_dict(), default=str) for c in rec.changes)
        lines.append(f"  - [{rec.severity}/{rec.confidence}] {rec.rule_id} {rec.subject!r}: {rec.title} | {changes}")
    return "\n".join(lines) or "  (none)"


async def check_expect(state: LoadedFixture, outcome: RuleOutcome, expect: Mapping[str, Any], label: str) -> None:
    """Compare one evaluation with `expect` (README "expect"); raises ExpectationFailed with the details."""
    unknown = set(expect) - EXPECT_KEYS
    if unknown:
        raise FixtureError(f"{label}: unknown expect keys {sorted(unknown)}")
    if outcome.error:
        raise ExpectationFailed(f"{label}: the rule raised {outcome.error}")
    recs = outcome.recommendations
    fires = bool(expect.get("fires"))
    if fires != bool(recs):
        raise ExpectationFailed(f"{label}: expected fires={fires}, got {len(recs)} recommendations:\n{describe(recs)}")
    matchers = list(expect.get("recommendations") or [])
    if not fires and matchers:
        raise FixtureError(f"{label}: fires: false with recommendation matchers")
    matched: set[int] = set()
    for index, matcher in enumerate(matchers):
        reasons = []
        for rec_index, rec in enumerate(recs):
            if rec_index in matched:
                continue
            problem = await rec_problem(state, rec, matcher)
            if problem is None:
                matched.add(rec_index)
                break
            reasons.append(f"{rec.subject!r}: {problem}")
        else:
            raise ExpectationFailed(
                f"{label}: recommendations[{index}] matched nothing.\nReturned:\n{describe(recs)}\nWhy not:\n  "
                + "\n  ".join(reasons or ["(no recommendation left to match)"])
            )
    if expect.get("others", "allow") == "forbid" and len(matched) != len(recs):
        extra = [rec for i, rec in enumerate(recs) if i not in matched]
        raise ExpectationFailed(f"{label}: others: forbid, but these were not expected:\n{describe(extra)}")


# ================================================================================================ running


_LOADED: dict[str, LoadedFixture] = {}
MAX_LOADED: Final = 3
"""Loaded fixtures kept open (each holds four databases and their threads); the least recently used is closed.
Pytest runs a file's cases one after another, so three is plenty to load each file once."""


def _close_all() -> None:
    for state in _LOADED.values():
        state.close()
    _LOADED.clear()


atexit.register(_close_all)


async def loaded(name: str) -> LoadedFixture:
    """The loaded state of a fixture, shared by its cases (variants change settings only, README step 7)."""
    path = fixture_path(name)
    key = str(path.resolve())
    state = _LOADED.pop(key, None)
    if state is None:
        while len(_LOADED) >= MAX_LOADED:
            oldest = next(iter(_LOADED))
            _LOADED.pop(oldest).close()
        state = await load(path)
        try:
            run_data_checks(state, (state.data.get("expect") or {}).get("data_checks") or [])
        except BaseException:
            state.close()
            raise
    _LOADED[key] = state  # most recently used last
    return state


@dataclass
class DryFixture:
    """A fixture expanded in memory only (no databases): enough for validation and the in-memory data checks."""

    name: str
    data: dict[str, Any]
    now: float
    traffic: list[TrafficEvent]
    rows_429: list[dict[str, Any]]
    samples: list[SampleRow]


def dry_check(name: str | Path) -> DryFixture:
    """Validate a fixture and check its `data_checks` against the expanded events, without databases (fast)."""
    path, data = read_fixture(name)
    now = parse_time(data["now"], 0, where="now")
    validate_settings(data.get("settings") or {}, where=f"{path.name}: settings")
    for index, variant in enumerate(data.get("variants") or []):
        validate_settings(
            {**(data.get("settings") or {}), **(variant.get("settings") or {})},
            where=f"{path.name}: variants[{index}].settings",
        )
    for section, allowed in (("events", EVENT_SECTIONS), ("state", STATE_SECTIONS)):
        for key in data.get(section) or {}:
            if key not in allowed and not str(key).startswith("x_"):
                raise FixtureError(f"{path.name}: unknown {section} section {key!r}")
    for table in data.get("tables") or {}:
        if table not in ALLOWED_TABLES:
            raise FixtureError(f"{path.name}: tables.{table} is not an allowed table")
    loader = _Loader(path.name, data, now, None, FakeClock(now), FixtureProviders())  # type: ignore[arg-type]
    traffic = loader.expand_traffic()
    rows_429 = [
        {
            "at_ms": t.event.at_ms + int(t.spec["upstream_429"].get("offset_ms", 0)),
            "endpoint_template": t.event.endpoint_template,
            "host": t.event.host,
            "egress": str(t.spec["upstream_429"]["egress"]),
        }
        for t in traffic
        if t.spec.get("upstream_429")
    ]
    for row in expand_rows((data.get("events") or {}).get("upstream_429"), now, where="events.upstream_429"):
        template = str(row["endpoint_template"])
        rows_429.append(
            {
                "at_ms": round(row["at"] * 1000),
                "endpoint_template": template,
                "host": str(row.get("host") or template.split("/", 1)[0]),
                "egress": str(row["egress"]),
            }
        )
    dry = DryFixture(path.stem, data, now, traffic, rows_429, loader.sample_rows(traffic))
    run_data_checks(dry, (data.get("expect") or {}).get("data_checks") or [])  # type: ignore[arg-type]
    for index, variant in enumerate(data.get("variants") or []):
        if "data_checks" in (variant.get("expect") or {}):
            raise FixtureError(f"{path.name}: variants[{index}] repeats data_checks (README: not allowed)")
    return dry


async def apply_case_settings(state: LoadedFixture, extra: Mapping[str, Any] | None) -> None:
    """The file's settings merged with a variant's, written and reloaded (README "variants")."""
    merged = {**(state.data.get("settings") or {}), **dict(extra or {})}
    values = validate_settings(merged, where=f"{state.name}: variant settings")
    loader = _Loader(state.name, state.data, state.now, state.dbs, state.clock, state.providers)
    loader.write_settings(values, state.history_times)
    await state.runtime.reload()


async def run_case(name: str, case: str | None = None) -> list[Recommendation]:
    """Run the file's own case (`case` None or equal to the file's case) or one variant; return the result."""
    state = await loaded(name)
    variant: Mapping[str, Any] | None = None
    if case is not None and case != state.data["case"]:
        variant = next((v for v in state.data.get("variants") or [] if str(v["case"]) == case), None)
        if variant is None:
            raise FixtureError(f"{state.name}: no variant {case!r}")
    await apply_case_settings(state, (variant or {}).get("settings"))
    expect = dict((variant or state.data)["expect"])
    expect.pop("data_checks", None)
    outcome = await state.engine.evaluate_rule(state.rule, now=state.now)
    if outcome.skipped == "unknown_rule":
        raise NotImplementedError(f"rule {state.rule} is not implemented yet")
    label = f"{state.name}" + (f"[{case}]" if variant is not None else "")
    await check_expect(state, outcome, expect, label)
    return outcome.recommendations


async def run_fixture(name: str) -> dict[str, list[Recommendation]]:
    """The file's case and every variant, in order. Returns `{case: recommendations}`; raises on the first failure."""
    state = await loaded(name)
    results: dict[str, list[Recommendation]] = {str(state.data["case"]): await run_case(name)}
    for variant in state.data.get("variants") or []:
        results[str(variant["case"])] = await run_case(name, str(variant["case"]))
    return results


def run_sync(coro_fn: Callable[[], Any]) -> Any:
    """Run a harness coroutine from synchronous code (scripts)."""
    return asyncio.run(coro_fn())


__all__ = [
    "FIXTURE_DIR",
    "TEST_KEY",
    "ExpectationFailed",
    "FixtureError",
    "FixtureProviders",
    "LoadedFixture",
    "check",
    "check_expect",
    "fixture_ids",
    "fixture_path",
    "load",
    "loaded",
    "parse_time",
    "read_fixture",
    "run_case",
    "run_data_checks",
    "run_fixture",
]
