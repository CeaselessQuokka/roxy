"""Fixture harness for Check Proxy Health: runs one `roxy.health_fixture/1` file through the real health runner.

What this is
    `load_cases()` reads every file in `tests/fixtures/health` (and its variants) into `Case`s, and
    `run_case(case, ...)` builds a worker context in a temporary state directory, loads the fixture's inputs,
    runs the one check through `HealthRunner.run_checks` (the same per-check path as a real run, with the run
    trigger, the per-check timeout and internal probe priority), reads the stored `health_results` row back, and
    returns everything the test compares with `expect`. `check_constraint` implements the constraint grammar
    shared with `tests/fixtures/insights`.

Why it exists
    The fixtures were written from plan 13.2 before the checks existed (19.10). The harness turns their inputs into
    real state (settings, rule rows, credential metadata, cooldowns, heartbeats, the leader lease, egress usage,
    recorded traffic through `MetricsRecorder`) and fakes only the outside world: Roblox and the public origin
    (answers recorded at `EgressClients.send` and `SystemFacts.origin_fetch`), DNS, TLS, commands, alert
    channels, status files and the address classifier, through the `SystemFacts` seam of `roxy/health/facts.py`.

How it works
    - Every outbound call is answered from the fixture or recorded as unmocked (which fails the test); the
      autouse socket guard of `tests/conftest.py` stops anything that would leave the machine.
    - The fake clock starts at the fixture's `now`; a mocked answer advances it by `latency_ms` before it
      returns, so checks that time themselves with `ctx.clock.monotonic()` measure exactly that.
    - Faults are applied to the real objects: the leak guard's self-test kit gets a matcher that never matches,
      cache.db writes raise or take time on the fake clock, and one rule row is reported as not compiling.

What to read next
    `tests/fixtures/health/README.md` (the format), `tests/health/test_health_fixtures.py` (the test).
"""

from __future__ import annotations

import contextlib
import copy
import ipaddress
import itertools
import json
import math
import os
import re
import secrets
import sqlite3
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.health import checks, probes
from roxy.health.facts import (
    AlertChannels,
    BackupFacts,
    CommandResult,
    DiskFacts,
    DnsAnswer,
    DnsFailure,
    JobFact,
    LagSample,
    OriginAnswer,
    OriginFailure,
    SmtpProbe,
    TlsAnswer,
    TlsFailure,
    VersionFacts,
    WebhookProbe,
    is_global_address,
)

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "health"
FORMAT = "roxy.health_fixture/1"
TOP_KEYS = {"format", "check", "params", "case", "name", "description", "now", "run", "inputs", "expect", "variants"}
INPUT_KEYS = {
    "settings", "tables", "state", "traffic_defaults", "profiles", "traffic", "events", "upstream", "files",
    "systemd", "timedatectl", "dns", "tls", "env", "alerts", "backup", "version", "databases", "faults",
}  # fmt: skip
STATE_KEYS = {"credential", "cooldowns", "workers", "leader", "disk", "egress", "admin_logins", "raw"}
EXPECT_KEYS = {
    "status", "value", "threshold", "critical", "fix_link", "explanation", "calls", "credential_calls",
    "no_calls_to", "data_checks",
}  # fmt: skip
VARIANT_KEYS = {"case", "name", "description", "inputs", "expect"}
FAULTS = {"leak_guard_bypassed", "cache_db_readonly", "cache_rw_latency_ms", "rules_compile_error"}
RESPONSE_KEYS = {
    "status",
    "headers",
    "body",
    "json",
    "latency_ms",
    "error",
    "exit_ip",
    "exit_ip_by_session",
    "expect_request",
}
TABLES_ALLOWED = {
    "rules_endpoint_block", "rules_endpoint_limit", "rules_cache", "rules_user_agent", "rules_header", "rules_routing",
    "upstream_limits", "credential_allowlist", "throttle_tiers", "cache_ignored_params", "ignored_value_headers",
    "ignored_paths", "access_list", "bans",
}  # fmt: skip
SITE_ORIGIN = "https://roxy.test"
TOKEN_PREFIX = (
    "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-"
    "items.|_"
)
DOC_RANGES = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
PHI = 0.6180339887498949


class FixtureError(AssertionError):
    """The fixture file is malformed (a typo must fail loudly instead of testing nothing)."""


# ================================================================================================ loading


@dataclass
class Case:
    """One runnable scenario: a file, or one of its variants (inputs merged, expect replaced)."""

    test_id: str
    path: Path
    check: str
    params: dict[str, str]
    case: str
    name: str
    now: str
    trigger: str
    inputs: dict[str, Any]
    expect: dict[str, Any]

    @property
    def stem(self) -> str:
        return self.path.stem


def _unknown(where: str, found: Iterable[str], allowed: set[str]) -> None:
    extra = sorted(set(found) - allowed)
    if extra:
        raise FixtureError(f"{where}: unknown keys {extra}")


def deep_merge(base: Any, over: Any) -> Any:
    """README: maps merge, lists and scalars replace."""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for key, value in over.items():
            out[key] = deep_merge(base[key], value) if key in base else copy.deepcopy(value)
        return out
    return copy.deepcopy(over)


def validate_document(doc: Mapping[str, Any], path: Path) -> None:
    _unknown(path.name, doc, TOP_KEYS)
    for key in ("format", "check", "case", "name", "description", "now", "inputs", "expect"):
        if key not in doc:
            raise FixtureError(f"{path.name}: missing {key}")
    if doc["format"] != FORMAT:
        raise FixtureError(f"{path.name}: format must be {FORMAT}")
    if checks.CATALOG.get(str(doc["check"])) is None:
        raise FixtureError(f"{path.name}: unknown check {doc['check']}")
    if "<" in str(doc["check"]) and not doc.get("params"):
        raise FixtureError(f"{path.name}: {doc['check']} needs params")
    stem_slug = str(doc["check"]).lower().replace("-", "_").replace("_<host>", "")
    if not path.stem.startswith(stem_slug + "__" + str(doc["case"]).replace("/", "")):
        raise FixtureError(f"{path.name}: file name does not match check and case")
    for document in [doc, *(doc.get("variants") or [])]:
        inputs = document.get("inputs") or {}
        _unknown(f"{path.name} inputs", inputs, INPUT_KEYS)
        _unknown(f"{path.name} state", (inputs.get("state") or {}), STATE_KEYS)
        _unknown(f"{path.name} faults", (inputs.get("faults") or {}), FAULTS)
        _unknown(f"{path.name} tables", (inputs.get("tables") or {}), TABLES_ALLOWED)
        for key, value in (inputs.get("upstream") or {}).items():
            for response in value if isinstance(value, list) else [value]:
                _unknown(f"{path.name} upstream {key}", response, RESPONSE_KEYS)
        if "expect" in document:
            _unknown(f"{path.name} expect", document["expect"], EXPECT_KEYS)
    for variant in doc.get("variants") or []:
        _unknown(f"{path.name} variant", variant, VARIANT_KEYS)
        if variant.get("case") not in ("pass", "warn", "fail", "n/a"):
            raise FixtureError(f"{path.name}: variant case {variant.get('case')!r}")


def load_cases(directory: Path = FIXTURE_DIR) -> list[Case]:
    """Every file and every variant, in file name order."""
    cases: list[Case] = []
    for path in sorted(directory.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        validate_document(doc, path)
        params = {str(k): str(v) for k, v in (doc.get("params") or {}).items()}
        trigger = str((doc.get("run") or {}).get("trigger", "manual"))
        base_inputs = doc.get("inputs") or {}
        cases.append(
            Case(
                path.stem,
                path,
                str(doc["check"]),
                params,
                str(doc["case"]),
                str(doc["name"]),
                str(doc["now"]),
                trigger,
                copy.deepcopy(base_inputs),
                dict(doc["expect"]),
            )
        )
        for variant in doc.get("variants") or []:
            inputs = deep_merge(base_inputs, variant.get("inputs") or {})
            test_id = f"{path.stem}[{variant['case']}-{variant['name']}]"
            cases.append(
                Case(
                    test_id,
                    path,
                    str(doc["check"]),
                    params,
                    str(variant["case"]),
                    str(variant["name"]),
                    str(doc["now"]),
                    trigger,
                    inputs,
                    dict(variant.get("expect") or {}),
                )
            )
    return cases


# ================================================================================================ time grammar

_RELATIVE = re.compile(r"^([+-])(\d+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86_400}


def parse_now(text: str) -> float:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def is_time_text(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value in ("now", "0m") or _RELATIVE.match(value):
        return True
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$", value))


def to_seconds(value: Any, now: float) -> float | None:
    """The time grammar: "now", "-3h", "+12s", ISO times, dates (UTC midnight), raw integers."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise FixtureError(f"boolean where a time was expected: {value!r}")
    if isinstance(value, int | float):
        return float(value)
    text = str(value)
    if text in ("now", "0m"):
        return now
    match = _RELATIVE.match(text)
    if match:
        sign = 1 if match.group(1) == "+" else -1
        return now + sign * int(match.group(2)) * _UNITS[match.group(3)]
    if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
        return datetime.fromisoformat(text).replace(tzinfo=UTC).timestamp()
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FixtureError(f"not a time: {text!r}") from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.timestamp()


def convert_times(value: Any, now: float) -> Any:
    """Time strings inside JSON documents become Unix seconds (README `files`)."""
    if isinstance(value, dict):
        return {k: convert_times(v, now) for k, v in value.items()}
    if isinstance(value, list):
        return [convert_times(v, now) for v in value]
    if is_time_text(value):
        return int(to_seconds(value, now) or 0)
    return value


def http_date(seconds: float) -> str:
    return format_datetime(datetime.fromtimestamp(int(seconds), tz=UTC), usegmt=True)


def systemd_time(seconds: float) -> str:
    return datetime.fromtimestamp(int(seconds), tz=UTC).strftime("%a %Y-%m-%d %H:%M:%S UTC")


# ================================================================================================ constraints

OPERATORS = {"eq", "ne", "lt", "lte", "gt", "gte", "between", "in", "not_in", "contains", "contains_all", "regex",
             "present", "matches_targets", "not_matches_targets"}  # fmt: skip
NUMERIC = {"lt", "lte", "gt", "gte", "between"}
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        match = _NUMBER.search(value)
        return float(match.group(0)) if match else None
    return None


def _equal(actual: Any, expected: Any) -> bool:
    if isinstance(expected, bool | int | float) and not isinstance(expected, str):
        number = _as_number(actual)
        return number is not None and math.isclose(number, float(expected), abs_tol=1e-9)
    return bool(actual == expected)


def check_constraint(actual: Any, constraint: Any, where: str = "value") -> list[str]:
    """The README constraint grammar. Returns the list of problems (empty: the constraint holds)."""
    if constraint is None:
        return [] if actual is None else [f"{where}: expected null, got {actual!r}"]
    if isinstance(constraint, dict) and constraint and set(constraint) <= OPERATORS:
        problems: list[str] = []
        for op, expected in constraint.items():
            if not _operator(op, actual, expected):
                problems.append(f"{where}: {op} {expected!r} does not hold for {actual!r}")
        return problems
    if isinstance(constraint, dict):
        if not isinstance(actual, Mapping):
            return [f"{where}: expected a mapping, got {actual!r}"]
        out: list[str] = []
        for key, value in constraint.items():
            out += check_constraint(actual.get(key), value, f"{where}.{key}")
        return out
    if isinstance(constraint, list):
        return [] if actual == constraint else [f"{where}: expected {constraint!r}, got {actual!r}"]
    return [] if _equal(actual, constraint) else [f"{where}: expected {constraint!r}, got {actual!r}"]


def _operator(op: str, actual: Any, expected: Any) -> bool:
    if op == "present":
        return (actual is not None and actual != "") == bool(expected)
    if op in NUMERIC:
        number = _as_number(actual)
        if number is None:
            return False
        if op == "between":
            low, high = expected
            return float(low) - 1e-9 <= number <= float(high) + 1e-9
        bound = float(expected)
        return {
            "lt": number < bound,
            "lte": number <= bound + 1e-9,
            "gt": number > bound,
            "gte": number >= bound - 1e-9,
        }[op]
    if op == "eq":
        return _equal(actual, expected)
    if op == "ne":
        return not _equal(actual, expected)
    if op == "in":
        return any(_equal(actual, item) for item in expected)
    if op == "not_in":
        return not any(_equal(actual, item) for item in expected)
    if op == "contains":
        if isinstance(actual, str):
            return str(expected) in actual
        return isinstance(actual, list | tuple) and expected in actual
    if op == "contains_all":
        items = [s.strip().lower() for s in actual.split(",")] if isinstance(actual, str) else list(actual or [])
        return all(str(e).lower() in [str(i).lower() for i in items] for e in expected)
    if op == "regex":
        return actual is not None and re.search(str(expected), str(actual)) is not None
    raise FixtureError(f"operator {op} is not used by the health fixtures")


# ================================================================================================ traffic

GENERATOR_FIELDS = {
    "name", "window", "per_minute", "total", "series", "profile", "endpoint_template", "host", "method", "egress",
    "outcome", "reason", "status", "source", "cache_state", "auth_class", "upstream_calls", "latency_ms",
    "queue_wait_ms", "upstream_ms", "bytes", "client_ip", "clients", "place_id", "places", "user_agent",
    "user_agents", "bypass", "error", "request_id", "upstream_status", "upstream_429", "samples", "path", "paths",
}  # fmt: skip
REFUSAL_REASONS = {
    "paused", "banned", "deny_list", "flood", "spam", "throttle_all", "throttle", "place_limit", "user_agent_rule",
    "ignored_path", "unsafe_url", "not_roblox", "host_not_allowed", "auth_smuggling", "header_rule",
    "endpoint_blocked", "endpoint_rule", "body_too_large", "headers_too_large", "url_too_long", "method_not_allowed",
    "challenge", "bot_score",
}  # fmt: skip
SERVED_REASONS = {
    "upstream_ok", "upstream_4xx", "cache_hit", "cache_revalidating", "cache_stale_cooldown", "cache_stale_error",
    "cache_coalesced", "cache_negative", "throttled_cache", "options_local",
}  # fmt: skip


def _distribution(spec: Any, n: int) -> float:
    if isinstance(spec, int | float):
        return float(spec)
    if not isinstance(spec, dict):
        raise FixtureError(f"bad distribution {spec!r}")
    points = sorted((float(str(k)[1:]) / 100.0, float(v)) for k, v in spec.items())
    if points[0][0] > 0:
        points.insert(0, (0.0, points[0][1]))
    if points[-1][0] < 1:
        points.append((1.0, points[-1][1]))
    q = ((n + 1) * PHI) % 1.0
    for (q0, v0), (q1, v1) in itertools.pairwise(points):
        if q0 <= q <= q1:
            value = v0 if q1 == q0 else v0 + (v1 - v0) * (q - q0) / (q1 - q0)
            return round(value, 1)
    return round(points[-1][1], 1)


def _pool(single: Any, pool: Any, n: int) -> Any:
    if pool is not None:
        if isinstance(pool, dict) and "cidr" in pool:
            network = ipaddress.ip_network(str(pool["cidr"]), strict=False)
            count = int(pool["count"])
            hosts = []
            for host in network.hosts():
                hosts.append(str(host))
                if len(hosts) >= count:
                    break
            return hosts[n % len(hosts)]
        items = pool["list"] if isinstance(pool, dict) else pool
        return items[n % len(items)]
    return single


def expand_traffic(inputs: Mapping[str, Any], now: float, stem: str) -> list[dict[str, Any]]:
    """Every OutcomeEvent of the file as a plain dict (plus `x_upstream_429` side output), in record order."""
    defaults = dict(inputs.get("traffic_defaults") or {})
    profiles = dict(inputs.get("profiles") or {})
    events: list[dict[str, Any]] = []
    for order, generator in enumerate(inputs.get("traffic") or []):
        _unknown(f"traffic {generator.get('name')}", generator, GENERATOR_FIELDS)
        fields = dict(defaults)
        names = generator.get("profile")
        for name in [names] if isinstance(names, str) else list(names or []):
            fields.update(profiles[name])
        fields.update(generator)
        start = to_seconds(generator["window"][0], now) or now
        end = to_seconds(generator["window"][1], now) or now
        minutes = round((end - start) / 60)
        if "per_minute" in generator:
            counts = [int(generator["per_minute"])] * minutes
        elif "total" in generator:
            total = int(generator["total"])
            counts = [total // minutes + (1 if i < total % minutes else 0) for i in range(minutes)]
        elif "series" in generator:
            counts = [int(c) for c in generator["series"]]
            if len(counts) != minutes:
                raise FixtureError(f"series of {generator['name']} needs {minutes} entries")
        else:
            raise FixtureError(f"{generator['name']}: needs per_minute, total or series")
        n = 0
        for minute, k in enumerate(counts):
            t0 = int((start + minute * 60) * 1000)
            for j in range(k):
                at_ms = t0 + (2 * j + 1) * 30000 // k
                events.append(_event(fields, generator, at_ms, n, order, stem))
                n += 1
    events.sort(key=lambda e: (e["at_ms"], e["x_order"], e["x_n"]))
    return events


def _event(
    fields: Mapping[str, Any], generator: Mapping[str, Any], at_ms: int, n: int, order: int, stem: str
) -> dict[str, Any]:
    template = str(fields["endpoint_template"])
    egress = str(fields["egress"])
    calls = int(fields.get("upstream_calls", 0 if egress == "none" else 1))
    if (egress == "none") != (calls == 0):
        raise FixtureError(f"{generator['name']}: egress none if and only if upstream_calls 0")
    auth = str(fields.get("auth_class", "anon"))
    if auth == "cred" and egress != "credential":
        raise FixtureError(f"{generator['name']}: auth_class cred needs egress credential")
    outcome, reason = str(fields["outcome"]), str(fields["reason"])
    if (reason in REFUSAL_REASONS) != (outcome == "refused"):
        raise FixtureError(f"{generator['name']}: reason {reason} does not fit outcome {outcome}")
    if reason in SERVED_REASONS and outcome not in ("served_upstream", "served_cache"):
        raise FixtureError(f"{generator['name']}: served reason with outcome {outcome}")
    latency = _distribution(fields.get("latency_ms", 0), n)
    queue_wait = _distribution(fields.get("queue_wait_ms", 0), n)
    upstream_ms = (
        _distribution(fields["upstream_ms"], n)
        if "upstream_ms" in fields
        else (max(0.0, latency - queue_wait) if calls else 0.0)
    )
    size = dict(fields.get("bytes") or {})
    source = str(fields["source"])
    status = int(fields["status"])
    return {
        "at_ms": at_ms,
        "request_id": str(fields.get("request_id") or f"{stem}-{generator['name']}-{n}"),
        "endpoint_template": template,
        "host": str(fields.get("host") or template.split("/", 1)[0]),
        "method": str(fields.get("method", "GET")),
        "egress": egress,
        "outcome": outcome,
        "reason": reason,
        "status": status,
        "source": source,
        "cache_state": str(fields["cache_state"]),
        "auth_class": auth,
        "caller_bytes_in": int(size.get("caller_in", 0)),
        "caller_bytes_out": int(size.get("caller_out", 0)),
        "upstream_calls": calls,
        "upstream_bytes_in": int(size.get("upstream_in", 0)) * calls,
        "upstream_bytes_out": int(size.get("upstream_out", 0)) * calls,
        "latency_ms": latency,
        "queue_wait_ms": queue_wait,
        "upstream_ms": upstream_ms,
        "client_ip": str(_pool(fields.get("client_ip"), fields.get("clients"), n)),
        "place_id": _pool(fields.get("place_id"), fields.get("places"), n),
        "user_agent": str(_pool(fields.get("user_agent", ""), fields.get("user_agents"), n) or ""),
        "bypass": bool(fields.get("bypass", False)),
        "error": bool(fields.get("error", False)),
        "upstream_status": fields.get("upstream_status", status if source == "relay" else None),
        "path": str(_pool(fields.get("path", ""), fields.get("paths"), n) or ""),
        "x_upstream_429": fields.get("upstream_429"),
        "x_order": order,
        "x_n": n,
    }


def outcome_event(item: Mapping[str, Any]) -> Any:
    from roxy.metrics.recorder import OutcomeEvent

    return OutcomeEvent(
        at_ms=int(item["at_ms"]),
        request_id=str(item["request_id"]),
        endpoint_template=str(item["endpoint_template"]),
        host=str(item["host"]),
        method=str(item["method"]),
        egress=Egress(item["egress"]),
        outcome=Outcome(item["outcome"]),
        reason=ReasonCode(item["reason"]),
        status=int(item["status"]),
        source=Source(item["source"]),
        cache_state=CacheState(item["cache_state"]),
        auth_class=AuthClass(item["auth_class"]),
        caller_bytes_in=int(item["caller_bytes_in"]),
        caller_bytes_out=int(item["caller_bytes_out"]),
        upstream_calls=int(item["upstream_calls"]),
        upstream_bytes_in=int(item["upstream_bytes_in"]),
        upstream_bytes_out=int(item["upstream_bytes_out"]),
        latency_ms=float(item["latency_ms"]),
        queue_wait_ms=float(item["queue_wait_ms"]),
        upstream_ms=float(item["upstream_ms"]),
        client_ip=str(item["client_ip"]),
        place_id=None if item["place_id"] is None else str(item["place_id"]),
        user_agent=str(item["user_agent"]),
        bypass=bool(item["bypass"]),
        error=bool(item["error"]),
        path=str(item["path"]),
        upstream_status=item["upstream_status"],
    )


def data_check_problems(
    events: Sequence[Mapping[str, Any]], checks_list: Sequence[Mapping[str, Any]], now: float
) -> list[str]:
    """`expect.data_checks` against the expanded events (the fixture proves its own numbers)."""
    problems: list[str] = []
    for item in checks_list:
        start = (to_seconds(item["window"][0], now) or now) * 1000
        end = (to_seconds(item["window"][1], now) or now) * 1000
        where = dict(item.get("where") or {})
        chosen = [
            e for e in events if start <= e["at_ms"] < end and all(str(e.get(k)) == str(v) for k, v in where.items())
        ]
        measures: dict[str, Any] = {
            "requests": len(chosen),
            "upstream_calls": sum(e["upstream_calls"] for e in chosen),
            "served_upstream": sum(1 for e in chosen if e["outcome"] == "served_upstream"),
            "served_cache": sum(1 for e in chosen if e["outcome"] == "served_cache"),
            "refused": sum(1 for e in chosen if e["outcome"] == "refused"),
            "failed": sum(1 for e in chosen if e["outcome"] == "failed"),
            "stale_after_failure": sum(1 for e in chosen if e["reason"] == "cache_stale_error"),
            "errors": sum(1 for e in chosen if e["error"]),
        }
        measures["avoided_calls"] = measures["requests"] - measures["upstream_calls"]
        measures["roblox_429"] = sum(
            1
            for e in events
            if start <= e["at_ms"] < end
            and e["x_upstream_429"]
            and all(str(e.get(k)) == str(v) for k, v in where.items() if k in ("endpoint_template", "host"))
        )
        reasons: dict[str, int] = {}
        for e in chosen:
            reasons[e["reason"]] = reasons.get(e["reason"], 0) + 1
        for key, expected in item.items():
            if key in ("window", "where"):
                continue
            if key == "by_reason":
                for reason, count in expected.items():
                    if reasons.get(reason, 0) != count:
                        problems.append(
                            f"data_check {item['window']}: by_reason {reason} {reasons.get(reason, 0)} != {count}"
                        )
                continue
            problems += check_constraint(measures[key], expected, f"data_check {item['window']} {key}")
    return problems


# ================================================================================================ the outside world


@dataclass
class Call:
    key: str
    egress: str
    method: str
    url: str
    session_id: str | None


@dataclass
class Recorder:
    """Every outbound call the check made, the unmocked ones, and `expect_request` violations."""

    calls: list[Call] = field(default_factory=list)
    unmocked: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)


def _segments_match(pattern: list[str], actual: list[str]) -> bool:
    if not pattern:
        return not actual
    head = pattern[0]
    if head == "**":
        return any(_segments_match(pattern[1:], actual[i:]) for i in range(1, len(actual) + 1))
    if not actual:
        return False
    return (head == "*" or head == actual[0]) and _segments_match(pattern[1:], actual[1:])


def path_query_match(pattern: str, path: str, query: str) -> bool:
    """README URL key rules: `*` one segment, `**` one or more, query as a set, trailing `?*` any query."""
    pattern_path, _, pattern_query = pattern.partition("?")
    if not _segments_match(pattern_path.strip("/").split("/") if pattern_path.strip("/") else [],
                           path.strip("/").split("/") if path.strip("/") else []):  # fmt: skip
        return False
    if pattern_query == "*":
        return True
    wanted = sorted(httpx.QueryParams(pattern_query).multi_items())
    return wanted == sorted(httpx.QueryParams(query).multi_items())


def _specificity(key: str) -> tuple[int, int]:
    return (key.count("*"), -len(key))


class MockResponses:
    """The fixture's `upstream` map: answers in order (the last repeats), per key."""

    def __init__(self, upstream: Mapping[str, Any], clock: FakeClock, now: float, recorder: Recorder) -> None:
        self.table = {k: (v if isinstance(v, list) else [v]) for k, v in upstream.items()}
        self.served: dict[str, int] = {}
        self.clock = clock
        self.now = now
        self.recorder = recorder
        self.sessions: list[str] = []

    def next(self, key: str) -> dict[str, Any]:
        index = self.served.get(key, 0)
        self.served[key] = index + 1
        items = self.table[key]
        return dict(items[min(index, len(items) - 1)])

    def key_for_roblox(self, method: str, url: str) -> str | None:
        parts = httpx.URL(url)
        host = parts.host
        candidates: list[str] = []
        for key in self.table:
            if key.startswith("probe:"):
                probe = probes.probe_for(key[len("probe:") :])
                if probe.host == host and probe.method == method and _same_url(probe.url, url):
                    return key
            elif key.startswith("https://"):
                target = httpx.URL(key.replace("?*", ""))
                if target.host == host:
                    query = key.split("?", 1)[1] if "?" in key else ""
                    pattern = target.path + ("?" + query if query else "")
                    if path_query_match(pattern, parts.path, parts.query.decode()):
                        candidates.append(key)
        if candidates:
            return sorted(candidates, key=_specificity)[0]
        if "any_roblox" in self.table:
            return "any_roblox"
        return None

    def key_for_origin(self, path_and_query: str) -> str | None:
        path, _, query = path_and_query.partition("?")
        found = [
            key
            for key in self.table
            if key.startswith("origin:") and path_query_match(key[len("origin:") :], path, query)
        ]
        return sorted(found, key=_specificity)[0] if found else None

    def check_request(
        self, key: str, response: Mapping[str, Any], egress: str, method: str, headers: Mapping[str, str]
    ) -> None:
        wanted = response.get("expect_request") or {}
        lowered = {k.lower() for k in headers}
        if "via" in wanted and wanted["via"] != egress:
            self.recorder.violations.append(f"{key}: via {egress}, expected {wanted['via']}")
        if "method" in wanted and str(wanted["method"]).upper() != method.upper():
            self.recorder.violations.append(f"{key}: method {method}, expected {wanted['method']}")
        for name in wanted.get("headers_present") or []:
            if name.lower() not in lowered:
                self.recorder.violations.append(f"{key}: header {name} missing")
        for name in wanted.get("headers_absent") or []:
            if name.lower() in lowered:
                self.recorder.violations.append(f"{key}: header {name} present")

    def advance(self, response: Mapping[str, Any]) -> None:
        latency = float(response.get("latency_ms") or 0)
        if latency > 0:
            self.clock.advance(latency / 1000.0)

    def render(
        self, response: Mapping[str, Any], *, session_id: str | None = None
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        headers: list[tuple[str, str]] = []
        for name, value in (response.get("headers") or {}).items():
            if str(name).lower() == "date" and is_time_text(value):
                headers.append((str(name), http_date(to_seconds(value, self.now) or self.now)))
            else:
                headers.append((str(name), str(value)))
        if "json" in response:
            body = json.dumps(response["json"]).encode()
            if not any(k.lower() == "content-type" for k, _ in headers):
                headers.append(("content-type", "application/json"))
        elif "exit_ip" in response or "exit_ip_by_session" in response:
            if "exit_ip_by_session" in response:
                if session_id is None:
                    raise AssertionError("ip_echo request without a session id")
                if session_id not in self.sessions:
                    self.sessions.append(session_id)
                addresses = list(response["exit_ip_by_session"])
                index = self.sessions.index(session_id)
                if index >= len(addresses):
                    raise AssertionError("more distinct sessions than exit_ip_by_session entries")
                ip = addresses[index]
            else:
                ip = response["exit_ip"]
            body = json.dumps({"ip": ip}).encode()
            headers.append(("content-type", "application/json"))
        else:
            body = str(response.get("body", "")).encode()
        return int(response.get("status", 200)), headers, body


def _same_url(a: str, b: str) -> bool:
    x, y = httpx.URL(a), httpx.URL(b)
    return x.host == y.host and x.path == y.path and sorted(x.params.multi_items()) == sorted(y.params.multi_items())


class FakeSend:
    """Stands in for `EgressClients.send`: answers from the fixture, records the egress (`via`) of each call."""

    def __init__(self, egress: Any, mocks: MockResponses, recorder: Recorder) -> None:
        self.egress = egress
        self.mocks = mocks
        self.recorder = recorder

    async def __call__(self, egress: Egress, out: Any) -> Any:
        from roxy.egress.errors import CredentialUnavailable, EgressDisabled, UpstreamConnectError, UpstreamTimeout
        from roxy.egress.models import CREDENTIAL_PROBE_PURPOSES, PURPOSE_EXIT_IP_PROBE, EgressResponse

        if egress is Egress.CREDENTIAL:
            manager = self.egress.credential
            await manager.refresh()
            usable = manager.probe_allowed() if out.purpose in CREDENTIAL_PROBE_PURPOSES else manager.available()
            if not usable:
                raise CredentialUnavailable(manager.status().status)
        else:
            usable, why = self.egress.is_enabled(egress, purpose=out.purpose)
            if not usable:
                raise EgressDisabled(egress, why)
        method = str(out.method).upper()
        if egress is Egress.ROTATOR and out.purpose == PURPOSE_EXIT_IP_PROBE:
            key = "ip_echo" if "ip_echo" in self.mocks.table else None
        else:
            key = self.mocks.key_for_roblox(method, str(out.url))
        if key is None:
            self.recorder.unmocked.append(f"{egress.value} {method} {out.url}")
            raise UpstreamConnectError(egress, "unmocked request (fixture)")
        self.recorder.calls.append(Call(key, egress.value, method, str(out.url), out.session_id))
        response = self.mocks.next(key)
        self.mocks.check_request(key, response, egress.value, method, out.headers)
        self.mocks.advance(response)
        error = response.get("error")
        if error == "timeout":
            raise UpstreamTimeout(egress, "ReadTimeout")
        if error in ("connect", "tls", "reset"):
            raise UpstreamConnectError(
                egress, {"connect": "ConnectError", "tls": "ConnectError ssl", "reset": "RemoteProtocolError"}[error]
            )
        status, headers, body = self.mocks.render(response, session_id=out.session_id)
        return EgressResponse(
            status=status,
            headers=httpx.Headers(headers),
            body=body,
            elapsed_ms=float(response.get("latency_ms") or 0),
            bytes_out=200,
            bytes_in=len(body) + 200,
            egress=egress,
            session_id=out.session_id,
            http_version="HTTP/2",
            url=str(out.url),
        )


class FixtureFacts:
    """The `SystemFacts` the fixture describes (see the module docstring); anything unmocked is recorded."""

    def __init__(
        self, inputs: Mapping[str, Any], *, now: float, state_dir: Path, mocks: MockResponses, recorder: Recorder
    ) -> None:
        self.inputs = inputs
        self.now = now
        self.state_dir = state_dir
        self.mocks = mocks
        self.recorder = recorder
        self.pid = 999_999
        self.compile_fault: tuple[str, str] | None = None
        fault = (self.inputs.get("faults") or {}).get("rules_compile_error")
        if fault:
            self.compile_fault = (str(fault["table"]), str(fault["id"]))
        for row in (self.inputs.get("state") or {}).get("workers") or []:
            if row.get("x_self"):
                self.pid = int(row["pid"])

    def environ(self) -> Mapping[str, str]:
        env = self.inputs.get("env") or {}
        return {str(k): str(v) for k, v in env.items() if not str(k).startswith("ROXY_") and k != "clients_trust_env"}

    def self_pid(self) -> int:
        return self.pid

    def is_public_address(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        if any(ip in network for network in DOC_RANGES if network.version == ip.version):
            return True  # documentation ranges count as public in these tests (README)
        return is_global_address(address)

    def perms_path(self) -> Path:
        return self.state_dir / "audit" / "perms.json"

    def rule_compiles(self, table: str, row_id: object, pattern: str, kind: str, *, exact: bool = False) -> bool:
        if self.compile_fault is not None and self.compile_fault == (table, str(row_id)):
            return False
        from roxy.rules import match

        if kind == "text_regex":
            return match.compile_like_re(pattern) is not None
        return match.compile_pattern(pattern, kind or "glob", exact=exact).valid

    async def resolve(self, host: str, timeout_s: float) -> DnsAnswer:
        answers = self.inputs.get("dns") or {}
        if host not in answers:
            self.recorder.unmocked.append(f"dns {host}")
            raise DnsFailure("error", "unmocked")
        item = answers[host]
        if "error" in item:
            raise DnsFailure(str(item["error"]))
        return DnsAnswer(tuple(str(a) for a in item.get("answers") or ()), float(item.get("latency_ms") or 0))

    async def tls_probe(self, host: str, port: int, timeout_s: float) -> TlsAnswer:
        answers = self.inputs.get("tls") or {}
        key = "origin" if host == httpx.URL(SITE_ORIGIN).host else host
        if key not in answers:
            self.recorder.unmocked.append(f"tls {key}")
            raise TlsFailure("error", "unmocked")
        item = answers[key]
        if "error" in item:
            raise TlsFailure(str(item["error"]))
        return TlsAnswer(float(item["days_left"]), float(item.get("handshake_ms") or 0))

    async def run_command(self, argv: Sequence[str], timeout_s: float) -> CommandResult:
        tool = argv[0]
        if tool == "systemctl":
            spec = self.inputs.get("systemd")
            if spec is None:
                self.recorder.unmocked.append("systemctl")
                return CommandResult(127, "", "unmocked")
            if "error" in spec:
                return CommandResult(int(spec["error"].get("returncode", 1)), "", str(spec["error"].get("stderr", "")))
            units = [a for a in argv[2:] if a.startswith("roxy@")]
            blocks = []
            for unit in units:
                props = spec["show"].get(unit, {})
                lines = []
                for key, value in props.items():
                    if key == "ExecMainStartTimestamp" and is_time_text(value):
                        value = systemd_time(to_seconds(value, self.now) or self.now)
                    lines.append(f"{key}={value}")
                blocks.append("\n".join(lines))
            return CommandResult(0, "\n\n".join(blocks) + "\n", "")
        if tool == "timedatectl":
            spec = self.inputs.get("timedatectl")
            if spec is None:
                self.recorder.unmocked.append("timedatectl")
                return CommandResult(127, "", "unmocked")
            if "error" in spec:
                return CommandResult(int(spec["error"].get("returncode", 1)), "", str(spec["error"].get("stderr", "")))
            return CommandResult(0, "".join(f"{k}={v}\n" for k, v in spec["show"].items()), "")
        self.recorder.unmocked.append(f"command {tool}")
        return CommandResult(127, "", "unmocked")

    async def origin_fetch(self, path: str, timeout_s: float) -> OriginAnswer:
        key = self.mocks.key_for_origin(path)
        if key is None:
            self.recorder.unmocked.append(f"origin {path}")
            raise OriginFailure("connect", "unmocked")
        self.recorder.calls.append(Call(key, "origin", "GET", SITE_ORIGIN + path, None))
        response = self.mocks.next(key)
        started = self.mocks.clock.monotonic()
        self.mocks.advance(response)
        error = response.get("error")
        if error:
            raise OriginFailure(str(error))
        status, headers, body = self.mocks.render(response)
        lowered = {k.lower(): v for k, v in headers}
        return OriginAnswer(status, lowered, body, (self.mocks.clock.monotonic() - started) * 1000)

    async def alert_channels(self, *, webhook_enabled: bool, timeout_s: float) -> AlertChannels:
        spec = self.inputs.get("alerts")
        if spec is None:
            self.recorder.unmocked.append("alerts")
            return AlertChannels(None, ())
        smtp = spec.get("smtp")
        email = None if smtp is None else SmtpProbe(str(smtp["connect"]), str(smtp["login"]), str(smtp["noop"]))
        hooks: list[WebhookProbe] = []
        if webhook_enabled:
            for hook in spec.get("webhooks") or []:
                provider = str(hook.get("provider", "other"))
                status = hook.get("get_status")
                hooks.append(
                    WebhookProbe(
                        provider, testable=provider == "discord", status=None if status is None else int(status)
                    )
                )
        return AlertChannels(email, tuple(hooks))

    async def backup_status(self) -> BackupFacts:
        spec = self.inputs.get("backup")
        if spec is None:
            self.recorder.unmocked.append("backup")
            return BackupFacts(known=False)
        last = spec.get("last_backup_at")
        return BackupFacts(
            known=True,
            last_success_at=None if last is None else to_seconds(last, self.now),
            restore_test=str(spec.get("restore_test", "never")),
        )

    async def version_facts(self) -> VersionFacts:
        spec = self.inputs.get("version")
        if spec is None:
            self.recorder.unmocked.append("version")
            return VersionFacts(None, None)
        advisories = spec.get("advisories")
        return VersionFacts(
            str(spec.get("deployed_sha") or "") or None, None if advisories is None else int(advisories)
        )

    async def disk_usage(self) -> DiskFacts:
        disk = (self.inputs.get("state") or {}).get("disk")
        if disk is None:
            self.recorder.unmocked.append("disk")
            return DiskFacts(0, 0, {})
        files = {
            str(name): (int(v.get("bytes", 0)), int(v.get("wal_bytes", 0)))
            for name, v in (disk.get("files") or {}).items()
        }
        return DiskFacts(int(disk.get("total_bytes", 0)), int(disk.get("free_bytes", 0)), files)

    async def quick_check(self, db_name: str) -> list[str]:
        spec = (self.inputs.get("databases") or {}).get("quick_check")
        if spec is None or db_name not in spec:
            self.recorder.unmocked.append(f"quick_check {db_name}")
            return []
        text = str(spec[db_name])
        return [] if text == "ok" else [text]

    async def leader_jobs(self) -> list[JobFact] | None:
        leader = (self.inputs.get("state") or {}).get("leader") or {}
        if "x_jobs" not in leader:
            return None
        return [
            JobFact(
                name=str(job["name"]),
                interval_s=float(job["interval_s"]),
                last_started_at=to_seconds(job.get("last_started_at"), self.now),
                last_finished_at=to_seconds(job.get("last_finished_at"), self.now),
                last_ok=job.get("last_ok"),
            )
            for job in leader["x_jobs"] or []
        ]

    async def loop_lag(self, window_s: float) -> list[LagSample]:
        samples: list[LagSample] = []
        start = self.now - window_s
        for row in (self.inputs.get("state") or {}).get("workers") or []:
            if (
                to_seconds(row.get("last_seen"), self.now) is not None
                and self.now - (to_seconds(row["last_seen"], self.now) or 0) > 20
            ):
                continue
            values = []
            for stretch in row.get("history") or []:
                lo = to_seconds(stretch["window"][0], self.now) or self.now
                hi = to_seconds(stretch["window"][1], self.now) or self.now
                if hi > start and lo < self.now + 1:
                    values.append(float(stretch["loop_lag_ms_p99"]))
            if not values and row.get("loop_lag_ms_p99") is not None:
                values.append(float(row["loop_lag_ms_p99"]))
            if values:
                samples.append(LagSample(str(row.get("worker_id") or row["pid"]), max(values)))
        return samples


# ================================================================================================ building state


def fake_secrets(*, with_credential: bool) -> dict[str, str]:
    values = {
        "roblox_credential": TOKEN_PREFIX + "FAKETESTCREDENTIAL" + secrets.token_hex(160).upper(),
        "rotator_url": f"http://fakeuser:fake{secrets.token_hex(8)}@127.0.0.1:9",
        "smtp_password": "fake-" + secrets.token_hex(8),
        "alert_emails": "owner@example.invalid",
        "alert_webhook_url": f"http://127.0.0.1:9/fake-webhook/{secrets.token_hex(8)}",
        "credential_encryption_key": secrets.token_hex(32),
        "totp_encryption_key": secrets.token_hex(32),
        "ip_hash_key": secrets.token_hex(32),
    }
    if not with_credential:
        values.pop("roblox_credential")
    return values


def write_credentials(directory: Path, values: Mapping[str, str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in values.items():
        path = directory / name
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
    directory.chmod(0o700)


def base_environment(state_dir: Path, credentials_dir: Path) -> dict[str, str]:
    return {
        "ROXY_ENV": "development",
        "ROXY_AUTO_MIGRATE": "1",
        "ROXY_STATE_DIR": str(state_dir),
        "ROXY_CONTROL_DB": str(state_dir / "control.db"),
        "ROXY_HOT_DB": str(state_dir / "hot.db"),
        "ROXY_METRICS_DB": str(state_dir / "metrics.db"),
        "ROXY_CACHE_DB": str(state_dir / "cache.db"),
        "ROXY_COLOR": "dev",
        "ROXY_WORKERS": "1",
        "ROXY_LOG_LEVEL": "info",
        "ROXY_MAX_REQUESTS": "20000",
        "ROXY_BIND": "127.0.0.1:0",
        "ROXY_INTERNAL_SOCKET": str(state_dir / "internal.sock"),
        "ROXY_TRUSTED_PROXY_HOPS": "1",
        "ROXY_TRUSTED_PROXY_CIDRS": "127.0.0.1/32,::1/128",
        "ROXY_SITE_ORIGIN": SITE_ORIGIN,
        "ROXY_ROTATOR_IP_ECHO_URL": "https://ipecho.test/ip",
        "CREDENTIALS_DIRECTORY": str(credentials_dir),
    }


def _columns(conn: sqlite3.Connection, table: str) -> dict[str, tuple[bool, Any]]:
    return {str(r[1]): (bool(r[3]), r[4]) for r in conn.execute(f'PRAGMA table_info("{table}")')}


def insert_rows(conn: sqlite3.Connection, table: str, rows: Sequence[Mapping[str, Any]], now: float) -> None:
    """README `tables` filling rules: SQL defaults, `now - 1d` for `*_at`, `fixture` for `*_by`, next id."""
    columns = _columns(conn, table)
    if not columns:
        raise FixtureError(f"no table {table}")
    next_id = (
        int(conn.execute(f'SELECT coalesce(max(rowid), 0) FROM "{table}"').fetchone()[0]) + 1 if "id" in columns else 0
    )
    for row in rows:
        data = {k: v for k, v in row.items() if not str(k).startswith("x_")}
        _unknown(f"tables {table}", data, set(columns))
        for name, (notnull, default) in columns.items():
            if name in data:
                continue
            if notnull and default is None:
                if name.endswith("_at"):
                    data[name] = int(now - 86_400)
                elif name.endswith("_by"):
                    data[name] = "fixture"
                elif name == "id":
                    data[name] = next_id
                    next_id += 1
        for name in list(data):
            if (name.endswith("_at") or name == "expires_at") and data[name] is not None:
                data[name] = int(to_seconds(data[name], now) or 0)
        names = ", ".join(f'"{n}"' for n in data)
        marks = ", ".join("?" for _ in data)
        conn.execute(f'INSERT INTO "{table}" ({names}) VALUES ({marks})', tuple(data.values()))


@dataclass
class CaseOutcome:
    """What a case produced: the stored row, the calls, and every problem found on the way."""

    row: dict[str, Any] | None
    recorder: Recorder
    problems: list[str]
    run_id: int | None = None
    result: Any = None


@dataclass
class Built:
    """A worker context built from fixture inputs, with its fakes (yielded by `fixture_context`)."""

    ctx: Any
    facts: FixtureFacts
    recorder: Recorder
    mocks: MockResponses
    clock: FakeClock
    now: float
    events: list[dict[str, Any]]
    state_dir: Path


async def run_case(case: Case, tmp_path: Path, monkeypatch: Any) -> CaseOutcome:
    """Build the state, run the one check through the runner, and read the stored result (see the docstring)."""
    from roxy.health.runner import HealthRunner, default_options

    async with fixture_context(case.inputs, case.now, tmp_path, monkeypatch, stem=case.stem) as built:
        problems = data_check_problems(built.events, case.expect.get("data_checks") or [], built.now)
        ctx = built.ctx
        runner = HealthRunner(ctx, facts=built.facts)
        found = checks.spec_for(checks.CATALOG[case.check].instance_id(case.params))
        assert found is not None
        spec, params = found
        options = default_options(ctx, case.trigger)
        run_id = await runner.run_checks([(spec, params)], trigger=case.trigger, actor="fixture", options=options)
        check_id = spec.instance_id(params)
        row = ctx.dbs.metrics.read_sync(
            lambda conn: conn.execute(
                "SELECT * FROM health_results WHERE run_id = ? AND check_id = ?", (run_id, check_id)
            ).fetchone()
        )
        stored = dict(row) if row is not None else None
        return CaseOutcome(stored, built.recorder, problems, run_id)


@contextlib.asynccontextmanager
async def fixture_context(
    inputs: Mapping[str, Any], now_text: str, tmp_path: Path, monkeypatch: Any, *, stem: str = "fixture"
) -> AsyncIterator[Built]:
    """A worker context with the fixture's state loaded and every outside call faked (see the module docstring)."""
    from roxy.config.env import EnvSettings
    from roxy.config.runtime import bump_config_version, load_runtime_settings
    from roxy.core.redact import SecretRegistry
    from roxy.core.tasks import TaskSupervisor
    from roxy.egress.clients import EgressClients
    from roxy.lifespan import AppContext
    from roxy.metrics.recorder import build_recorder
    from roxy.rules.store import load_rules_store
    from roxy.storage.db import open_databases
    from roxy.storage.migrate import migrate_all

    state = dict(inputs.get("state") or {})
    now = parse_now(now_text)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o750)
    credentials_dir = tmp_path / "credentials"
    credential = state.get("credential") or {}
    write_credentials(credentials_dir, fake_secrets(with_credential=credential.get("present", True) is not False))
    for name in list(os.environ):
        if name.startswith("ROXY_") or name == "CREDENTIALS_DIRECTORY":
            monkeypatch.delenv(name, raising=False)
    for name, value in base_environment(state_dir, credentials_dir).items():
        monkeypatch.setenv(name, value)
    for name, value in (inputs.get("env") or {}).items():
        if str(name).startswith("ROXY_"):
            monkeypatch.setenv(str(name), str(value))
    SecretRegistry.clear()
    env = EnvSettings()
    clock = FakeClock(now)
    dbs = open_databases(env)
    migrate_all(dbs, contract=True)
    recorder_obj: Recorder = Recorder()
    mocks = MockResponses(inputs.get("upstream") or {}, clock, now, recorder_obj)
    tasks = TaskSupervisor(clock=clock)
    egress: Any = None
    try:
        _write_settings(dbs, inputs, now)
        if inputs.get("tables"):
            dbs.control.write_sync(lambda conn: _write_tables(conn, inputs["tables"], now))
        dbs.control.write_sync(lambda conn: bump_config_version(conn, int(now)))
        settings = await load_runtime_settings(dbs, clock)
        rules = await load_rules_store(dbs, clock)
        release = str((inputs.get("version") or {}).get("running_sha") or "3f9c2a1")
        ctx = AppContext(
            env=env,
            clock=clock,
            dbs=dbs,
            settings=settings,
            rules=rules,
            worker_id="roxy-test:999999:fixture0",
            color=env.color,
            started_at=now - 3600,
            tasks=tasks,
            release=release,
        )
        from roxy.core.iphash import load_ip_hash_key

        ctx.ip_hash_key = load_ip_hash_key(credentials_dir)
        ctx.recorder = build_recorder(ctx)
        egress = EgressClients(
            env=env,
            settings=settings,
            dbs=dbs,
            clock=clock,
            worker_id=ctx.worker_id,
            recorder=lambda: ctx.recorder,
            environ={},
            socket_metering=False,
        )
        await egress.start()
        ctx.egress = egress
        from roxy.cache.service import CacheService
        from roxy.upstream.service import UpstreamService

        ctx.upstream = UpstreamService(ctx)
        ctx.cache = CacheService.from_context(ctx)
        await ctx.cache.store.sync_generation()
        await _write_state(ctx, state, now)
        events = expand_traffic(inputs, now, stem)
        await _record_traffic(ctx, events, now, clock)
        await egress.refresh()
        await settings.reload()
        await rules.reload()
        _write_files(inputs.get("files") or {}, state_dir, tmp_path, now)
        _apply_faults(ctx, inputs.get("faults") or {}, clock, inputs)
        egress.send = FakeSend(egress, mocks, recorder_obj)
        if (inputs.get("env") or {}).get("clients_trust_env"):
            _make_clients_trust_env(egress)
        facts = FixtureFacts(inputs, now=now, state_dir=state_dir, mocks=mocks, recorder=recorder_obj)
        clock.set(now)
        yield Built(ctx, facts, recorder_obj, mocks, clock, now, events, state_dir)
    finally:
        if egress is not None:
            with contextlib.suppress(Exception):
                await egress.aclose()
        with contextlib.suppress(Exception):
            await tasks.stop(drain_timeout_s=1.0)
        dbs.close_all_sync()
        SecretRegistry.clear()


def _write_settings(dbs: Any, inputs: Mapping[str, Any], now: float) -> None:
    from roxy.config import catalog

    values: dict[str, Any] = {}
    for key, raw in (inputs.get("settings") or {}).items():
        if key not in catalog.CATALOG:
            raise FixtureError(f"unknown setting {key}")
        values[key] = catalog.validate_value(key, raw)
    if values:
        merged = {**catalog.DEFAULTS, **values}
        issues = catalog.validate_cross(merged)
        if issues:
            raise FixtureError(f"settings break cross rules: {[getattr(i, 'message', i) for i in issues]}")
    raw_rows = ((((inputs.get("state") or {}).get("raw") or {}).get("control") or {}).get("settings")) or []
    for row in raw_rows:
        if row["key"] in values:
            raise FixtureError(f"{row['key']} is both a setting and a raw row")

    def write(conn: sqlite3.Connection) -> None:
        for key, value in values.items():
            conn.execute(
                "INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, 'fixture')",
                (key, json.dumps(value), int(now - 86_400)),
            )
        for row in raw_rows:
            updated = int(to_seconds(row.get("updated_at", "-1d"), now) or now)
            conn.execute(
                "INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                (str(row["key"]), str(row["value_json"]), updated, str(row.get("updated_by", "fixture"))),
            )

    dbs.control.write_sync(write)


def _write_tables(conn: sqlite3.Connection, tables: Mapping[str, Any], now: float) -> None:
    for table, rows in tables.items():
        insert_rows(conn, table, rows, now)


async def _write_state(ctx: Any, state: Mapping[str, Any], now: float) -> None:
    dbs = ctx.dbs
    credential = state.get("credential")
    if credential and credential.get("present", True) is not False:
        manager = ctx.egress.credential
        account = credential.get("account_id")
        probes_list = credential.get("probes") or []
        last_probe = probes_list[-1] if probes_list else None

        def write_meta(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE credential_meta SET status = ?, status_at = ?, set_at = ?, account_id_fingerprint = ?, "
                "last_probe_at = ?, last_probe_result = ? WHERE id = 1",
                (
                    str(credential.get("status", "unknown")),
                    int(to_seconds(credential.get("status_at", "-1d"), now) or now),
                    int(to_seconds(credential.get("set_at", "-1d"), now) or now),
                    None if account is None else manager.fingerprint_of(str(account)),
                    None if last_probe is None else int(to_seconds(last_probe["at"], now) or now),
                    None
                    if last_probe is None
                    else json.dumps({"result": last_probe.get("result"), "kind": last_probe.get("kind")}),
                ),
            )

        dbs.control.write_sync(write_meta)
    cooldowns = state.get("cooldowns") or []
    if cooldowns:

        def write_cooldowns(conn: sqlite3.Connection) -> None:
            for row in cooldowns:
                until_ms = int((to_seconds(row["until"], now) or now) * 1000)
                set_at = int(to_seconds(row.get("set_at", "now"), now) or now)
                conn.execute(
                    "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, ?, ?, ?)",
                    (str(row["key"]), until_ms, str(row.get("source", "default")), set_at, int(row.get("hits", 0))),
                )

        dbs.hot.write_sync(write_cooldowns)
    workers = state.get("workers") or []
    if workers:

        def write_workers(conn: sqlite3.Connection) -> None:
            for row in workers:
                data = {k: v for k, v in row.items() if not k.startswith("x_") and k != "history"}
                for name in ("started_at", "last_seen"):
                    if name in data:
                        data[name] = int(to_seconds(data[name], now) or now)
                names = ", ".join(data)
                conn.execute(
                    f"INSERT INTO worker_heartbeat ({names}) VALUES ({', '.join('?' for _ in data)})",
                    tuple(data.values()),
                )

        dbs.metrics.write_sync(write_workers)
    leader = state.get("leader")
    if leader:

        def write_leader(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO lease (name, holder, expires_ms, epoch) VALUES ('leader', ?, ?, ?)",
                (
                    str(leader["holder"]),
                    int((to_seconds(leader["expires"], now) or now) * 1000),
                    int(leader.get("epoch", 1)),
                ),
            )

        dbs.hot.write_sync(write_leader)
    usage = ((state.get("egress") or {}).get("usage")) or []
    if usage:

        def write_usage(conn: sqlite3.Connection) -> None:
            for row in usage:
                at = to_seconds(row["at"], now) or now
                unit = {"minute": 60, "hour": 3600, "day": 86_400}.get(str(row["granularity"]), 86_400)
                values = (
                    int(at - at % unit),
                    str(row["egress"]),
                    str(row["granularity"]),
                    int(row.get("requests", 0)),
                    int(row.get("req_bytes", 0)),
                    int(row.get("resp_bytes", 0)),
                    int(row.get("overhead_bytes", 0)),
                )
                conn.execute(
                    "INSERT INTO egress_usage (bucket_start, egress, granularity, requests, req_bytes, resp_bytes, "
                    "overhead_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    values,
                )

        dbs.metrics.write_sync(write_usage)
    logins = state.get("admin_logins") or []
    if logins:
        from roxy.core.iphash import ip_hash
        from roxy.metrics import security_events
        from roxy.metrics.recorder import EventRecord, write_events

        records = [
            EventRecord(
                at_ms=int((to_seconds(item["at"], now) or now) * 1000),
                type=security_events.LOGIN,
                severity="info" if item.get("successful", True) else "warn",
                reason_code="success" if item.get("successful", True) else "failure",
                ip_hash=ip_hash(str(item["ip"]), ctx.ip_hash_key) if ctx.ip_hash_key else None,
                place=None,
                endpoint_template=None,
                detail=security_events.login_detail(
                    str(item["ip"]),
                    bool(item.get("successful", True)),
                    item.get("username"),
                    str(item.get("method", "")),
                ),
            )
            for item in logins
        ]
        dbs.metrics.write_sync(lambda conn: write_events(conn, records))


async def _record_traffic(ctx: Any, events: Sequence[Mapping[str, Any]], now: float, clock: FakeClock) -> None:
    if not events:
        return
    recorder = ctx.recorder
    for item in events:
        clock.set(item["at_ms"] / 1000.0)
        recorder.record_outcome(outcome_event(item))
        side = item.get("x_upstream_429")
        if side:
            recorder.record_upstream_429(
                at_ms=int(item["at_ms"]) + int(side.get("offset_ms", 0)),
                endpoint_template=str(item["endpoint_template"]),
                host=str(item["host"]),
                egress=str(side["egress"]),
                retry_after_s=side.get("retry_after_s"),
                ratelimit_headers=side.get("ratelimit_headers"),
                request_id=str(item["request_id"]),
            )
    clock.set(now)
    await recorder.flush()


def _write_files(files: Mapping[str, Any], state_dir: Path, tmp_path: Path, now: float) -> None:
    roots = {"{state_dir}": state_dir, "{exports_dir}": tmp_path / "exports", "{backup_dir}": tmp_path / "backups"}
    for logical, spec in files.items():
        root, _, rest = str(logical).partition("/")
        if root not in roots:
            raise FixtureError(f"unknown file root {root}")
        path = roots[root] / rest
        if spec.get("missing"):
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if "json" in spec:
            path.write_text(json.dumps(convert_times(spec["json"], now)), encoding="utf-8")
        elif "content" in spec:
            path.write_text(str(spec["content"]), encoding="utf-8")
        elif "size_bytes" in spec:
            with path.open("wb") as handle:
                handle.truncate(int(spec["size_bytes"]))
        if "mode" in spec:
            path.chmod(int(str(spec["mode"]), 8))
        if "age" in spec:
            moment = to_seconds(spec["age"], now) or now
            os.utime(path, (moment, moment))


def _apply_faults(ctx: Any, faults: Mapping[str, Any], clock: FakeClock, inputs: Mapping[str, Any]) -> None:
    if faults.get("leak_guard_bypassed"):
        from roxy.egress.credential import GuardSelfTestKit, LeakMatcher

        manager = ctx.egress.credential
        real = manager.guard_self_test_kit

        def bypassed_kit(*args: Any, **kwargs: Any) -> Any:
            kit = real(*args, **kwargs)
            return GuardSelfTestKit(requests=kit.requests, matcher=LeakMatcher(()), synthetic=kit.synthetic)

        manager.guard_self_test_kit = bypassed_kit
    cache_db = ctx.dbs.cache
    if faults.get("cache_db_readonly"):

        async def refuse(*args: Any, **kwargs: Any) -> Any:
            raise sqlite3.OperationalError("attempt to write a readonly database")

        cache_db.write = refuse
    delay_ms = faults.get("cache_rw_latency_ms")
    if delay_ms:
        real_write, real_read = cache_db.write, cache_db.read

        async def slow_write(*args: Any, **kwargs: Any) -> Any:
            clock.advance(float(delay_ms) / 1000.0)
            return await real_write(*args, **kwargs)

        async def slow_read(*args: Any, **kwargs: Any) -> Any:
            clock.advance(float(delay_ms) / 1000.0)
            return await real_read(*args, **kwargs)

        cache_db.write = slow_write
        cache_db.read = slow_read


def _make_clients_trust_env(egress: Any) -> None:
    """Model a client built with trust_env=True (README `env.clients_trust_env`)."""
    real = egress._make_rotator_client

    def honoring(*args: Any, **kwargs: Any) -> Any:
        client = real(*args, **kwargs)
        client.http._trust_env = True
        return client

    egress._make_rotator_client = honoring


# ================================================================================================ comparing


def compare(case: Case, outcome: CaseOutcome) -> list[str]:
    """Every way the stored row and the calls differ from `expect` (an empty list means the case passes)."""
    problems = list(outcome.problems)
    expect = case.expect
    row = outcome.row
    rec = outcome.recorder
    problems += [f"unmocked: {item}" for item in rec.unmocked]
    problems += [f"expect_request: {item}" for item in rec.violations]
    if row is None:
        return [*problems, "no health_results row was stored"]
    if expect.get("status") != case.case:
        problems.append(f"fixture expect.status {expect.get('status')!r} differs from case {case.case!r}")
    for key in ("status", "value", "threshold", "fix_link", "explanation"):
        if key in expect:
            problems += check_constraint(row.get(key), expect[key], key)
    if "critical" in expect and bool(row.get("critical")) != bool(expect["critical"]):
        problems.append(f"critical: expected {expect['critical']}, got {bool(row.get('critical'))}")
    if row.get("status") in ("warn", "fail") and not row.get("explanation"):
        problems.append("explanation must be present for warn and fail")
    for key, wanted in (expect.get("calls") or {}).items():
        made = [c for c in rec.calls if c.key == key]
        if "count" in wanted:
            problems += check_constraint(len(made), wanted["count"], f"calls[{key}].count")
        if "via" in wanted:
            wrong = [c.egress for c in made if c.egress != wanted["via"]]
            if wrong or not made:
                problems.append(f"calls[{key}].via: expected {wanted['via']}, got {[c.egress for c in made]}")
    if "credential_calls" in expect:
        count = sum(1 for c in rec.calls if c.egress == "credential")
        problems += check_constraint(count, expect["credential_calls"], "credential_calls")
    for key in expect.get("no_calls_to") or []:
        if any(c.key == key for c in rec.calls):
            problems.append(f"no_calls_to: {key} was called")
    return problems


def describe(outcome: CaseOutcome) -> str:
    row = outcome.row or {}
    calls = [(c.key, c.egress) for c in outcome.recorder.calls]
    return (
        f"stored: status={row.get('status')!r} value={row.get('value')!r} threshold={row.get('threshold')!r} "
        f"critical={row.get('critical')!r} fix_link={row.get('fix_link')!r}\n"
        f"explanation={row.get('explanation')!r}\ncalls={calls}"
    )


__all__ = [
    "Case",
    "CaseOutcome",
    "FixtureError",
    "check_constraint",
    "compare",
    "describe",
    "load_cases",
    "run_case",
]
