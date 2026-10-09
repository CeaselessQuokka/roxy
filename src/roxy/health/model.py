"""Health check data shapes: statuses, one check's result, the catalog entry of a check, and band helpers.

What this is
    `Status` (pass, warn, fail, n/a), `CheckKind`, `CheckResult` (one `health_results` row before it is stored),
    `CheckSpec` (one plan 13.2 check: title, what it measures, thresholds, the fix link, the explanation, its
    timeout and the function that runs it), `RunOptions` (what a run was asked to do) and the small helpers
    `band_low_good` and `band_high_good` that turn a measured number into a status.

Why it exists
    The runner, the storage layer, the reports and the admin API all talk about the same objects. Defining them
    once, in a module that imports nothing else from the health package, avoids import cycles and gives every
    field one meaning. Plan 13.2: "Each result row shows status badge, measured value, threshold, a one-paragraph
    explanation of what the check means, and a How to fix link".

How it works
    Plain dataclasses. A `CheckResult` carries text for people (`value`, `threshold`, `explanation`) and numbers
    for machines (`measured`, `unit`, `detail`), and `critical` for the two results plan 13.2 calls critical (an
    account switch, C1, and a leak guard that did not block, C2). `detail` is a small bounded mapping without
    secrets; anything in it that came from outside Roxy (headers, command output) sits under `external`, which
    the LLM copy moves into its `untrusted` section (plan 12.5).

What to read next
    `roxy/health/checks.py` (the checks), `roxy/health/runner.py` (how a run executes them).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from roxy.health.checks import CheckEnv


class Status(StrEnum):
    """The four statuses of a check result (plan 13.2). Stored as these exact strings."""

    PASS = "pass"  # noqa: S105 (a status name, not a password)
    WARN = "warn"
    FAIL = "fail"
    NA = "n/a"


STATUS_ORDER: dict[str, int] = {Status.PASS: 0, Status.NA: 1, Status.WARN: 2, Status.FAIL: 3}
"""Worse is larger: used to pick the worst result and to decide whether a comparison got better or worse."""


class CheckKind(StrEnum):
    """What a check touches, which decides its timeout and whether a scheduled run may skip it."""

    LOCAL = "local"  # Roxy's own state and databases only
    UPSTREAM = "upstream"  # calls Roblox anonymously through the upstream buckets
    CREDENTIAL = "credential"  # calls Roblox with the account credential (13.3 budget)
    NETWORK = "network"  # DNS, TLS, the public origin, the rotator, alert channels
    SYSTEM = "system"  # the operating system: systemd, files written by root tools


class Trigger(StrEnum):
    """Who started a run (`health_runs.trigger`)."""

    MANUAL = "manual"
    SCHEDULE = "schedule"
    DEPLOY = "deploy"
    CLI = "cli"


TRIGGERS: tuple[str, ...] = tuple(t.value for t in Trigger)


@dataclass(slots=True)
class CheckResult:
    """One check's outcome (a `health_results` row plus the fields of the 0003 migration)."""

    check_id: str
    status: Status
    value: str
    threshold: str
    explanation: str
    fix_link: str
    critical: bool = False
    measured: float | None = None
    unit: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        """The JSON shape used by the API, the SSE event and the reports."""
        return {
            "check_id": self.check_id,
            "status": self.status.value,
            "value": self.value,
            "threshold": self.threshold,
            "explanation": self.explanation,
            "fix_link": self.fix_link,
            "critical": self.critical,
            "measured": self.measured,
            "unit": self.unit,
            "detail": dict(self.detail),
            "duration_ms": round(self.duration_ms, 3),
        }


CheckFn = Callable[["CheckEnv"], Awaitable[CheckResult]]


@dataclass(frozen=True, slots=True)
class CheckSpec:
    """One plan 13.2 check: everything the catalog, the runner and the Health page need to know about it.

    `id` keeps 13.2's placeholder (`H-REACH-<host>`); `instance_id(params)` fills it in. `uses_credential` marks
    the checks that call Roblox with the account (H-CRED-AUTH), which scheduled runs skip unless
    `health_auto_include_credential` is 1 (plan 13.1 and 13.3).
    """

    id: str
    title: str
    measures: str
    thresholds: str
    fix_link: str
    fix_label: str
    explanation: str
    kind: CheckKind
    timeout_s: float
    fn: CheckFn
    uses_credential: bool = False
    placeholder: str = ""  # the 13.2 placeholder name ("host") when the id has one

    def instance_id(self, params: Mapping[str, str] | None = None) -> str:
        """The stored `check_id`: the 13.2 id with its placeholder filled in."""
        if not self.placeholder:
            return self.id
        value = (params or {}).get(self.placeholder, "")
        return self.id.replace(f"<{self.placeholder}>", value)


@dataclass(frozen=True, slots=True)
class RunOptions:
    """What one run was asked to do.

    `checks` limits the run to some check ids (13.2 ids, placeholders kept or filled); empty means every check.
    `include_credential` is the scheduled-run switch (manual runs always include credential checks).
    `admin_ip` is the address of the admin who started the run (H-BANS must never find it banned); it is used
    in memory only and never stored.
    """

    checks: tuple[str, ...] = ()
    include_credential: bool = True
    admin_ip: str | None = None

    def as_public_dict(self) -> dict[str, Any]:
        """What is stored with the run (`health_runs.options_json`): never the admin's address."""
        return {"checks": list(self.checks), "include_credential": self.include_credential}


def band_low_good(value: float, pass_below: float, warn_below: float) -> Status:
    """Lower is better: pass under `pass_below`, warn under `warn_below`, fail at or above it."""
    if value < pass_below:
        return Status.PASS
    if value < warn_below:
        return Status.WARN
    return Status.FAIL


def band_high_good(value: float, pass_above: float, warn_above: float) -> Status:
    """Higher is better: pass over `pass_above`, warn over `warn_above`, fail at or below it."""
    if value > pass_above:
        return Status.PASS
    if value > warn_above:
        return Status.WARN
    return Status.FAIL


def worst(statuses: list[Status]) -> Status:
    """The worst status of a list (pass for an empty list)."""
    found = Status.PASS
    for status in statuses:
        if STATUS_ORDER[status] > STATUS_ORDER[found]:
            found = status
    return found


__all__ = [
    "STATUS_ORDER",
    "TRIGGERS",
    "CheckFn",
    "CheckKind",
    "CheckResult",
    "CheckSpec",
    "RunOptions",
    "Status",
    "Trigger",
    "band_high_good",
    "band_low_good",
    "worst",
]
