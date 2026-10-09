"""Every plan 13.2 check: what it measures, its pass, warn and fail thresholds, its explanation and its fix link.

What this is
    One async function per check of the 13.2 table and the `CATALOG` that describes them (`CheckSpec`). Each
    function receives a `CheckEnv` (the worker context, the replaceable `SystemFacts`, the run trigger and
    options) and returns one `CheckResult`. Thresholds are the module constants below (the plan's defaults; plan
    13.2 lists no settings for them), and every result says which threshold it was judged against.

Why it exists
    Plan 13.2 is a checklist an owner acts on, so each row must be honest (P6) and specific: the measured value,
    the threshold, a paragraph that explains what the check means and what was found, and a link to the page or
    runbook that fixes it. Checks never duplicate the logic of the packages they look at: they call the real
    APIs (`EgressClients` self-tests, `CredentialManager.probe` through `UpstreamService.credential_probe_fetch`,
    `UpstreamService.internal_fetch`, `metrics.queries` read models, the cache's shared tier, the scheduler's
    heartbeat view, the catalog validators and the rules matcher).

How it works
    - Upstream checks (H-REACH, H-CLOCK) call Roblox through `ctx.upstream.internal_fetch` at internal priority,
      so they wait for bucket slots, honor cooldowns and breakers, and are recorded as Roxy's own calls; they
      never burst. H-CRED-AUTH is the only check that uses the credential, and only through the credential path.
    - Durations are measured with `ctx.clock.monotonic()`, so the fixture harness's fake clock decides them.
    - Anything outside Roxy (DNS, TLS, commands, the public origin, alert channels, status files) is read through
      `env.facts` (`roxy/health/facts.py`), which tests replace.
    - A check that cannot apply here (no rotator configured, development without systemd) answers `n/a` with an
      explanation, never a false pass.

What to read next
    `roxy/health/runner.py` (how a run executes these), `roxy/health/probes.py` (the 13.4 probe URLs).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Final
from urllib.parse import urlsplit

from roxy.health import probes
from roxy.health.facts import (
    DnsFailure,
    OriginAnswer,
    OriginFailure,
    SystemFacts,
    TlsFailure,
    parse_iso_time,
    read_json_file,
)
from roxy.health.model import (
    CheckKind,
    CheckResult,
    CheckSpec,
    RunOptions,
    Status,
    Trigger,
    band_high_good,
    band_low_good,
)

# ------------------------------------------------------------------------------------------------ thresholds
# Plan 13.2 defaults. They are plan constants, not settings: the catalog (config/catalog.py) has no health
# threshold keys, and each result names the threshold it used.

CRED_COOLDOWN_FAIL_S: Final = 60.0
DNS_PASS_MS: Final = 100.0
DNS_WARN_MS: Final = 500.0
TLS_WARN_DAYS: Final = 14.0
REACH_PASS_MS: Final = 800.0
REACH_WARN_MS: Final = 2000.0
LATENCY_WINDOW_S: Final = 900
LATENCY_PASS_MS: Final = 1000.0
LATENCY_WARN_MS: Final = 2500.0
RATE_WINDOW_S: Final = 900
RATE_429_PASS_PCT: Final = 0.5
RATE_429_WARN_PCT: Final = 2.0
ERR_PASS_PCT: Final = 0.5
ERR_WARN_PCT: Final = 2.0
CACHE_RW_PASS_MS: Final = 20.0
CACHE_RW_WARN_MS: Final = 200.0
CACHE_HIT_WINDOW_S: Final = 3600
CACHE_HIT_PASS_PCT: Final = 30.0
CACHE_HIT_WARN_PCT: Final = 10.0
DB_SIZE_PASS_PCT: Final = 70.0
DB_SIZE_WARN_PCT: Final = 90.0
MIB: Final = 1024 * 1024
WAL_PASS_BYTES: Final = 64 * MIB
WAL_WARN_BYTES: Final = 256 * MIB
DISK_PASS_FREE_PCT: Final = 25.0
DISK_WARN_FREE_PCT: Final = 10.0
LEADER_RENEW_WARN_S: Final = 10.0
JOB_LATE_INTERVALS: Final = 2.0
"""A job is late when it last started more than this many intervals ago."""
LOOP_LAG_WINDOW_S: Final = 300.0
LOOP_LAG_PASS_MS: Final = 50.0
LOOP_LAG_WARN_MS: Final = 200.0
ROTATOR_SLOW_MS: Final = 2000.0
"""13.2 gives no number for a slow rotator echo; the H-REACH warn edge is used (anything slower is slow)."""
QUOTA_PASS_PCT: Final = 30.0
QUOTA_WARN_PCT: Final = 10.0
QUOTA_MIN_DAYS_FOR_PROJECTION: Final = 1.0
SYSTEMD_RESTART_WINDOW_S: Final = 86_400.0
TLS_PUBLIC_PASS_DAYS: Final = 21.0
TLS_PUBLIC_WARN_DAYS: Final = 7.0
CLOCK_PASS_S: Final = 2.0
CLOCK_WARN_S: Final = 10.0
PERMS_MAX_AGE_S: Final = 7 * 3600.0
BACKUP_PASS_H: Final = 26.0
BACKUP_WARN_H: Final = 72.0
BAN_WIDE_PREFIX_V4: Final = 16
BAN_WIDE_PREFIX_V6: Final = 32
"""A ban wider than these prefixes needs a note (13.2 says /16; for IPv6 a /32 is the same order of size)."""
TOP_PLACES: Final = 5
TOP_PLACE_MIN_SHARE: Final = 0.05
ADMIN_LOGIN_LOOKBACK_S: Final = 30 * 86_400
NETWORK_CONCURRENCY: Final = 8
"""Lookups and handshakes one H-DNS or H-TLS check runs at once (about 35 allowed hosts by default)."""
SECURITY_HEADERS_REQUIRED: Final = ("strict-transport-security", "x-content-type-options")
APP_SERVER_NAMES: Final = ("uvicorn", "gunicorn", "python", "starlette")

# Timeouts per check kind (the runner raises the upstream ones to cover the internal queue wait and the attempts).
TIMEOUT_LOCAL_S: Final = 20.0
TIMEOUT_NETWORK_S: Final = 30.0
TIMEOUT_UPSTREAM_S: Final = 60.0
TIMEOUT_SYSTEM_S: Final = 15.0
COMMAND_TIMEOUT_S: Final = 5.0
ORIGIN_TIMEOUT_S: Final = 10.0
DNS_TIMEOUT_S: Final = 5.0
TLS_TIMEOUT_S: Final = 10.0
ALERT_TIMEOUT_S: Final = 10.0

PROBE_PURPOSE: Final = "health_check"
"""The purpose Roxy's own reachability probes carry (`internal_endpoints` lists it; plan rows 28 and 29)."""

UNITS: Final = ("roxy@blue", "roxy@green")


# ------------------------------------------------------------------------------------------------ the environment


@dataclass(slots=True)
class CheckEnv:
    """What one check run receives. `params` fills the 13.2 placeholder (`host` for H-REACH)."""

    ctx: Any
    facts: SystemFacts
    spec: CheckSpec
    params: Mapping[str, str] = field(default_factory=dict)
    trigger: str = Trigger.MANUAL.value
    options: RunOptions = field(default_factory=RunOptions)

    @property
    def check_id(self) -> str:
        return self.spec.instance_id(self.params)

    def setting(self, key: str) -> Any:
        return self.ctx.settings.get(key)

    def now(self) -> float:
        return float(self.ctx.clock.now())

    def mono(self) -> float:
        return float(self.ctx.clock.monotonic())

    @property
    def development(self) -> bool:
        return str(getattr(self.ctx.env, "env", "production")) == "development"

    def result(
        self,
        status: Status,
        value: str,
        *,
        finding: str = "",
        threshold: str | None = None,
        critical: bool = False,
        measured: float | None = None,
        unit: str = "",
        detail: Mapping[str, Any] | None = None,
    ) -> CheckResult:
        """A result with this check's id, explanation, threshold text and fix link filled in."""
        explanation = self.spec.explanation if not finding else f"{self.spec.explanation} {finding}"
        return CheckResult(
            check_id=self.check_id,
            status=status,
            value=value,
            threshold=threshold if threshold is not None else self.spec.thresholds,
            explanation=explanation,
            fix_link=self.spec.fix_link,
            critical=critical,
            measured=None if measured is None else round(float(measured), 3),
            unit=unit,
            detail=dict(detail or {}),
        )

    def not_applicable(self, value: str, finding: str, **detail: Any) -> CheckResult:
        return self.result(Status.NA, value, finding=finding, detail=detail)


def _fmt(value: float, digits: int = 0) -> str:
    """A number for display text (no thousands separators, so the first number in a value parses cleanly)."""
    return f"{value:.{digits}f}"


def _ms(seconds: float) -> float:
    # Rounded to a microsecond: a difference of two clock readings is not exact in binary floating point, and an
    # answer that took exactly 800 ms must land on the 800 ms edge, not 799.9999999.
    return round(seconds * 1000.0, 3)


# ------------------------------------------------------------------------------------------------ credential


async def check_cred_present(env: CheckEnv) -> CheckResult:
    egress = env.ctx.egress
    if egress is None:
        return env.not_applicable("unknown", "The egress clients are not running in this worker.")
    await egress.credential.refresh()
    status = egress.credential.status()
    if status.present:
        source = f" ({status.source} value)" if status.source else ""
        extra = "" if status.enabled else " The credential is switched off (credential_enabled = 0)."
        return env.result(Status.PASS, f"present{source}", finding=extra.strip(), detail={"source": status.source})
    problem = f" Reason: {status.problem}." if status.problem else ""
    return env.result(
        Status.FAIL,
        "absent",
        finding="No Roblox credential is loaded, so allowlisted endpoints and the credential probes cannot work."
        + problem,
        detail={"problem": status.problem},
    )


_PROBE_VALUES: Final[dict[str, tuple[Status, str]]] = {
    "ok": (Status.PASS, "200, same account"),
    "ok_no_account_id": (Status.WARN, "200, account not identified"),
    "account_mismatch": (Status.FAIL, "200, different account"),
    "rejected": (Status.FAIL, "rejected"),
    "rate_limited": (Status.WARN, "429, rate limited"),
    "cooling_down": (Status.WARN, "cooling down, not called"),
    "busy": (Status.WARN, "another credential probe was running"),
    "timeout": (Status.WARN, "no answer (timeout)"),
    "connect_error": (Status.WARN, "no answer (connection failed)"),
    "degraded": (Status.WARN, "shared state unreadable"),
}


async def check_cred_auth(env: CheckEnv) -> CheckResult:
    egress, upstream = env.ctx.egress, env.ctx.upstream
    if egress is None or upstream is None:
        return env.not_applicable("unknown", "The egress or upstream service is not running in this worker.")
    await egress.credential.refresh()
    status = egress.credential.status()
    if not status.enabled:
        return env.not_applicable("disabled", "The credential is switched off (credential_enabled = 0).")
    if not status.present:
        return env.not_applicable("absent", "No credential is loaded; H-CRED-PRESENT reports it.")
    # The credential path only: the manager's probe, paced by the reserved probe sub-bucket (plan 7.3, 13.3).
    probe = await egress.credential.probe("health", fetch=upstream.probe_fetch_for("health"))
    outcome = str(probe.outcome)
    verdict, label = _PROBE_VALUES.get(outcome, (Status.WARN, outcome))
    if outcome == "rejected":
        label = f"{probe.status_code} rejected" if probe.status_code else "rejected"
    elif outcome.startswith("http_"):
        verdict, label = (Status.WARN, f"{outcome[5:]} unexpected answer")
    findings = {
        Status.PASS: "",
        Status.WARN: "The credential could not be confirmed this time, but nothing says it expired.",
        Status.FAIL: "Roblox no longer accepts the credential; Roxy stopped using it.",
    }
    finding = findings.get(verdict, "")
    if outcome == "account_mismatch":
        finding = (
            "The credential now belongs to a different Roblox account than the one recorded when it was set. "
            "That is an account switch (plan C1): Roxy stopped using it until you confirm the account."
        )
    elif outcome == "rate_limited" and probe.retry_after_s:
        label = f"429, rate limited (retry in {probe.retry_after_s} s)"
        finding = "Roblox rate-limited the account; this is not an expiry. The credential cools down meanwhile."
    detail = {"outcome": outcome, "status_code": probe.status_code, "account_match": probe.account_match}
    return env.result(
        verdict,
        label,
        finding=finding,
        critical=outcome == "account_mismatch",
        measured=probe.latency_ms,
        unit="ms",
        detail=detail,
    )


async def check_cred_cooldown(env: CheckEnv) -> CheckResult:
    egress = env.ctx.egress
    if egress is None:
        return env.not_applicable("unknown", "The egress clients are not running in this worker.")
    await egress.credential.refresh()
    if not egress.credential.status().present:
        return env.not_applicable("absent", "No credential is loaded, so there is nothing to cool down.")
    remaining = float(egress.credential.cooldown_remaining())
    value = f"{_fmt(remaining, 1)} s remaining"
    if remaining <= 0:
        return env.result(Status.PASS, "0 s remaining", measured=0.0, unit="s")
    status = Status.WARN if remaining < CRED_COOLDOWN_FAIL_S else Status.FAIL
    finding = (
        "Roblox rate-limited the account recently, so allowlisted traffic waits until the cooldown ends."
        if status is Status.WARN
        else "The account is cooling down for a minute or more; allowlisted endpoints answer from cache or 503."
    )
    return env.result(status, value, finding=finding, measured=remaining, unit="s")


async def check_cred_guard(env: CheckEnv) -> CheckResult:
    egress = env.ctx.egress
    if egress is None:
        return env.not_applicable("unknown", "The egress clients are not running in this worker.")
    outcome = await egress.self_test_leak_guard()
    status = Status(outcome.status)
    finding = "" if status is Status.PASS else str(outcome.detail).rstrip(".") + "."
    if status is Status.FAIL:
        finding = (
            "The leak guard let a synthetic credential-bearing rotator request through (it was never sent). "
            "Plan C2 depends on this guard: treat it as an emergency."
        )
    facts = {k: v for k, v in dict(outcome.facts).items() if k in ("blocked", "attempts", "reached_network")}
    return env.result(status, str(outcome.value), finding=finding, critical=status is Status.FAIL, detail=facts)


async def check_env_proxy(env: CheckEnv) -> CheckResult:
    egress = env.ctx.egress
    if egress is None:
        return env.not_applicable("unknown", "The egress clients are not running in this worker.")
    outcome = egress.self_test_env_proxy(env.facts.environ())
    status = Status(outcome.status)
    finding = "" if status is Status.PASS else str(outcome.detail).rstrip(".") + "."
    if status is Status.WARN:
        finding = (
            "Proxy variables are set in the service environment but every outbound client ignores them "
            "(trust_env is off). Remove them from roxy.env so a future client cannot pick them up."
        )
    detail = {k: v for k, v in dict(outcome.facts).items() if k in ("variables_set", "clients_honoring")}
    return env.result(status, str(outcome.value), finding=finding, critical=status is Status.FAIL, detail=detail)


# ------------------------------------------------------------------------------------------------ DNS and TLS


def _allowed_hosts(env: CheckEnv) -> list[str]:
    hosts = [str(h).strip().lower().rstrip(".") for h in (env.setting("allowed_roblox_hosts") or ()) if str(h).strip()]
    return list(dict.fromkeys(hosts))


async def _bounded_gather(items: Sequence[Any], fn: Any, limit: int = NETWORK_CONCURRENCY) -> list[Any]:
    gate = asyncio.Semaphore(limit)

    async def one(item: Any) -> Any:
        async with gate:
            return await fn(item)

    return list(await asyncio.gather(*(one(item) for item in items)))


async def check_dns(env: CheckEnv) -> CheckResult:
    hosts = _allowed_hosts(env)
    if not hosts:
        return env.not_applicable("no hosts", "allowed_roblox_hosts is empty.")

    async def lookup(host: str) -> tuple[str, Any]:
        try:
            return host, await env.facts.resolve(host, DNS_TIMEOUT_S)
        except DnsFailure as exc:
            return host, exc

    answers = await _bounded_gather(hosts, lookup)
    failures = [(host, item.kind) for host, item in answers if isinstance(item, DnsFailure)]
    private = [
        host
        for host, item in answers
        if not isinstance(item, DnsFailure) and any(not env.facts.is_public_address(a) for a in item.addresses)
    ]
    latencies = [(item.latency_ms, host) for host, item in answers if not isinstance(item, DnsFailure)]
    slowest_ms, slowest_host = max(latencies) if latencies else (0.0, "")
    detail = {"hosts": len(hosts), "failures": dict(failures), "private": private[:20]}
    if failures:
        first_host, kind = failures[0]
        value = f"{len(failures)} of {len(hosts)} hosts failed ({kind} for {first_host})"
        finding = "Roxy cannot reach a Roblox host whose name does not resolve; callers of that host get errors."
        return env.result(Status.FAIL, value, finding=finding, measured=slowest_ms, unit="ms", detail=detail)
    if private:
        value = f"{len(private)} of {len(hosts)} hosts resolve to a private address ({private[0]})"
        finding = (
            "A Roblox host resolves to a private address: a poisoned or split-horizon resolver. Roxy refuses to "
            "send traffic there (plan 9.10)."
        )
        return env.result(Status.FAIL, value, finding=finding, measured=slowest_ms, unit="ms", detail=detail)
    status = band_low_good(slowest_ms, DNS_PASS_MS, DNS_WARN_MS)
    value = f"{_fmt(slowest_ms)} ms slowest ({slowest_host}), {len(hosts)} hosts resolved"
    finding = "" if status is Status.PASS else "Name resolution is slow; every new upstream connection pays it."
    return env.result(status, value, finding=finding, measured=slowest_ms, unit="ms", detail=detail)


async def check_tls(env: CheckEnv) -> CheckResult:
    hosts = _allowed_hosts(env)
    if not hosts:
        return env.not_applicable("no hosts", "allowed_roblox_hosts is empty.")

    async def handshake(host: str) -> tuple[str, Any]:
        try:
            return host, await env.facts.tls_probe(host, 443, TLS_TIMEOUT_S)
        except TlsFailure as exc:
            return host, exc

    answers = await _bounded_gather(hosts, handshake)
    failures = [(host, item.kind) for host, item in answers if isinstance(item, TlsFailure)]
    good = [(item.days_left, item.handshake_ms, host) for host, item in answers if not isinstance(item, TlsFailure)]
    detail: dict[str, Any] = {"hosts": len(hosts), "failures": dict(failures)}
    if failures:
        host, kind = failures[0]
        value = f"{len(failures)} of {len(hosts)} handshakes failed ({kind} for {host})"
        finding = "A TLS handshake to a Roblox host failed, so every call to it fails before it is sent."
        return env.result(Status.FAIL, value, finding=finding, detail=detail)
    soonest_days, _ms_unused, soonest_host = min(good)
    slowest = max(item[1] for item in good)
    status = Status.PASS if soonest_days > TLS_WARN_DAYS else Status.WARN
    value = (
        f"{_fmt(soonest_days)} days to the soonest certificate expiry ({soonest_host}), "
        f"slowest handshake {_fmt(slowest)} ms"
    )
    finding = (
        ""
        if status is Status.PASS
        else "A Roblox certificate expires soon. Roblox renews its own certificates; if it does not, calls will fail."
    )
    return env.result(status, value, finding=finding, measured=soonest_days, unit="days", detail=detail)


async def check_tls_public(env: CheckEnv) -> CheckResult:
    origin = str(getattr(env.ctx.env, "site_origin", ""))
    parts = urlsplit(origin)
    if parts.scheme != "https" or not parts.hostname:
        return env.not_applicable("not https", "ROXY_SITE_ORIGIN is not an https address (a development setup).")
    try:
        answer = await env.facts.tls_probe(parts.hostname, parts.port or 443, TLS_TIMEOUT_S)
    except TlsFailure as exc:
        finding = "The public certificate is not accepted: browsers and game servers using https fail now."
        return env.result(Status.FAIL, f"handshake failed ({exc.kind})", finding=finding, detail={"error": exc.kind})
    days = float(answer.days_left)
    status = band_high_good(days, TLS_PUBLIC_PASS_DAYS, TLS_PUBLIC_WARN_DAYS)
    finding = "" if status is Status.PASS else "Certbot should renew 30 days ahead; renewal is failing or late."
    return env.result(status, f"{_fmt(days)} days left", finding=finding, measured=days, unit="days")


# ------------------------------------------------------------------------------------------------ Roblox probes


def _json_body(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


async def check_reach(env: CheckEnv) -> CheckResult:
    host = str(env.params.get("host", "")).strip().lower()
    upstream = env.ctx.upstream
    if upstream is None:
        return env.not_applicable("unknown", "The upstream service is not running in this worker.")
    probe = probes.probe_for(host)
    from roxy.core.reasons import ReasonCode

    started = env.mono()
    try:
        result = await upstream.internal_fetch(PROBE_PURPOSE, probe.method, probe.url, body=probe.body)
    except ValueError:
        return env.not_applicable("not allowed", f"{host} is not on allowed_roblox_hosts, so it is never probed.")
    elapsed = _ms(env.mono() - started)
    status_code = result.upstream_status
    detail: dict[str, Any] = {
        "url": probe.url,
        "method": probe.method,
        "reason": result.reason.value,
        "calls": result.calls,
        "egress": result.egress.value,
    }
    threshold = (
        f"pass: {'any status below 500' if probe.head_only else 'expected status'} under {_fmt(REACH_PASS_MS)} ms; "
        f"warn: under {_fmt(REACH_WARN_MS)} ms or a 429; fail: anything else"
    )
    reason = result.reason
    if status_code == 429 or reason is ReasonCode.UPSTREAM_COOLDOWN:
        value = f"429 in {_fmt(elapsed)} ms" if status_code == 429 else "429 cooldown active, not called"
        finding = "Roblox rate-limited this host; the probe waits like any other call. Reachable, but throttled."
        return env.result(
            Status.WARN, value, finding=finding, threshold=threshold, measured=elapsed, unit="ms", detail=detail
        )
    if reason in (ReasonCode.UPSTREAM_OK, ReasonCode.UPSTREAM_4XX, ReasonCode.UPSTREAM_5XX) and status_code is not None:
        value = f"{status_code} in {_fmt(elapsed)} ms"
        if not probe.accepts(int(status_code)):
            finding = f"{host} answered with a status that means it is not working ({status_code})."
            return env.result(
                Status.FAIL, value, finding=finding, threshold=threshold, measured=elapsed, unit="ms", detail=detail
            )
        status = band_low_good(elapsed, REACH_PASS_MS, REACH_WARN_MS)
        finding = "" if status is Status.PASS else f"{host} answered, but slowly; callers wait as long."
        if status is Status.FAIL:
            finding = f"{host} answered after {_fmt(elapsed)} ms, beyond the {_fmt(REACH_WARN_MS)} ms warn edge."
        if probe.json_field and int(status_code) == 200 and status is not Status.FAIL:
            payload = _json_body(result.body)
            if not isinstance(payload, dict) or probe.json_field not in payload:
                status = Status.WARN
                finding = f"{host} answered 200 without the `{probe.json_field}` field this probe expects."
        return env.result(
            status, value, finding=finding, threshold=threshold, measured=elapsed, unit="ms", detail=detail
        )
    labels = {
        ReasonCode.UPSTREAM_TIMEOUT: "timeout",
        ReasonCode.UPSTREAM_CONNECT: "connection failed",
        ReasonCode.UPSTREAM_BUSY: "no bucket slot in time",
        ReasonCode.QUEUE_OVERFLOW: "queue full",
        ReasonCode.EGRESS_DISABLED: "no egress available",
        ReasonCode.DEGRADED: "shared state unavailable",
    }
    label = labels.get(reason, reason.value)
    value = f"no answer ({label}) after {_fmt(elapsed)} ms"
    status = Status.WARN if reason in (ReasonCode.UPSTREAM_BUSY, ReasonCode.QUEUE_OVERFLOW) else Status.FAIL
    finding = (
        "The probe waited for a bucket slot and gave up; the host was not judged. Roxy is busy or a bucket is small."
        if status is Status.WARN
        else f"{host} could not be reached; callers of this host get errors or stale answers."
    )
    return env.result(status, value, finding=finding, threshold=threshold, measured=elapsed, unit="ms", detail=detail)


async def check_clock(env: CheckEnv) -> CheckResult:
    ntp: bool | None = None
    command = await env.facts.run_command(("timedatectl", "show"), COMMAND_TIMEOUT_S)
    if command.returncode == 0:
        props = _key_values(command.stdout)
        if "NTPSynchronized" in props:
            ntp = props["NTPSynchronized"].strip().lower() == "yes"
    skew: float | None = None
    upstream = env.ctx.upstream
    if upstream is not None:
        before = env.now()
        with contextlib.suppress(ValueError):
            result = await upstream.internal_fetch(PROBE_PURPOSE, "GET", probes.CLOCK_PROBE_URL)
            after = env.now()
            header = result.trace.upstream_headers.get("date") if result.trace is not None else None
            if header:
                with contextlib.suppress(TypeError, ValueError, IndexError):
                    moment = parsedate_to_datetime(header)
                    if moment.tzinfo is None:
                        moment = moment.replace(tzinfo=UTC)
                    skew = (before + after) / 2 - moment.timestamp()
    ntp_text = {True: "NTP synchronized", False: "NTP not synchronized", None: "NTP status unreadable"}[ntp]
    detail = {"skew_s": None if skew is None else round(skew, 3), "ntp_synchronized": ntp}
    if skew is None:
        if ntp is False:
            return env.result(Status.WARN, f"no Roblox Date header; {ntp_text}", finding="NTP is off.", detail=detail)
        return env.not_applicable("no Roblox Date header", "Roblox could not be asked for its time this run.", **detail)
    size = abs(skew)
    direction = "ahead of" if skew > 0 else "behind"
    status = band_low_good(size, CLOCK_PASS_S, CLOCK_WARN_S)
    if status is Status.PASS and ntp is False:
        status = Status.WARN
    value = f"{_fmt(size, 1)} s {direction} Roblox; {ntp_text}"
    finding = ""
    if status is not Status.PASS:
        finding = (
            "The server clock disagrees with Roblox. Skew breaks TOTP sign-in windows and makes Retry-After dates "
            "and cache ages wrong; enable NTP (timedatectl set-ntp true)."
        )
    return env.result(status, value, finding=finding, measured=size, unit="s", detail=detail)


# ------------------------------------------------------------------------------------------------ public origin


def _server_problem(headers: Mapping[str, str]) -> str:
    server = str(headers.get("server", "")).strip()
    if not server:
        return ""
    lowered = server.lower()
    if re.search(r"\d", server) or any(name in lowered for name in APP_SERVER_NAMES):
        return f"Server header reveals {server[:40]!r}"
    return ""


def _origin_https(env: CheckEnv) -> bool:
    return urlsplit(str(getattr(env.ctx.env, "site_origin", ""))).scheme == "https"


async def check_e2e(env: CheckEnv) -> CheckResult:
    if not _origin_https(env):
        return env.not_applicable("not https", "ROXY_SITE_ORIGIN is not an https address, so there is no nginx.")
    answers: list[OriginAnswer | OriginFailure] = []
    for _ in range(2):
        try:
            answers.append(await env.facts.origin_fetch(probes.E2E_PATH, ORIGIN_TIMEOUT_S))
        except OriginFailure as exc:
            answers.append(exc)
    parts: list[str] = []
    problems: list[str] = []
    for index, item in enumerate(answers, start=1):
        if isinstance(item, OriginFailure):
            parts.append(f"no answer ({item.kind})")
            problems.append(f"request {index} got no answer ({item.kind})")
            continue
        cache = str(item.headers.get("roxy-cache", "")).upper()
        parts.append(f"{item.status} {cache}".strip())
        if not 200 <= item.status < 300:
            problems.append(f"request {index} answered {item.status}")
            continue
        if not item.headers.get("roxy-request-id"):
            problems.append(f"request {index} has no Roxy-Request-Id")
        missing = [name for name in SECURITY_HEADERS_REQUIRED if not item.headers.get(name)]
        if missing:
            problems.append(f"request {index} is missing {', '.join(missing)}")
        server = _server_problem(item.headers)
        if server:
            problems.append(f"request {index}: {server}")
    value = ", ".join(parts)
    detail = {"problems": problems}
    if problems:
        finding = "The public pipeline (nginx, then Roxy, then Roblox) is broken: " + "; ".join(problems) + "."
        return env.result(Status.FAIL, value, finding=finding, detail=detail)
    first = answers[0].headers.get("roxy-cache", "").upper() if isinstance(answers[0], OriginAnswer) else ""
    second = answers[1].headers.get("roxy-cache", "").upper() if isinstance(answers[1], OriginAnswer) else ""
    if first in ("MISS", "HIT", "REVALIDATING", "STALE", "COALESCED") and second in ("HIT", "REVALIDATING"):
        return env.result(Status.PASS, value, detail=detail)
    finding = (
        "Both answers worked, but the second one was not served from the cache: a cache rule stopped matching, "
        "caching is off, or cache.db is not writable."
    )
    return env.result(Status.WARN, value, finding=finding, detail=detail)


async def check_nginx(env: CheckEnv) -> CheckResult:
    if not _origin_https(env):
        return env.not_applicable("not https", "ROXY_SITE_ORIGIN is not an https address, so there is no nginx.")
    paths = {
        "/": "/",
        "static": probes.STATIC_ASSET_PATH,
        "admin": probes.ADMIN_PATH,
        "internal": probes.INTERNAL_VERSION_PATH,
    }
    answers: dict[str, OriginAnswer | OriginFailure] = {}
    for label, path in paths.items():
        try:
            answers[label] = await env.facts.origin_fetch(path, ORIGIN_TIMEOUT_S)
        except OriginFailure as exc:
            answers[label] = exc
    required: list[str] = []
    optional: list[str] = []
    hsts_ok = 0
    for label in ("/", "static", "admin"):
        item = answers[label]
        if isinstance(item, OriginFailure):
            required.append(f"{paths[label]} got no answer ({item.kind})")
            continue
        if item.headers.get("strict-transport-security"):
            hsts_ok += 1
        else:
            required.append(f"HSTS missing on {paths[label]}")
        server = _server_problem(item.headers)
        if server:
            required.append(f"{server} on {paths[label]}")
    root = answers["/"]
    if isinstance(root, OriginAnswer) and not root.headers.get("x-content-type-options"):
        optional.append("X-Content-Type-Options missing on /")
    internal = answers["internal"]
    if isinstance(internal, OriginFailure):
        required.append(f"{probes.INTERNAL_VERSION_PATH} got no answer ({internal.kind})")
    elif internal.status != 404:
        required.append(f"{probes.INTERNAL_VERSION_PATH} answered {internal.status}, not 404")
    processes = getattr(env.ctx.env, "nginx_worker_processes", None)
    connections = getattr(env.ctx.env, "nginx_worker_connections", None)
    budget = int(env.setting("tarpit_connection_budget"))
    capacity: int | None = None
    if processes and connections:
        capacity = int(processes) * int(connections) // 2  # every held request uses two nginx connections
        if budget > capacity:
            optional.append(
                f"tarpit_connection_budget {budget} is above what nginx can hold ({capacity}: "
                f"{processes} workers x {connections} connections, halved)"
            )
    detail = {"required": required, "optional": optional, "tarpit_budget": budget, "nginx_capacity": capacity}
    if required:
        value = "; ".join(required)
        finding = "nginx is missing a required header or answer, so a protection the plan relies on is off."
        return env.result(Status.FAIL, value, finding=finding, detail=detail)
    if optional:
        value = "; ".join(optional)
        finding = "Everything required is in place; an optional setting disagrees with nginx."
        return env.result(Status.WARN, value, finding=finding, detail=detail)
    value = f"HSTS on {hsts_ok} of 3 paths, Server without a version, {probes.INTERNAL_VERSION_PATH} answers 404"
    return env.result(Status.PASS, value, detail=detail)


# ------------------------------------------------------------------------------------------------ recent traffic


def _window(env: CheckEnv, seconds: int) -> Any:
    from roxy.metrics.queries import Window

    now = int(env.now())
    start = now - seconds
    return Window(start - start % 60, now + 60 - now % 60, "minute")


async def _totals(env: CheckEnv, seconds: int, filters: Mapping[str, Any] | None = None) -> dict[str, Any]:
    from roxy.metrics.queries import totals_sync

    window = _window(env, seconds)
    totals: dict[str, Any] = await env.ctx.dbs.metrics.read(lambda conn: totals_sync(conn, window, filters=filters))
    return totals


CALLER_SOURCES: Final = ("roblox", "roxy", "relay", "cache")
UPSTREAM_EGRESSES: Final = ("direct", "credential", "rotator")


async def check_latency(env: CheckEnv) -> CheckResult:
    totals = await _totals(env, LATENCY_WINDOW_S, {"egress": list(UPSTREAM_EGRESSES)})
    p95 = totals.get("p95_ms")
    calls = int(totals.get("upstream_calls") or 0)
    if p95 is None or calls == 0:
        return env.not_applicable("no upstream calls", "No request reached Roblox in the last 15 minutes.")
    status = band_low_good(float(p95), LATENCY_PASS_MS, LATENCY_WARN_MS)
    value = f"{_fmt(float(p95))} ms p95 over {calls} upstream calls (last 15 min)"
    finding = "" if status is Status.PASS else "Roblox answers slowly; callers wait as long, and slots stay taken."
    return env.result(status, value, finding=finding, measured=float(p95), unit="ms", detail={"calls": calls})


async def check_429_rate(env: CheckEnv) -> CheckResult:
    totals = await _totals(env, RATE_WINDOW_S)
    calls = int(totals.get("upstream_calls") or 0)
    count = int(totals.get("roblox_429") or 0)
    if calls == 0:
        return env.not_applicable("no upstream calls", "No request reached Roblox in the last 15 minutes.")
    pct = count * 100.0 / calls
    status = band_low_good(pct, RATE_429_PASS_PCT, RATE_429_WARN_PCT)
    value = f"{_fmt(pct, 2)}% of {calls} upstream calls ({count} Roblox 429s, last 15 min)"
    finding = (
        ""
        if status is Status.PASS
        else "Roblox is rate-limiting Roxy. Open recommendations name the endpoints and the bucket or cache change."
    )
    return env.result(
        status, value, finding=finding, measured=pct, unit="%", detail={"calls": calls, "roblox_429": count}
    )


async def check_err_rate(env: CheckEnv) -> CheckResult:
    totals = await _totals(env, RATE_WINDOW_S, {"source": list(CALLER_SOURCES)})
    requests = int(totals.get("requests") or 0)
    errors = int(totals.get("status_5xx") or 0)
    if requests == 0:
        return env.not_applicable("no requests", "No caller request in the last 15 minutes.")
    pct = errors * 100.0 / requests
    status = band_low_good(pct, ERR_PASS_PCT, ERR_WARN_PCT)
    value = f"{_fmt(pct, 2)}% of {requests} caller requests answered 5xx (last 15 min)"
    finding = "" if status is Status.PASS else "Callers are getting server errors; the Errors view shows which."
    detail = {"requests": requests, "status_5xx": errors}
    return env.result(status, value, finding=finding, measured=pct, unit="%", detail=detail)


async def check_cache_hit(env: CheckEnv) -> CheckResult:
    totals = await _totals(env, CACHE_HIT_WINDOW_S)
    demand = int(totals.get("demand") or 0)
    if demand == 0:
        return env.not_applicable("no requests", "No caller request in the last hour.")
    pct = float(totals.get("avoided") or 0) * 100.0 / demand
    status = Status.PASS if pct > CACHE_HIT_PASS_PCT else Status.WARN  # 13.2: lower is "only warn"
    value = f"{_fmt(pct, 1)}% of {demand} requests avoided an upstream call (last hour)"
    finding = (
        ""
        if status is Status.PASS
        else "Most requests still go to Roblox. Cache rules, TTLs and ignored parameters decide how many are avoided."
    )
    detail = {"demand": demand, "upstream_calls": int(totals.get("upstream_calls") or 0)}
    return env.result(status, value, finding=finding, measured=pct, unit="%", detail=detail)


# ------------------------------------------------------------------------------------------------ storage


async def check_cache_rw(env: CheckEnv) -> CheckResult:
    cache = env.ctx.cache
    shared = getattr(getattr(cache, "store", None), "shared", None)
    if shared is None:
        return env.not_applicable("unknown", "The cache is not running in this worker.")
    from roxy.cache.store import CacheEntry
    from roxy.core.reasons import AuthClass

    nonce = secrets.token_hex(6)
    key = f"roxy-health-check {nonce} !health"
    entry_id = hashlib.sha256(f"roxy-health:{nonce}".encode()).hexdigest()[:24]
    now = int(env.now())
    body = b"roxy health check " + nonce.encode("ascii")
    # Expired at birth and negative: it can never answer a lookup, even in the moment it exists.
    entry = CacheEntry(
        id=entry_id,
        key=key,
        auth_class=AuthClass.ANON,
        method="GET",
        host="health.invalid",
        path="/roxy-health-check",
        status=204,
        body=body,
        content_type=None,
        stored_at=now,
        expires_at=now,
        stale_until=now,
        ttl=0,
        negative=True,
        generation=int(getattr(cache.store, "floor", 0)),
    )
    steps: dict[str, float] = {}
    started = env.mono()
    written = False
    try:
        mark = env.mono()
        written = bool(await shared.write(entry, compress=False))
        steps["write"] = _ms(env.mono() - mark)
        if not written:
            error = str(getattr(getattr(shared, "health", None), "last_error", "") or "")[:120]
            finding = "cache.db refused a write, so new answers are kept in this worker's memory only."
            return env.result(Status.FAIL, "write failed", finding=finding, detail={"error": error})
        mark = env.mono()
        found = await shared.read([entry_id])
        steps["read"] = _ms(env.mono() - mark)
        back = found.entries.get(entry_id)
        if back is None or back.body != body:
            finding = "An entry written to cache.db could not be read back."
            return env.result(Status.FAIL, "read back failed", finding=finding, detail={"steps_ms": steps})
        mark = env.mono()
        removed = await shared.delete_ids([entry_id])
        steps["delete"] = _ms(env.mono() - mark)
        written = removed != 1
    except Exception as exc:  # SharedStateUnavailable, sqlite3 errors: the round trip failed, report it
        finding = "The cache.db round trip failed part way through."
        return env.result(Status.FAIL, f"failed ({type(exc).__name__})", finding=finding, detail={"steps_ms": steps})
    finally:
        if written:
            with contextlib.suppress(Exception):
                await shared.delete_ids([entry_id])
    total = _ms(env.mono() - started)
    status = band_low_good(total, CACHE_RW_PASS_MS, CACHE_RW_WARN_MS)
    value = f"{_fmt(total, 1)} ms for write, read and delete"
    finding = "" if status is Status.PASS else "cache.db is slow: the disk is busy or another process holds a lock."
    rounded = {k: round(v, 2) for k, v in steps.items()}
    return env.result(status, value, finding=finding, measured=total, unit="ms", detail={"steps_ms": rounded})


async def check_db_integrity(env: CheckEnv) -> CheckResult:
    problems: dict[str, list[str]] = {}
    for name in ("control", "hot"):
        found = await env.facts.quick_check(name)
        if found:
            problems[name] = [str(item)[:200] for item in found[:5]]
    if not problems:
        return env.result(Status.PASS, "ok (control.db, hot.db)")
    name, items = next(iter(problems.items()))
    value = f"{name}.db: {items[0]}"
    finding = "PRAGMA quick_check found damage. Stop writes, restore that file from the last backup (runbook)."
    return env.result(Status.FAIL, value, finding=finding, critical=False, detail={"problems": problems})


async def check_db_size(env: CheckEnv) -> CheckResult:
    budget_gb = float(env.setting("storage_total_budget_gb") or 0)
    if budget_gb <= 0:
        return env.not_applicable("no budget", "storage_total_budget_gb is 0.")
    disk = await env.facts.disk_usage()
    total = sum(size + wal for size, wal in disk.files.values())
    budget = budget_gb * 1_000_000_000  # decimal GB, as the catalog's unit says
    pct = total * 100.0 / budget
    status = band_low_good(pct, DB_SIZE_PASS_PCT, DB_SIZE_WARN_PCT)
    value = f"{_fmt(pct)}% of the {_fmt(budget_gb, 1)} GB budget ({_fmt(total / 1e9, 2)} GB)"
    finding = (
        "" if status is Status.PASS else "The databases are close to their budget; retention or caps can shrink them."
    )
    sizes = {name: size + wal for name, (size, wal) in disk.files.items()}
    return env.result(status, value, finding=finding, measured=pct, unit="%", detail={"bytes": sizes})


async def check_wal(env: CheckEnv) -> CheckResult:
    disk = await env.facts.disk_usage()
    if not disk.files:
        return env.not_applicable("unknown", "No database files were found.")
    largest_name, (_size, largest) = max(disk.files.items(), key=lambda item: item[1][1])
    total = sum(wal for _size, wal in disk.files.values())
    status = band_low_good(float(largest), WAL_PASS_BYTES, WAL_WARN_BYTES)
    value = f"{_fmt(largest / MIB)} MiB largest WAL ({largest_name}), {_fmt(total / MIB)} MiB in total"
    finding = (
        ""
        if status is Status.PASS
        else "A WAL file keeps growing: checkpoints cannot keep up, usually because a long read holds them back."
    )
    return env.result(status, value, finding=finding, measured=largest / MIB, unit="MiB")


async def check_disk(env: CheckEnv) -> CheckResult:
    disk = await env.facts.disk_usage()
    if disk.total_bytes <= 0:
        return env.not_applicable("unknown", "The state volume size could not be read.")
    pct = disk.free_bytes * 100.0 / disk.total_bytes
    status = band_high_good(pct, DISK_PASS_FREE_PCT, DISK_WARN_FREE_PCT)
    value = f"{_fmt(pct, 1)}% free ({_fmt(disk.free_bytes / 1e9, 1)} of {_fmt(disk.total_bytes / 1e9, 1)} GB)"
    finding = "" if status is Status.PASS else "The state volume is filling up; SQLite stops writing when it is full."
    return env.result(status, value, finding=finding, measured=pct, unit="% free")


# ------------------------------------------------------------------------------------------------ fleet


async def check_workers(env: CheckEnv) -> CheckResult:
    from roxy.scheduler.heartbeat import HEARTBEAT_STALE_S, fleet_view

    now = env.now()
    pid = env.facts.self_pid()
    rows: list[dict[str, Any]] = await env.ctx.dbs.metrics.read(lambda conn: fleet_view(conn, now, this_pid=pid))
    own = next((row for row in rows if row.get("is_this_worker")), None)
    color = str(own.get("color")) if own is not None and own.get("color") else str(env.ctx.color)
    same = [row for row in rows if str(row.get("color") or "") == color]
    fresh = {int(row["pid"]) for row in same if row.get("fresh")}
    fresh.add(pid)  # the worker running this check is alive, whatever its last heartbeat says
    expected = max(1, int(getattr(env.ctx.env, "workers", 1)))
    count = len(fresh)
    stale = [row for row in same if not row.get("fresh") and int(row["pid"]) != pid]
    value = f"{count} of {expected} {color} workers fresh"
    detail = {"expected": expected, "fresh": count, "stale_rows": len(stale), "stale_after_s": HEARTBEAT_STALE_S}
    if count >= expected:
        return env.result(Status.PASS, value, detail=detail)
    if count <= 1 and expected > 1:
        finding = "Only this worker reports in; the others are frozen or crashed and were not replaced."
        return env.result(Status.FAIL, value, finding=finding, detail=detail)
    finding = f"{expected - count} worker(s) stopped sending heartbeats and no replacement has appeared."
    return env.result(Status.WARN, value, finding=finding, detail=detail)


async def check_leader(env: CheckEnv) -> CheckResult:
    from roxy.scheduler.leader import LEADER_LEASE, LEADER_TTL_S
    from roxy.storage import leases

    current = await env.ctx.dbs.hot.read(lambda conn: leases.holder_epoch(conn, LEADER_LEASE))
    now_ms = int(env.ctx.clock.now_ms())
    if current is None or current[2] <= now_ms:
        ago = "never held" if current is None else f"expired {_fmt((now_ms - current[2]) / 1000)} s ago"
        finding = "No worker holds the leader lease, so rollups, retention, probes and scheduled runs are not running."
        return env.result(Status.FAIL, f"no leader (lease {ago})", finding=finding)
    _holder, epoch, expires_ms = current
    renewed_ago = max(0.0, LEADER_TTL_S - (expires_ms - now_ms) / 1000)
    jobs = await env.facts.leader_jobs()
    now = env.now()
    late: list[str] = []
    failing: list[str] = []
    for job in jobs or ():
        started = job.last_started_at
        if job.interval_s > 0 and started is not None and now - started > JOB_LATE_INTERVALS * job.interval_s:
            late.append(job.name)
        if job.last_ok is False:
            failing.append(job.name)
    detail = {"epoch": epoch, "renewed_ago_s": round(renewed_ago, 1), "late": late, "failing": failing}
    jobs_text = (
        "job status unavailable" if jobs is None else f"{len(jobs)} jobs, {len(late)} late, {len(failing)} failing"
    )
    value = f"lease renewed {_fmt(renewed_ago)} s ago (epoch {epoch}); {jobs_text}"
    problems: list[str] = []
    if renewed_ago >= LEADER_RENEW_WARN_S:
        problems.append("the lease was not renewed on time")
    if late:
        problems.append("late jobs: " + ", ".join(late[:5]))
    if failing:
        problems.append("failing jobs: " + ", ".join(failing[:5]))
    if problems:
        return env.result(
            Status.WARN, value, finding="The leader runs, but " + "; ".join(problems) + ".", detail=detail
        )
    return env.result(Status.PASS, value, detail=detail)


async def check_loop_lag(env: CheckEnv) -> CheckResult:
    samples = await env.facts.loop_lag(LOOP_LAG_WINDOW_S)
    if not samples:
        return env.not_applicable("unknown", "No worker reported its event loop lag in the last 5 minutes.")
    worst_sample = max(samples, key=lambda sample: sample.p99_ms)
    p99 = float(worst_sample.p99_ms)
    status = band_low_good(p99, LOOP_LAG_PASS_MS, LOOP_LAG_WARN_MS)
    value = f"{_fmt(p99)} ms p99, worst of {len(samples)} workers (last 5 min)"
    finding = (
        ""
        if status is Status.PASS
        else "Something blocks a worker's event loop (synchronous work); every request in it waits meanwhile."
    )
    return env.result(status, value, finding=finding, measured=p99, unit="ms", detail={"worker": worst_sample.worker})


# ------------------------------------------------------------------------------------------------ rotator


async def check_rotator_reach(env: CheckEnv) -> CheckResult:
    egress = env.ctx.egress
    if egress is None:
        return env.not_applicable("unknown", "The egress clients are not running in this worker.")
    enabled = bool(env.setting("rotator_enabled"))
    weight = float(env.setting("rotator_weight") or 0)
    rotator = egress.rotator
    if not rotator.configured():
        if enabled and weight > 0:
            finding = "Routing gives the rotator a share of traffic, but no rotator URL is configured."
            return env.result(Status.FAIL, "not configured, weight > 0", finding=finding)
        return env.not_applicable("not configured", "No rotator URL is configured and routing does not use one.")
    if not enabled:
        if weight > 0:
            finding = (
                "The rotator is switched off while rotator_weight is above 0: routing expects a path that is not there."
            )
            return env.result(Status.FAIL, f"disabled while weight is {_fmt(weight)}", finding=finding)
        return env.not_applicable("disabled", "The rotator is switched off and routing gives it no traffic.")
    from roxy.egress.rotator import mask_ip

    started = env.mono()
    probe = await rotator.exit_ip_probe()
    elapsed = _ms(env.mono() - started)
    if probe.error or not probe.exit_ip:
        finding = "The IP echo request through the rotator failed; rotator traffic fails or falls back to direct."
        return env.result(
            Status.FAIL, f"failed after {_fmt(elapsed)} ms", finding=finding, detail={"error": probe.error}
        )
    masked = mask_ip(probe.exit_ip)
    status = Status.PASS if elapsed < ROTATOR_SLOW_MS else Status.WARN
    value = f"ok in {_fmt(elapsed)} ms, exit {masked}"
    finding = "" if status is Status.PASS else "The rotator answers slowly; every rotator call pays this delay."
    return env.result(status, value, finding=finding, measured=elapsed, unit="ms", detail={"exit": masked})


async def check_rotator_session(env: CheckEnv) -> CheckResult:
    egress = env.ctx.egress
    template = str(env.setting("rotator_session_username_template") or "")
    if not template:
        return env.not_applicable(
            "no template", "rotator_session_username_template is empty, so sticky sessions are off."
        )
    if egress is None or not egress.rotator.configured() or not bool(env.setting("rotator_enabled")):
        return env.not_applicable("rotator off", "The rotator is not configured or switched off.")
    rotator = egress.rotator
    first_session, second_session = rotator.new_session_id(), rotator.new_session_id()
    ips: list[str] = []
    for session in (first_session, first_session, second_session):
        probe = await rotator.exit_ip_probe(session)
        if probe.error or not probe.exit_ip:
            finding = "An IP echo request through a rotator session failed, so sessions could not be checked."
            return env.result(Status.FAIL, "probe failed", finding=finding, detail={"error": probe.error})
        ips.append(probe.exit_ip)
    sticky = ips[0] == ips[1]
    distinct = ips[2] != ips[0]
    if sticky and distinct:
        return env.result(Status.PASS, "same exit for one session, a different exit for a second session")
    if not sticky:
        finding = "One session id got two different exit addresses: the provider is not keeping sessions sticky."
        return env.result(Status.WARN, "session not sticky", finding=finding)
    finding = (
        "Two session ids got the same exit address: the provider ignores the session parameter, so a burned exit "
        "cannot be dropped (sticky_until_429). Check the username template against the provider's format."
    )
    return env.result(Status.WARN, "same exit for two sessions", finding=finding)


def _next_cycle(start_s: int, billing_day: int) -> int:
    start = datetime.fromtimestamp(start_s, tz=UTC)
    day = min(max(int(billing_day), 1), 28)
    month = start.month + 1
    year = start.year + (1 if month > 12 else 0)
    month = 1 if month > 12 else month
    return int(start.replace(year=year, month=month, day=day).timestamp())


async def check_rotator_quota(env: CheckEnv) -> CheckResult:
    if not bool(env.setting("rotator_enabled")) and float(env.setting("rotator_weight") or 0) <= 0:
        return env.not_applicable("rotator off", "The rotator is switched off and carries no traffic.")
    quota_gb = float(env.setting("rotator_quota_gb_per_month") or 0)
    if quota_gb <= 0:
        return env.not_applicable(
            "quota unknown", "rotator_quota_gb_per_month is 0 (unknown), so there is nothing to compare."
        )
    from roxy.egress.rotator import DECIMAL_GB, cycle_start_for, usage_since

    now = env.now()
    billing_day = int(env.setting("rotator_billing_day") or 1)
    start = cycle_start_for(now, billing_day)
    end = _next_cycle(start, billing_day)
    used: int = await env.ctx.dbs.metrics.read(lambda conn: usage_since(conn, "rotator", start))
    quota = quota_gb * DECIMAL_GB
    remaining_pct = (quota - used) * 100.0 / quota
    elapsed_days = max(0.0, (now - start) / 86_400)
    cycle_days = (end - start) / 86_400
    projected = used / elapsed_days * cycle_days if elapsed_days >= QUOTA_MIN_DAYS_FOR_PROJECTION else None
    status = band_high_good(remaining_pct, QUOTA_PASS_PCT, QUOTA_WARN_PCT)
    overrun = projected is not None and projected > quota
    if overrun:
        status = Status.FAIL
    projected_text = "no projection yet" if projected is None else f"projected {_fmt(projected / 1e9, 1)} GB"
    value = f"{_fmt(remaining_pct)}% remaining ({_fmt(used / 1e9, 2)} of {_fmt(quota_gb, 1)} GB used), {projected_text}"
    finding = ""
    if overrun:
        finding = "At this cycle's pace the rotator will use more than the monthly quota before the cycle ends."
    elif status is not Status.PASS:
        finding = "Little rotator quota is left this cycle; rotator traffic stops at the hard stop."
    price = float(env.setting("rotator_price_per_gb_usd") or 0)
    detail = {
        "used_bytes": used,
        "quota_bytes": int(quota),
        "projected_bytes": None if projected is None else int(projected),
        "cycle_start": start,
        "cycle_end": end,
        "projected_cost_usd": None if projected is None or not price else round(projected / 1e9 * price, 2),
    }
    return env.result(status, value, finding=finding, measured=remaining_pct, unit="% remaining", detail=detail)


# ------------------------------------------------------------------------------------------------ system


def _key_values(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


_SYSTEMD_TIME = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\s+([A-Za-z]+))?")


def parse_systemd_time(text: str) -> float | None:
    """Unix seconds from a systemd timestamp (`Tue 2026-10-06 15:00:00 UTC` or `@1759762800`), None if absent."""
    value = text.strip()
    if not value or value == "n/a":
        return None
    if value.startswith("@"):
        try:
            return float(value[1:])
        except ValueError:
            return None
    match = _SYSTEMD_TIME.search(value)
    if match is None:
        return None
    moment = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
    zone = (match.group(2) or "").upper()
    if zone in ("UTC", "GMT", ""):
        return moment.replace(tzinfo=UTC).timestamp()
    return time.mktime(moment.timetuple())  # the server's local zone (systemd prints local time)


async def check_systemd(env: CheckEnv) -> CheckResult:
    color = str(env.ctx.color)
    if color not in ("blue", "green"):
        return env.not_applicable(
            "not under systemd", "This worker is not a blue or green systemd service (development)."
        )
    argv = ("systemctl", "show", *UNITS, "-p", "ActiveState,NRestarts,ExecMainStartTimestamp")
    command = await env.facts.run_command(argv, COMMAND_TIMEOUT_S)
    blocks = [block for block in re.split(r"\n\s*\n", command.stdout.strip()) if block.strip()]
    if command.returncode != 0 or len(blocks) != len(UNITS):
        return env.not_applicable("unreadable", "systemctl show could not be read here.", returncode=command.returncode)
    now = env.now()
    units: dict[str, dict[str, str]] = {unit: _key_values(block) for unit, block in zip(UNITS, blocks, strict=True)}
    parts: list[str] = []
    failed: list[str] = []
    restarted: list[str] = []
    own = f"roxy@{color}"
    for unit, props in units.items():
        state = props.get("ActiveState", "unknown")
        restarts = int(props.get("NRestarts", "0") or 0) if props.get("NRestarts", "0").isdigit() else 0
        parts.append(f"{unit} {state} ({restarts} restarts)")
        if state == "failed":
            failed.append(unit)
        started = parse_systemd_time(props.get("ExecMainStartTimestamp", ""))
        if state == "active" and restarts > 0 and started is not None and now - started < SYSTEMD_RESTART_WINDOW_S:
            restarted.append(unit)
    own_state = units[own].get("ActiveState", "unknown")
    value = ", ".join(parts)
    detail = {"units": {unit: props.get("ActiveState") for unit, props in units.items()}}
    if failed:
        finding = (
            f"{', '.join(failed)} is in the failed state (crash loop or start limit). Run "
            "`systemctl reset-failed` after reading its journal; a deploy cannot use that color until then."
        )
        return env.result(Status.FAIL, value, finding=finding, detail=detail)
    if own_state not in ("active", "reloading"):
        return env.result(Status.WARN, value, finding=f"{own} reports {own_state}.", detail=detail)
    if restarted:
        finding = f"{', '.join(restarted)} restarted in the last 24 hours (Restart=on-failure after a crash)."
        return env.result(Status.WARN, value, finding=finding, detail=detail)
    return env.result(Status.PASS, value, detail=detail)


def _octal(text: object) -> int | None:
    try:
        return int(str(text), 8)
    except (TypeError, ValueError):
        return None


SECRET_PREFIXES: Final = ("/etc/roxy/credentials", "/var/backups/roxy")


async def check_secrets_perms(env: CheckEnv) -> CheckResult:
    path = env.facts.perms_path()
    document = await asyncio.to_thread(read_json_file, path)
    if document is None or not isinstance(document, dict):
        if env.development:
            return env.not_applicable("no audit result", "roxy-audit does not run in development.")
        finding = "roxy-audit.service has not written perms.json (or it is unreadable); the permissions are unknown."
        return env.result(Status.WARN, "no audit result", finding=finding)
    try:
        mtime: float | None = await asyncio.to_thread(lambda: os.stat(path).st_mtime)
    except OSError:
        mtime = None
    raw_checked = document.get("checked_at", document.get("generated_at"))
    checked = float(raw_checked) if isinstance(raw_checked, int | float) else parse_iso_time(raw_checked)
    stamps = [stamp for stamp in (checked, mtime) if stamp is not None]
    age = env.now() - min(stamps) if stamps else None
    loose_secret: list[str] = []
    loose_other: list[str] = []
    entries = 0
    for item in document.get("results") or ():
        if not isinstance(item, dict):
            continue
        entries += 1
        mode, expected = _octal(item.get("mode")), _octal(item.get("expected"))
        if mode is None or expected is None or not mode & ~expected:
            continue
        line = f"{item.get('path')} {item.get('mode')} (expected {item.get('expected')})"
        (loose_secret if item.get("secret") else loose_other).append(line)
    for item in document.get("findings") or ():  # the roxy.perms/1 shape written by deploy/tools/roxy-audit.py
        if not isinstance(item, dict):
            continue
        entries += 1
        if item.get("ok", True):
            continue
        where = str(item.get("path", ""))
        line = f"{where}: {'; '.join(str(p) for p in item.get('problems') or ())}"[:200]
        secret = any(where.startswith(prefix) for prefix in SECRET_PREFIXES)
        (loose_secret if secret else loose_other).append(line)
    age_text = "unknown age" if age is None else f"{_fmt(age / 3600, 1)} h old"
    detail = {"entries": entries, "loose_secret": loose_secret[:10], "loose_other": loose_other[:10]}
    if loose_secret:
        value = f"{age_text}; looser on a secret: {loose_secret[0]}"
        finding = "A secret file or directory is readable by more accounts than it should be. Fix the mode now."
        return env.result(Status.FAIL, value, finding=finding, measured=age, unit="s", detail=detail)
    stale = age is None or age >= PERMS_MAX_AGE_S
    if loose_other or stale:
        reason = f"looser on a non-secret: {loose_other[0]}" if loose_other else "the audit result is stale"
        finding = (
            "A non-secret file is looser than expected."
            if loose_other
            else "roxy-audit.timer runs every 6 hours; a result older than 7 hours means it stopped."
        )
        return env.result(Status.WARN, f"{age_text}; {reason}", finding=finding, measured=age, unit="s", detail=detail)
    return env.result(Status.PASS, f"{age_text}; {entries} paths as expected", measured=age, unit="s", detail=detail)


async def check_backup(env: CheckEnv) -> CheckResult:
    facts = await env.facts.backup_status()
    if not facts.known:
        if env.development:
            return env.not_applicable("no backup record", "roxy-backup does not run in development.")
        finding = "No backup has ever been recorded (backup.json is missing)."
        return env.result(Status.FAIL, "never", finding=finding)
    if facts.last_success_at is None:
        finding = "No backup has completed yet."
        if facts.last_failure_at is not None:
            finding += f" The last attempt failed at step {facts.last_failure_step or 'unknown'}."
        return env.result(Status.FAIL, "never", finding=finding, detail={"restore_test": facts.restore_test})
    hours = max(0.0, (env.now() - facts.last_success_at) / 3600)
    status = band_low_good(hours, BACKUP_PASS_H, BACKUP_WARN_H)
    restore = {"pass": "restore test passed", "fail": "restore test FAILED", "skipped": "restore drill is manual",
               "never": "no restore test yet"}.get(facts.restore_test, facts.restore_test)  # fmt: skip
    if facts.restore_test == "fail":
        status = Status.FAIL
    value = f"{_fmt(hours)} h since the last backup; {restore}"
    finding = ""
    if facts.restore_test == "fail":
        finding = "The last restore test failed: the backups may not be usable."
    elif status is not Status.PASS:
        finding = "The nightly backup did not complete on time."
    detail = {"restore_test": facts.restore_test, "last_failure_step": facts.last_failure_step}
    return env.result(status, value, finding=finding, measured=hours, unit="h", detail=detail)


async def check_version(env: CheckEnv) -> CheckResult:
    running = str(getattr(env.ctx, "release", "") or "")
    facts = await env.facts.version_facts()
    if not facts.deployed_sha:
        return env.not_applicable(f"running {running[:12] or 'unknown'}", "No deploy has recorded a version here.")
    deployed = facts.deployed_sha.strip()
    match = bool(running) and (running.startswith(deployed) or deployed.startswith(running))
    advisories = facts.advisories
    advisory_text = "advisories not recorded" if advisories is None else f"{advisories} known advisories"
    value = f"running {running[:12]}, deployed {deployed[:12]}; {advisory_text}"
    detail = {"running": running[:40], "deployed": deployed[:40], "advisories": advisories}
    if not match:
        finding = "This worker does not run the release the last deploy recorded (a switch that did not take)."
        return env.result(Status.FAIL, value, finding=finding, detail=detail)
    if advisories:
        finding = "The dependency audit recorded at deploy lists known vulnerabilities; update the lock file."
        return env.result(Status.WARN, value, finding=finding, detail=detail)
    return env.result(Status.PASS, value, detail=detail)


# ------------------------------------------------------------------------------------------------ configuration


PATTERN_TABLES: Final[tuple[tuple[str, bool], ...]] = (
    ("rules_endpoint_block", False),
    ("rules_endpoint_limit", False),
    ("rules_cache", False),
    ("rules_routing", False),
    ("credential_allowlist", True),
)
RULE_ROWS_MAX: Final = 20_000


def _config_rows(conn: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"settings": conn.execute("SELECT key, value_json FROM settings LIMIT 5000").fetchall()}
    for table, _exact in PATTERN_TABLES:
        out[table] = conn.execute(
            f"SELECT id, pattern, type FROM {table} WHERE enabled = 1 LIMIT {RULE_ROWS_MAX}"  # noqa: S608 (fixed names)
        ).fetchall()
    out["ignored_paths"] = conn.execute(f"SELECT pattern FROM ignored_paths LIMIT {RULE_ROWS_MAX}").fetchall()  # noqa: S608
    for table in ("rules_user_agent", "rules_header"):
        out[table] = conn.execute(
            f"SELECT id, needle FROM {table} WHERE mode = 'regex' AND enabled = 1 LIMIT {RULE_ROWS_MAX}"  # noqa: S608
        ).fetchall()
    return out


async def check_config(env: CheckEnv) -> CheckResult:
    from roxy.config import catalog

    rows = await env.ctx.dbs.control.read(_config_rows)
    errors: list[str] = []
    warnings: list[str] = []
    overrides: dict[str, Any] = {}
    for raw_key, value_json in rows["settings"]:
        key = raw_key if raw_key in catalog.CATALOG else catalog.ALIASES.get(raw_key, raw_key)
        spec = catalog.CATALOG.get(key)
        if spec is None:
            warnings.append(f"unknown stored setting {str(raw_key)[:60]} (ignored by the runtime)")
            continue
        try:
            overrides[key] = catalog.validate_spec_value(spec, json.loads(value_json))
        except (ValueError, TypeError) as exc:
            errors.append(f"{key}: {str(exc)[:120]}")
    for issue in catalog.validate_cross(overrides) if overrides else []:
        errors.append(str(getattr(issue, "message", issue))[:200])
    for table, exact in PATTERN_TABLES:
        for row_id, pattern, kind in rows[table]:
            if not env.facts.rule_compiles(table, row_id, str(pattern), str(kind or "glob"), exact=exact):
                errors.append(f"{table} rule {row_id} does not compile")
    for (pattern,) in rows["ignored_paths"]:
        if not env.facts.rule_compiles("ignored_paths", pattern, str(pattern), "glob"):
            errors.append(f"ignored path {str(pattern)[:60]} does not compile")
    for table in ("rules_user_agent", "rules_header"):
        for row_id, needle in rows[table]:
            if not env.facts.rule_compiles(table, row_id, str(needle), "text_regex"):
                errors.append(f"{table} rule {row_id} does not compile")
    rules = getattr(env.ctx, "rules", None)
    for invalid in getattr(getattr(rules, "snapshot", None), "invalid_rows", ()) or ():
        errors.append(f"rule row {invalid} does not fit its table and is ignored")
    detail = {"errors": errors[:20], "warnings": warnings[:20], "overrides": len(overrides)}
    if errors:
        value = f"{len(errors)} errors: {errors[0]}"
        finding = "Some stored configuration cannot be applied as written; the runtime falls back or ignores it."
        return env.result(Status.FAIL, value, finding=finding, detail=detail)
    if warnings:
        value = f"{len(warnings)} warnings: {warnings[0]}"
        return env.result(
            Status.WARN, value, finding="Nothing is misconfigured, but stored rows are ignored.", detail=detail
        )
    return env.result(Status.PASS, f"0 issues ({len(overrides)} overrides, every rule compiles)", detail=detail)


def _network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


def _bans_rows(conn: Any, now: int) -> dict[str, Any]:
    return {
        "bans": conn.execute(
            "SELECT id, subject_type, subject, reason_text FROM bans WHERE expires_at IS NULL OR expires_at > ? "
            "ORDER BY id LIMIT 50000",
            (now,),
        ).fetchall(),
        "access": conn.execute(
            "SELECT id, kind, cidr FROM access_list WHERE (expires_at IS NULL OR expires_at > ?) "
            "AND kind IN ('bypass', 'allow_admin') LIMIT 10000",
            (now,),
        ).fetchall(),
    }


def _metrics_for_bans(conn: Any, now: float) -> dict[str, Any]:
    from roxy.metrics.queries import Page, Window, client_table_sync

    start = int(now) - 86_400
    window = Window(start - start % 60, int(now) + 60 - int(now) % 60, "minute")
    places = client_table_sync(conn, window, "place", now=now, page=Page(size=100, sort="served"))["rows"]
    logins = conn.execute(
        "SELECT detail_json FROM events WHERE type = 'login' AND at_ms >= ? ORDER BY id DESC LIMIT 1000",
        (int((now - ADMIN_LOGIN_LOOKBACK_S) * 1000),),
    ).fetchall()
    return {"places": places, "logins": [row[0] for row in logins]}


async def check_bans(env: CheckEnv) -> CheckResult:
    now = env.now()
    control = await env.ctx.dbs.control.read(lambda conn: _bans_rows(conn, int(now)))
    metrics = await env.ctx.dbs.metrics.read(lambda conn: _metrics_for_bans(conn, now))
    bypass = [_network(row[2]) for row in control["access"] if row[1] == "bypass"]
    admin_nets = [_network(row[2]) for row in control["access"] if row[1] == "allow_admin"]
    admin_ips: set[str] = set()
    for text in metrics["logins"]:
        with contextlib.suppress(TypeError, ValueError):
            detail = json.loads(text or "{}")
            if isinstance(detail, dict) and detail.get("successful") and detail.get("ip"):
                admin_ips.add(str(detail["ip"]))
    if env.options.admin_ip:
        admin_ips.add(env.options.admin_ip)
    admin_points = [_network(ip) for ip in admin_ips]
    served_total = sum(int(row.get("served") or 0) for row in metrics["places"]) or 1
    top_places = {
        str(row["key"])
        for row in metrics["places"][:TOP_PLACES]
        if int(row.get("served") or 0) / served_total >= TOP_PLACE_MIN_SHARE
        and row.get("key") not in (None, "", "other")
    }
    conflicts: list[str] = []
    suspicious: list[str] = []
    for ban_id, subject_type, subject, reason_text in control["bans"]:
        if subject_type in ("ip", "cidr"):
            network = _network(subject)
            if network is None:
                continue
            if any(n is not None and n.version == network.version and n.overlaps(network) for n in bypass):
                conflicts.append(f"ban {ban_id} covers a bypass entry")
            if any(
                n is not None and n.version == network.version and n.overlaps(network)
                for n in admin_nets + admin_points
            ):
                conflicts.append(f"ban {ban_id} covers an admin address")
            wide = BAN_WIDE_PREFIX_V4 if network.version == 4 else BAN_WIDE_PREFIX_V6
            if network.prefixlen < wide and not str(reason_text or "").strip():
                suspicious.append(f"ban {ban_id} is a /{network.prefixlen} without a note")
        elif subject_type == "place" and str(subject) in top_places:
            conflicts.append(f"ban {ban_id} covers a top place by served traffic")
    detail = {"active_bans": len(control["bans"]), "conflicts": conflicts[:20], "suspicious": suspicious[:20]}
    if conflicts:
        finding = "A ban refuses traffic that must never be refused (bans are checked before bypass)."
        return env.result(Status.FAIL, f"{len(conflicts)} conflicting: {conflicts[0]}", finding=finding, detail=detail)
    if suspicious:
        finding = "A very wide ban without a note is easy to forget; write down why it exists."
        return env.result(Status.WARN, f"{len(suspicious)} suspicious: {suspicious[0]}", finding=finding, detail=detail)
    return env.result(Status.PASS, f"0 issues in {len(control['bans'])} active bans", detail=detail)


# ------------------------------------------------------------------------------------------------ alerts


async def check_alerts(env: CheckEnv) -> CheckResult:
    channels = await env.facts.alert_channels(
        webhook_enabled=bool(env.setting("alert_webhook_enabled")), timeout_s=ALERT_TIMEOUT_S
    )
    parts: list[str] = []
    up = down = untestable = 0
    if channels.email is not None:
        email = channels.email
        if email.ok:
            up += 1
            parts.append("email ok")
        else:
            down += 1
            steps = (("connect", email.connect), ("login", email.login), ("noop", email.noop))
            step, state = next((name, value) for name, value in steps if value != "ok")
            parts.append(f"email down ({step} {state})")
    for hook in channels.webhooks:
        if not hook.testable:
            untestable += 1
            parts.append(f"webhook ({hook.provider}) not testable without sending")
        elif hook.ok:
            up += 1
            parts.append(f"webhook ({hook.provider}) ok")
        else:
            down += 1
            why = f"HTTP {hook.status}" if hook.status is not None else (hook.error or "no answer")
            parts.append(f"webhook ({hook.provider}) down ({why})")
    configured = up + down + untestable
    value = ", ".join(parts) if parts else "no channel configured"
    detail = {"up": up, "down": down, "untestable": untestable}
    if configured == 0 or (up == 0 and untestable == 0):
        finding = "No alert can reach you right now: every configured channel failed its test (nothing was sent)."
        return env.result(Status.FAIL, value, finding=finding, detail=detail)
    if down or untestable:
        finding = (
            "One alert channel is down."
            if down
            else "A webhook provider cannot be tested without posting; use Send test alert on Settings > Alerts."
        )
        return env.result(Status.WARN, value, finding=finding, detail=detail)
    return env.result(Status.PASS, value, detail=detail)


# ------------------------------------------------------------------------------------------------ the catalog


def _spec(
    check_id: str,
    title: str,
    measures: str,
    thresholds: str,
    fix_link: str,
    fix_label: str,
    explanation: str,
    kind: CheckKind,
    fn: Any,
    *,
    timeout_s: float | None = None,
    uses_credential: bool = False,
    placeholder: str = "",
) -> CheckSpec:
    default = {
        CheckKind.LOCAL: TIMEOUT_LOCAL_S,
        CheckKind.UPSTREAM: TIMEOUT_UPSTREAM_S,
        CheckKind.CREDENTIAL: TIMEOUT_UPSTREAM_S,
        CheckKind.NETWORK: TIMEOUT_NETWORK_S,
        CheckKind.SYSTEM: TIMEOUT_SYSTEM_S,
    }[kind]
    return CheckSpec(
        id=check_id,
        title=title,
        measures=measures,
        thresholds=thresholds,
        fix_link=fix_link,
        fix_label=fix_label,
        explanation=explanation,
        kind=kind,
        timeout_s=timeout_s or default,
        fn=fn,
        uses_credential=uses_credential,
        placeholder=placeholder,
    )


SPECS: Final[tuple[CheckSpec, ...]] = (
    _spec(
        "H-CRED-PRESENT", "Credential configured", "present or not", "pass: present; fail: absent",
        "/admin/credential#status", "Credential page",
        "Roxy keeps exactly one Roblox credential (plan C1). Allowlisted endpoints and the credential probes need it.",
        CheckKind.LOCAL, check_cred_present,
    ),
    _spec(
        "H-CRED-AUTH", "Credential valid and authenticated",
        "GET users.roblox.com/v1/users/authenticated through the credential path, account compared with the record",
        "pass: 200 and the same account; warn: 429 (rate limited, not expired); fail: 401 or 403, or another account",
        "/admin/credential#status", "Credential page (runbook: Credential rejected)",
        "One call on the account through the credential path (never the rotator) confirms it is still signed in and "
        "still the account recorded when it was set.",
        CheckKind.CREDENTIAL, check_cred_auth, uses_credential=True,
    ),
    _spec(
        "H-CRED-COOLDOWN", "Credential not cooling down", "remaining credential cooldown",
        "pass: 0 s; warn: under 60 s; fail: 60 s or more", "/admin/upstream#cooldowns", "Upstream page",
        "After Roblox rate-limits the account, Roxy pauses every credential call fleet-wide until the cooldown ends.",
        CheckKind.LOCAL, check_cred_cooldown,
    ),
    _spec(
        "H-CRED-GUARD", "Leak guard self-test",
        "the guard blocks a synthetic credential-bearing rotator request in-process (never sent)",
        "pass: blocked; fail: not blocked (critical)", "/admin/help/runbooks#leak-guard", "Runbook: Leak guard",
        "The leak guard is the last defense that keeps the credential off the rotator and the anonymous path (C2).",
        CheckKind.LOCAL, check_cred_guard,
    ),
    _spec(
        "H-ENV-PROXY", "No proxy variables leak into clients",
        "HTTPS_PROXY, HTTP_PROXY, ALL_PROXY and SSLKEYLOGFILE in the service environment; trust_env on the clients",
        "pass: unset; warn: set but ignored; fail: clients honoring them", "/admin/help/operations#environment",
        "Ops docs",
        "Every outbound client ignores proxy variables (trust_env off) and never writes TLS keys, so the credential "
        "cannot leave through a proxy Roxy does not control.",
        CheckKind.LOCAL, check_env_proxy,
    ),
    _spec(
        "H-DNS", "DNS resolution for each allowed Roblox host", "slowest resolution time, public addresses",
        "pass: under 100 ms; warn: under 500 ms; fail: 500 ms or more, a failure or a private address",
        "/admin/help/runbooks#dns", "Runbook: DNS",
        "Every allowed Roblox host must resolve quickly to public addresses (plan 9.10 refuses private ones).",
        CheckKind.NETWORK, check_dns,
    ),
    _spec(
        "H-TLS", "TLS handshake to each allowed Roblox host", "handshake time, certificate days left",
        "pass: every handshake ok and more than 14 days left; warn: 14 days or fewer; fail: a failed handshake",
        "/admin/help/runbooks#tls", "Runbook: TLS",
        "A handshake to every allowed host proves the CA bundle, the network path and Roblox's certificates.",
        CheckKind.NETWORK, check_tls,
    ),
    _spec(
        "H-REACH-<host>", "Upstream reachability per Roblox host",
        "status and latency of the 13.4 probe (anonymous, cache bypassed, through the buckets)",
        "pass: expected status under 800 ms; warn: under 2000 ms or a 429; fail: anything else",
        "/admin/upstream#hosts", "Upstream page",
        "One cheap public request per allowed host, paced by the same buckets as callers, shows which Roblox "
        "service is down or slow.",
        CheckKind.UPSTREAM, check_reach, placeholder="host",
    ),
    _spec(
        "H-E2E", "End to end through the public pipeline",
        "two requests through nginx and Roxy: statuses, Roxy-Cache transition, Roxy-Request-Id, security headers",
        "pass: all as expected; warn: the cache did not transition; fail: non-2xx or missing headers",
        "/admin/help/operations#end-to-end", "Cache page and Ops docs",
        "The same request a game server makes, sent twice to the public address, exercises nginx, the proxy "
        "pipeline, the cache and Roblox together.",
        CheckKind.NETWORK, check_e2e,
    ),
    _spec(
        "H-LATENCY", "Recent upstream latency", "p95 of requests that called Roblox, last 15 minutes",
        "pass: under 1000 ms; warn: under 2500 ms; fail: higher", "/admin/upstream", "Upstream page",
        "How long requests that went to Roblox took recently (bucketed histograms, accurate to within a bucket).",
        CheckKind.LOCAL, check_latency,
    ),
    _spec(
        "H-429-RATE", "Recent Roblox 429 rate", "Roblox 429s as a share of upstream calls, last 15 minutes",
        "pass: under 0.5%; warn: under 2%; fail: 2% or more", "/admin/recommendations", "Recommendations",
        "Every Roblox 429 is logged; a rising share means Roxy is calling Roblox too fast for some endpoints.",
        CheckKind.LOCAL, check_429_rate,
    ),
    _spec(
        "H-ERR-RATE", "Recent caller-facing 5xx rate", "share of caller requests answered 5xx, last 15 minutes",
        "pass: under 0.5%; warn: under 2%; fail: 2% or more", "/admin/system#errors", "Errors page",
        "What callers actually received: stale serves after an upstream error and Roxy's own 429s are not 5xx.",
        CheckKind.LOCAL, check_err_rate,
    ),
    _spec(
        "H-CACHE-RW", "Cache write, read, delete round trip", "round trip time on cache.db",
        "pass: ok under 20 ms; warn: under 200 ms; fail: a failed step", "/admin/system#storage", "System page",
        "A throwaway entry is written to cache.db, read back and deleted; it can never answer a request.",
        CheckKind.LOCAL, check_cache_rw,
    ),
    _spec(
        "H-CACHE-HIT", "Cache effectiveness", "share of caller requests that avoided an upstream call, last hour",
        "pass: over 30%; warn: 30% or lower (only warns)", "/admin/cache#settings", "Cache page",
        "Avoided calls are requests minus upstream calls (plan P6); a low share means Roblox sees most traffic.",
        CheckKind.LOCAL, check_cache_hit,
    ),
    _spec(
        "H-DB-INTEGRITY", "Database integrity", "PRAGMA quick_check on control.db and hot.db",
        "pass: ok; fail: errors", "/admin/help/runbooks#database-corrupt", "Runbook: Database corrupt",
        "quick_check reads every page of the two databases that hold settings, rules and shared limits.",
        CheckKind.LOCAL, check_db_integrity,
    ),
    _spec(
        "H-DB-SIZE", "Database sizes vs budget", "database files with their WAL files, share of the budget",
        "pass: under 70%; warn: under 90%; fail: 90% or more", "/admin/data#retention", "Data page",
        "Every table has a cap and a retention period; storage_total_budget_gb is the ceiling for all of them.",
        CheckKind.LOCAL, check_db_size,
    ),
    _spec(
        "H-WAL", "WAL sizes", "largest WAL file", "pass: under 64 MiB; warn: under 256 MiB; fail: higher",
        "/admin/system#storage", "System page",
        "Write-ahead logs are folded back into their databases by checkpoints; a large one means they lag.",
        CheckKind.LOCAL, check_wal,
    ),
    _spec(
        "H-DISK", "Free disk space on the state volume", "free share of the volume",
        "pass: over 25% free; warn: over 10%; fail: 10% or less", "/admin/system#storage", "System page",
        "SQLite needs free space for its WAL and for VACUUM; a full volume stops every write.",
        CheckKind.LOCAL, check_disk,
    ),
    _spec(
        "H-WORKERS", "Worker liveness", "fresh heartbeats of this color against ROXY_WORKERS",
        "pass: all fresh; warn: one or more stale; fail: none fresh other than this worker",
        "/admin/system#workers", "System page",
        "Each worker writes a heartbeat every 5 s; one older than 20 s is stale (frozen or crashed).",
        CheckKind.LOCAL, check_workers,
    ),
    _spec(
        "H-LEADER", "Scheduler leader alive", "leader lease age, last job run times",
        "pass: renewed under 10 s ago and jobs on time; warn: late or failing jobs; fail: no leader",
        "/admin/system#jobs", "System page",
        "One worker in the fleet holds the leader lease and runs rollups, retention, probes and scheduled runs.",
        CheckKind.LOCAL, check_leader,
    ),
    _spec(
        "H-LOOP-LAG", "Event loop lag", "worst worker's loop lag p99, last 5 minutes",
        "pass: under 50 ms; warn: under 200 ms; fail: higher", "/admin/system#workers", "System page",
        "How late each worker's event loop wakes up; synchronous work on the loop delays every request in it.",
        CheckKind.LOCAL, check_loop_lag,
    ),
    _spec(
        "H-ROTATOR-REACH", "Rotator reachable", "IP echo through the rotator: status, latency, exit IP (masked)",
        "pass: ok; warn: slow (2000 ms or more); fail: failure, or disabled while rotator_weight is above 0",
        "/admin/egress#rotator", "Egress page",
        "An IP echo request through the rotator proves the proxy gateway accepts Roxy's login and answers.",
        CheckKind.NETWORK, check_rotator_reach,
    ),
    _spec(
        "H-ROTATOR-SESSION", "Sticky sessions work",
        "exit IP for two requests with one session id, and for a second session id",
        "pass: same, then different; warn: same IP for different sessions; fail: probe failure",
        "/admin/egress#rotator", "Egress page",
        "With a session username template, one session must keep one exit and a new session must get another.",
        CheckKind.NETWORK, check_rotator_session,
    ),
    _spec(
        "H-ROTATOR-QUOTA", "Remaining rotator quota", "share of the monthly quota left, cycle projection",
        "pass: over 30% left; warn: over 10%; fail: lower, or a projected overrun", "/admin/egress#budget",
        "Egress page",
        "Rotator bytes are metered on the wire; the projection extends this cycle's average to the cycle end.",
        CheckKind.LOCAL, check_rotator_quota,
    ),
    _spec(
        "H-SYSTEMD", "systemd unit status", "ActiveState and NRestarts of roxy@blue and roxy@green",
        "pass: active, no restarts in 24 h; warn: restarts; fail: a failed unit",
        "/admin/help/runbooks#service-down", "Runbooks",
        "Read with systemctl show (an unprivileged property read); the idle color is normally inactive.",
        CheckKind.SYSTEM, check_systemd,
    ),
    _spec(
        "H-NGINX", "nginx reachability and config sanity",
        "HSTS on /, a static asset and /admin; no version in Server; /internal/version 404; tarpit budget",
        "pass: all; warn: an optional item; fail: a required item missing", "/admin/help/operations#nginx",
        "Ops docs",
        "nginx terminates TLS, adds HSTS (the security headers snippet), hides its version and the internal API.",
        CheckKind.NETWORK, check_nginx,
    ),
    _spec(
        "H-TLS-PUBLIC", "Public certificate expiry", "days left on the public certificate",
        "pass: over 21 days; warn: over 7 days; fail: 7 days or fewer, or a failed handshake",
        "/admin/help/runbooks#certificate", "Runbook: Certificate",
        "Certbot renews the public certificate 30 days before it expires.",
        CheckKind.NETWORK, check_tls_public,
    ),
    _spec(
        "H-CLOCK", "Clock skew", "difference to Roblox's Date header, NTP status (timedatectl, if readable)",
        "pass: under 2 s; warn: under 10 s; fail: 10 s or more", "/admin/help/runbooks#clock", "Runbook: Clock",
        "Roxy's time decides TOTP sign-in, cooldowns, cache ages and Retry-After; Roblox's Date header is a check.",
        CheckKind.UPSTREAM, check_clock,
    ),
    _spec(
        "H-CONFIG", "Config validity", "settings within catalog bounds, no contradictions, rules compile",
        "pass: 0 issues; warn: warnings; fail: errors", "/admin/settings", "Settings page",
        "Stored settings and rules are validated again here, as the runtime reads them.",
        CheckKind.LOCAL, check_config,
    ),
    _spec(
        "H-BANS", "Ban list sanity",
        "active bans against bypass entries, admin addresses, top places; wide CIDRs without a note",
        "pass: 0 issues; warn: suspicious; fail: conflicting", "/admin/protection#bans", "Protection page",
        "Bans are checked before bypass, so a ban over a bypass entry or the admin's address refuses them.",
        CheckKind.LOCAL, check_bans,
    ),
    _spec(
        "H-SECRETS-PERMS", "Secret file permissions", "perms.json from roxy-audit.service and its age",
        "pass: as expected and under 7 h old; warn: looser on non-secrets or stale; fail: looser on secrets",
        "/admin/help/runbooks#file-permissions", "Runbook",
        "The roxy user cannot read /etc/roxy/credentials, so a root timer audits modes every 6 hours.",
        CheckKind.SYSTEM, check_secrets_perms,
    ),
    _spec(
        "H-ALERTS", "Alert channel test without sending", "SMTP connect, login and NOOP; Discord webhook GET",
        "pass: ok; warn: one channel down or untestable; fail: all down", "/admin/settings#alerts",
        "Settings > Alerts",
        "Alert channels are tested without sending a message: the mail server is asked to log in and NOOP.",
        CheckKind.NETWORK, check_alerts,
    ),
    _spec(
        "H-BACKUP", "Last backup age and restore test", "hours since the last good backup, restore test result",
        "pass: under 26 h; warn: under 72 h; fail: older, never, or a failed restore test",
        "/admin/help/runbooks#backups", "Runbook: Backups",
        "roxy-backup.service runs nightly and records its result; a restore test runs every 28 days.",
        CheckKind.SYSTEM, check_backup,
    ),
    _spec(
        "H-VERSION", "Running version", "running commit against the deployed one, dependency advisories",
        "pass: match and clean; warn: advisories; fail: mismatch", "/admin/help/operations#deploy", "Deploy docs",
        "Each deploy records the commit it switched to; the running worker must be that release.",
        CheckKind.SYSTEM, check_version,
    ),
)  # fmt: skip

CATALOG: Final[dict[str, CheckSpec]] = {spec.id: spec for spec in SPECS}
ORDER: Final[dict[str, int]] = {spec.id: index for index, spec in enumerate(SPECS)}

RECOMMENDATION_RULES: Final[dict[str, tuple[str, ...]]] = {
    "H-CRED-AUTH": ("CRED-EXPIRING",),
    "H-CRED-GUARD": ("CRED-ROTATOR-GUARD",),
    "H-REACH-<host>": ("UP-5XX", "UP-TIMEOUT", "UP-429-HOST"),
    "H-LATENCY": ("UP-LATENCY", "UP-QUEUE-SAT"),
    "H-429-RATE": ("UP-429-ENDPOINT", "UP-429-HOST", "UP-429-AMPLIFY", "UP-BUCKET-TUNE"),
    "H-ERR-RATE": ("SYS-ERRORS", "UP-5XX", "UP-TIMEOUT"),
    "H-CACHE-HIT": ("CACHE-LOW-HIT", "CACHE-TTL-TUNE", "CACHE-KEYSPLIT", "CACHE-OFF"),
    "H-DB-SIZE": ("SYS-DISK",),
    "H-DISK": ("SYS-DISK",),
    "H-LOOP-LAG": ("SYS-LOOP-LAG",),
    "H-ROTATOR-QUOTA": ("EGR-BURN",),
    "H-CONFIG": ("SEC-DEFAULTS",),
    "H-BANS": ("FILTER-COLLATERAL", "FILTER-REMOVE"),
}
"""Recommendation rules that fix a failing check (the 13.1 "Apply fix" button); SYS-HEALTH-FAIL links to any."""


def sort_key(check_id: str) -> tuple[int, str]:
    """Catalog order for a stored check id (per-host H-REACH results sort with their base check)."""
    base = "H-REACH-<host>" if check_id.startswith("H-REACH-") else check_id
    return ORDER.get(base, len(ORDER)), check_id


def spec_for(check_id: str) -> tuple[CheckSpec, dict[str, str]] | None:
    """The spec and placeholder values of a stored or requested check id (`H-REACH-games.roblox.com`)."""
    if check_id in CATALOG:
        return CATALOG[check_id], {}
    if check_id.startswith("H-REACH-") and len(check_id) > len("H-REACH-"):
        return CATALOG["H-REACH-<host>"], {"host": check_id[len("H-REACH-") :].lower()}
    return None


def expand(ctx: Any, wanted: Sequence[str] = ()) -> list[tuple[CheckSpec, dict[str, str]]]:
    """Every check instance of a run in catalog order: one H-REACH per allowed host (13.2), filtered by `wanted`."""
    hosts = [str(h).strip().lower().rstrip(".") for h in (ctx.settings.get("allowed_roblox_hosts") or ())]
    planned: list[tuple[CheckSpec, dict[str, str]]] = []
    for spec in SPECS:
        if spec.placeholder == "host":
            planned.extend((spec, {"host": host}) for host in dict.fromkeys(h for h in hosts if h))
        else:
            planned.append((spec, {}))
    if not wanted:
        return planned
    chosen = set(wanted)
    return [(spec, params) for spec, params in planned if spec.id in chosen or spec.instance_id(params) in chosen]


def known_check_id(check_id: str) -> bool:
    return spec_for(check_id) is not None


__all__ = [
    "CATALOG",
    "ORDER",
    "RECOMMENDATION_RULES",
    "SPECS",
    "CheckEnv",
    "expand",
    "known_check_id",
    "parse_systemd_time",
    "sort_key",
    "spec_for",
]
