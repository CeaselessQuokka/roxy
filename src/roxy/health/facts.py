"""The health checks' window on the outside world: one replaceable object for DNS, TLS, commands and files.

What this is
    `SystemFacts`, the protocol every check uses for anything outside Roxy's own databases and clients, and
    `LiveFacts`, the production implementation: DNS lookups, TLS handshakes, `systemctl` and `timedatectl`, the
    public origin (nginx), the alert channels (SMTP connect, login and NOOP; a Discord webhook GET), the backup and
    deploy status files, disk usage, `PRAGMA quick_check`, the leader's job status, event loop lag, the address
    classifier, the process environment, and the rule compiler. Plus the small result types they return.

Why it exists
    The checks must be testable without touching any real system (plan 19.12): the fixture harness swaps this one
    object for a fake that answers from YAML. It also keeps the rules for talking to the outside world in one
    place: every client is built with `trust_env=False` and a TLS context that never logs keys
    (`egress.metering.tls_context`), commands are fixed argument lists (never built from input) with a timeout,
    output is bounded, and nothing here ever returns a secret.
    Python's `ipaddress` marks the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
    2001:db8::/32) as private, which is right for production; the classifier is a method so tests can count them
    as public, as the fixture README requires.

How it works
    Every method is either a plain function of local state or a coroutine with its own timeout. Durations are
    measured with `ctx.clock.monotonic()` so a fake clock controls them in tests. Failures are raised as the
    small exception types below (`DnsFailure`, `TlsFailure`, `OriginFailure`) with a short `kind`, never as raw
    library exceptions.

What to read next
    `roxy/health/checks.py` (who calls what), `tests/health/harness.py` (the fixture implementation).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import shutil
import socket
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol
from urllib.parse import urlsplit

import httpx

log = logging.getLogger("roxy.health.facts")

MAX_OUTPUT_BYTES: Final = 64 * 1024
"""Most bytes kept from a command's stdout or stderr, or from an origin answer body (plan P9)."""

MAX_STATUS_FILE_BYTES: Final = 1024 * 1024
"""Largest status file (perms.json, backup.json) read; a bigger one is treated as unreadable."""

ORIGIN_USER_AGENT: Final = "Roxy-HealthCheck/1"
JOB_STATUS_FRESH_S: Final = 180.0
"""Published leader job status older than this is ignored (the leader publishes every 30 s)."""

DEPLOYED_VERSION_FILES: Final[tuple[Path, ...]] = (
    Path("/var/lib/roxy-deploy/deployed_version"),
    Path("/var/lib/roxy/deployed_version"),
)
"""Where `deploy.sh` step 9 records the deployed commit (deploy state first, plan 17.3 layout second)."""

ADVISORY_FILES: Final[tuple[Path, ...]] = (
    Path("/var/lib/roxy-deploy/advisories.json"),
    Path("/var/lib/roxy/audit/advisories.json"),
)
"""The dependency audit recorded at deploy (H-VERSION). Optional: when absent, advisories are "not recorded"."""

SYSTEMCTL_CANDIDATES: Final = ("/usr/bin/systemctl", "/bin/systemctl")
TIMEDATECTL_CANDIDATES: Final = ("/usr/bin/timedatectl", "/bin/timedatectl")


# ------------------------------------------------------------------------------------------------- result types


class DnsFailure(Exception):
    """A lookup that gave no usable answer. `kind`: nxdomain, timeout, servfail or error."""

    def __init__(self, kind: str, detail: str = "") -> None:
        self.kind = kind
        super().__init__(f"{kind}: {detail}"[:200] if detail else kind)


class TlsFailure(Exception):
    """A TLS handshake that did not complete. `kind`: handshake_failed, expired, hostname_mismatch, timeout,
    connect or error."""

    def __init__(self, kind: str, detail: str = "") -> None:
        self.kind = kind
        super().__init__(f"{kind}: {detail}"[:200] if detail else kind)


class OriginFailure(Exception):
    """A request to the public origin that got no HTTP answer. `kind`: timeout, connect, tls or error."""

    def __init__(self, kind: str, detail: str = "") -> None:
        self.kind = kind
        super().__init__(f"{kind}: {detail}"[:200] if detail else kind)


@dataclass(frozen=True, slots=True)
class DnsAnswer:
    addresses: tuple[str, ...]
    latency_ms: float


@dataclass(frozen=True, slots=True)
class TlsAnswer:
    days_left: float
    handshake_ms: float


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class OriginAnswer:
    """One answer of the public origin. `headers` have lowercase names; a header sent twice keeps the last."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    latency_ms: float


@dataclass(frozen=True, slots=True)
class SmtpProbe:
    """Each step is ok, refused, timeout, failed or skipped (an earlier step failed)."""

    connect: str
    login: str
    noop: str

    @property
    def ok(self) -> bool:
        return self.connect == "ok" and self.login == "ok" and self.noop == "ok"


@dataclass(frozen=True, slots=True)
class WebhookProbe:
    """`testable` False for providers that cannot be checked without posting a message (13.2 H-ALERTS)."""

    provider: str
    testable: bool
    status: int | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.testable and self.status is not None and 200 <= self.status < 300


@dataclass(frozen=True, slots=True)
class AlertChannels:
    """The configured channels: `email` None when no mail credentials exist; webhooks only when enabled."""

    email: SmtpProbe | None
    webhooks: tuple[WebhookProbe, ...]


@dataclass(frozen=True, slots=True)
class BackupFacts:
    """What `backup.sh` last recorded (`/var/lib/roxy/audit/backup.json`). `known` False: no record at all.

    `restore_test` is pass, fail, skipped (an encrypted set: the drill is manual) or never.
    """

    known: bool
    last_success_at: float | None = None
    last_failure_at: float | None = None
    last_failure_step: str = ""
    restore_test: str = "never"
    restore_test_at: float | None = None


@dataclass(frozen=True, slots=True)
class VersionFacts:
    """The deployed commit recorded by the deploy (None: never recorded) and its dependency advisories."""

    deployed_sha: str | None
    advisories: int | None


@dataclass(frozen=True, slots=True)
class DiskFacts:
    """The state volume and Roxy's database files: `files` maps a file name to (bytes, WAL bytes)."""

    total_bytes: int
    free_bytes: int
    files: Mapping[str, tuple[int, int]]


@dataclass(frozen=True, slots=True)
class JobFact:
    """One leader job as `JobRunner.status()` reports it (times are Unix seconds)."""

    name: str
    interval_s: float
    last_started_at: float | None
    last_finished_at: float | None
    last_ok: bool | None


@dataclass(frozen=True, slots=True)
class LagSample:
    """The event loop lag p99 of one worker over a recent window."""

    worker: str
    p99_ms: float


# ------------------------------------------------------------------------------------------------- the protocol


class SystemFacts(Protocol):
    """Everything a check may learn from outside Roxy's own clients and databases (see the module docstring)."""

    def environ(self) -> Mapping[str, str]: ...

    def self_pid(self) -> int: ...

    def is_public_address(self, address: str) -> bool: ...

    def perms_path(self) -> Path: ...

    def rule_compiles(self, table: str, row_id: object, pattern: str, kind: str, *, exact: bool = False) -> bool: ...

    async def resolve(self, host: str, timeout_s: float) -> DnsAnswer: ...

    async def tls_probe(self, host: str, port: int, timeout_s: float) -> TlsAnswer: ...

    async def run_command(self, argv: Sequence[str], timeout_s: float) -> CommandResult: ...

    async def origin_fetch(self, path: str, timeout_s: float) -> OriginAnswer: ...

    async def alert_channels(self, *, webhook_enabled: bool, timeout_s: float) -> AlertChannels: ...

    async def backup_status(self) -> BackupFacts: ...

    async def version_facts(self) -> VersionFacts: ...

    async def disk_usage(self) -> DiskFacts: ...

    async def quick_check(self, db_name: str) -> list[str]: ...

    async def leader_jobs(self) -> list[JobFact] | None: ...

    async def loop_lag(self, window_s: float) -> list[LagSample]: ...


# ------------------------------------------------------------------------------------------------- helpers


def is_global_address(address: str) -> bool:
    """Production address classifier: True for globally routable addresses (IPv4-mapped IPv6 unwrapped)."""
    try:
        ip = ipaddress.ip_address(address.strip().split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not ip.is_multicast


def parse_iso_time(text: object) -> float | None:
    """Unix seconds from `2026-10-07T15:00:00Z` (what the root tools write), None when unparsable."""
    if not isinstance(text, str) or not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.timestamp()


def read_json_file(path: Path) -> Any:
    """Parse a small JSON status file; None when missing, too large or not JSON. Never follows a symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_STATUS_FILE_BYTES + 1)
    if len(data) > MAX_STATUS_FILE_BYTES:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _first_line(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            text = handle.read(256)
    except OSError:
        return None
    line = text.strip().splitlines()[0].strip() if text.strip() else ""
    return line or None


def _bounded(data: bytes) -> str:
    return data[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")


def _resolve_tool(candidates: Sequence[str]) -> str | None:
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    found = shutil.which(Path(candidates[0]).name)
    return found or None


def backup_facts_from(document: Any) -> BackupFacts:
    """`BackupFacts` from a parsed `backup.json` (see `deploy/tools/backup.sh`)."""
    if not isinstance(document, dict):
        return BackupFacts(known=False)
    success = document.get("last_success")
    failure = document.get("last_failure")
    restore = document.get("restore_test")
    restore_state = "never"
    restore_at: float | None = None
    if isinstance(restore, dict):
        restore_at = parse_iso_time(restore.get("at"))
        ok = restore.get("ok")
        restore_state = "pass" if ok is True else "fail" if ok is False else "skipped"
    return BackupFacts(
        known=True,
        last_success_at=parse_iso_time(success.get("at")) if isinstance(success, dict) else None,
        last_failure_at=parse_iso_time(failure.get("at")) if isinstance(failure, dict) else None,
        last_failure_step=str(failure.get("step", ""))[:80] if isinstance(failure, dict) else "",
        restore_test=restore_state,
        restore_test_at=restore_at,
    )


def advisories_from(document: Any) -> int | None:
    """The advisory count of a dependency audit record: `{"count": n}`, `{"advisories": [...]}` or a list."""
    if isinstance(document, dict):
        count = document.get("count")
        if isinstance(count, int) and not isinstance(count, bool):
            return max(0, count)
        items = document.get("advisories", document.get("vulnerabilities"))
        if isinstance(items, list):
            return len(items)
        return None
    if isinstance(document, list):
        return len(document)
    return None


# ------------------------------------------------------------------------------------------------- production


class LiveFacts:
    """The production `SystemFacts` for one worker context (see the module docstring)."""

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    # --- local -------------------------------------------------------------------------------------------------

    def environ(self) -> Mapping[str, str]:
        return os.environ

    def self_pid(self) -> int:
        return os.getpid()

    def is_public_address(self, address: str) -> bool:
        return is_global_address(address)

    def _state_dir(self) -> Path:
        return Path(getattr(self._ctx.env, "state_dir", "/var/lib/roxy"))

    def perms_path(self) -> Path:
        return self._state_dir() / "audit" / "perms.json"

    def rule_compiles(self, table: str, row_id: object, pattern: str, kind: str, *, exact: bool = False) -> bool:
        """Whether a stored rule pattern compiles exactly as the matcher would compile it (`rules/match.py`).

        `kind` is the row's `type` (glob or regex) for endpoint patterns, or `text_regex` for a regex needle of a
        User-Agent or header rule.
        """
        from roxy.rules import match

        if kind == "text_regex":
            return match.compile_like_re(pattern) is not None
        return match.compile_pattern(pattern, kind or "glob", exact=exact).valid

    def _mono(self) -> float:
        return float(self._ctx.clock.monotonic())

    # --- network -----------------------------------------------------------------------------------------------

    async def resolve(self, host: str, timeout_s: float) -> DnsAnswer:
        loop = asyncio.get_running_loop()
        started = self._mono()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM), timeout=max(0.1, timeout_s)
            )
        except TimeoutError as exc:
            raise DnsFailure("timeout") from exc
        except socket.gaierror as exc:
            if exc.errno in (getattr(socket, "EAI_NONAME", -2), getattr(socket, "EAI_NODATA", -5)):
                raise DnsFailure("nxdomain") from exc
            if exc.errno == getattr(socket, "EAI_AGAIN", -3):
                raise DnsFailure("servfail") from exc
            raise DnsFailure("error", type(exc).__name__) from exc
        except OSError as exc:
            raise DnsFailure("error", type(exc).__name__) from exc
        latency = (self._mono() - started) * 1000
        addresses = tuple(dict.fromkeys(str(info[4][0]) for info in infos))
        if not addresses:
            raise DnsFailure("nxdomain")
        return DnsAnswer(addresses, latency)

    async def tls_probe(self, host: str, port: int, timeout_s: float) -> TlsAnswer:
        from roxy.egress.metering import tls_context

        context = await asyncio.to_thread(tls_context, True)  # loading the CA bundle reads files: not on the loop
        started = self._mono()
        writer: asyncio.StreamWriter | None = None
        try:
            _reader, opened = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host), timeout=max(0.1, timeout_s)
            )
            writer = opened
            handshake_ms = (self._mono() - started) * 1000
            ssl_object = opened.get_extra_info("ssl_object")
            cert = ssl_object.getpeercert() if ssl_object is not None else None
            not_after = (cert or {}).get("notAfter")
            if not isinstance(not_after, str):
                raise TlsFailure("error", "no certificate expiry")
            days_left = (ssl.cert_time_to_seconds(not_after) - float(self._ctx.clock.now())) / 86_400
            return TlsAnswer(days_left, handshake_ms)
        except TimeoutError as exc:
            raise TlsFailure("timeout") from exc
        except ssl.SSLCertVerificationError as exc:
            code = getattr(exc, "verify_code", None)
            kind = "expired" if code == 10 else "hostname_mismatch" if code == 62 else "handshake_failed"
            raise TlsFailure(kind, str(getattr(exc, "verify_message", ""))[:120]) from exc
        except ssl.SSLError as exc:
            raise TlsFailure("handshake_failed", type(exc).__name__) from exc
        except OSError as exc:
            raise TlsFailure("connect", type(exc).__name__) from exc
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)

    async def run_command(self, argv: Sequence[str], timeout_s: float) -> CommandResult:
        """Run a fixed command (`systemctl show ...`, `timedatectl show`) with a timeout and bounded output."""
        if not argv:
            return CommandResult(127, "", "no command")
        tool = argv[0]
        candidates = (
            SYSTEMCTL_CANDIDATES
            if tool == "systemctl"
            else TIMEDATECTL_CANDIDATES
            if tool == "timedatectl"
            else (tool,)
        )
        resolved = _resolve_tool(candidates)
        if resolved is None:
            return CommandResult(127, "", f"{tool} not found")
        # A minimal environment: the command needs no proxy, locale or credential from the service environment.
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "SYSTEMD_PAGER": ""}
        try:
            process = await asyncio.create_subprocess_exec(
                resolved,
                *argv[1:],
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except OSError as exc:
            return CommandResult(126, "", type(exc).__name__)
        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout=max(0.1, timeout_s))
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            with contextlib.suppress(Exception):
                await process.wait()
            return CommandResult(124, "", "timed out")
        return CommandResult(int(process.returncode or 0), _bounded(out), _bounded(err))

    async def origin_fetch(self, path: str, timeout_s: float) -> OriginAnswer:
        """GET `<ROXY_SITE_ORIGIN><path>` through nginx, exactly as a caller would (no redirects followed)."""
        from roxy.egress.metering import tls_context

        origin = str(getattr(self._ctx.env, "site_origin", "")).rstrip("/")
        context = await asyncio.to_thread(tls_context, True)
        started = self._mono()
        headers_out = {"User-Agent": ORIGIN_USER_AGENT, "Accept": "*/*"}
        try:
            # trust_env=False: a proxy variable in the service environment must never reroute this request.
            async with (
                httpx.AsyncClient(
                    trust_env=False, verify=context, follow_redirects=False, timeout=max(0.1, timeout_s)
                ) as client,
                client.stream("GET", origin + path, headers=headers_out) as response,
            ):
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_OUTPUT_BYTES:
                        break
                headers = {k.lower(): v for k, v in response.headers.items()}
                status = response.status_code
        except httpx.TimeoutException as exc:
            raise OriginFailure("timeout") from exc
        except httpx.ConnectError as exc:
            kind = "tls" if "ssl" in str(exc).lower() or "certificate" in str(exc).lower() else "connect"
            raise OriginFailure(kind, type(exc).__name__) from exc
        except httpx.HTTPError as exc:
            raise OriginFailure("error", type(exc).__name__) from exc
        return OriginAnswer(status, headers, b"".join(chunks)[:MAX_OUTPUT_BYTES], (self._mono() - started) * 1000)

    async def alert_channels(self, *, webhook_enabled: bool, timeout_s: float) -> AlertChannels:
        """Test the alert channels WITHOUT sending anything (13.2 H-ALERTS)."""
        from roxy.notify.mail import load_mail_config
        from roxy.notify.webhook import load_webhook_url

        credentials_dir = getattr(self._ctx.env, "credentials_dir", None)
        config = await asyncio.to_thread(load_mail_config, credentials_dir)
        email = await self._smtp_probe(config, timeout_s) if config is not None else None
        webhooks: list[WebhookProbe] = []
        if webhook_enabled:
            url = await asyncio.to_thread(load_webhook_url, credentials_dir)
            if url is not None:
                webhooks.append(await self._webhook_probe(url, timeout_s))
        return AlertChannels(email, tuple(webhooks))

    async def _smtp_probe(self, config: Any, timeout_s: float) -> SmtpProbe:
        import aiosmtplib

        from roxy.notify.mail import smtp_tls_context

        context = await asyncio.to_thread(smtp_tls_context)
        client = aiosmtplib.SMTP(
            hostname=config.host, port=config.port, use_tls=True, tls_context=context, timeout=max(1.0, timeout_s)
        )
        try:
            await client.connect()
        except (aiosmtplib.SMTPConnectTimeoutError, aiosmtplib.SMTPTimeoutError, TimeoutError):
            return SmtpProbe("timeout", "skipped", "skipped")
        except (aiosmtplib.SMTPConnectError, ConnectionRefusedError):
            return SmtpProbe("refused", "skipped", "skipped")
        except (aiosmtplib.SMTPException, OSError):
            return SmtpProbe("failed", "skipped", "skipped")
        try:
            try:
                await client.login(config.from_addr, config.password.get_secret_value())
            except aiosmtplib.SMTPAuthenticationError:
                return SmtpProbe("ok", "refused", "skipped")
            except (aiosmtplib.SMTPTimeoutError, TimeoutError):
                return SmtpProbe("ok", "timeout", "skipped")
            except (aiosmtplib.SMTPException, OSError):
                return SmtpProbe("ok", "failed", "skipped")
            try:
                await client.noop()
            except (aiosmtplib.SMTPException, OSError, TimeoutError):
                return SmtpProbe("ok", "ok", "failed")
            return SmtpProbe("ok", "ok", "ok")
        finally:
            with contextlib.suppress(Exception):
                await client.quit()

    async def _webhook_probe(self, url: str, timeout_s: float) -> WebhookProbe:
        from roxy.egress.metering import tls_context

        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        discord = host in ("discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com") and (
            parts.path.startswith("/api/webhooks/")
        )
        if not discord:
            return WebhookProbe("other", testable=False)
        context = await asyncio.to_thread(tls_context, True)
        try:
            # A GET on a Discord webhook URL returns its metadata and posts nothing (13.2 H-ALERTS).
            async with httpx.AsyncClient(
                trust_env=False, verify=context, follow_redirects=False, timeout=max(1.0, timeout_s)
            ) as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            return WebhookProbe("discord", testable=True, error=type(exc).__name__)
        return WebhookProbe("discord", testable=True, status=response.status_code)

    # --- files -------------------------------------------------------------------------------------------------

    async def backup_status(self) -> BackupFacts:
        path = self._state_dir() / "audit" / "backup.json"
        document = await asyncio.to_thread(read_json_file, path)
        return backup_facts_from(document) if document is not None else BackupFacts(known=False)

    async def version_facts(self) -> VersionFacts:
        def read() -> VersionFacts:
            deployed = None
            for candidate in DEPLOYED_VERSION_FILES:
                deployed = _first_line(candidate)
                if deployed:
                    break
            advisories = None
            for candidate in ADVISORY_FILES:
                document = read_json_file(candidate)
                if document is not None:
                    advisories = advisories_from(document)
                    break
            return VersionFacts(deployed[:64] if deployed else None, advisories)

        return await asyncio.to_thread(read)

    async def disk_usage(self) -> DiskFacts:
        dbs = self._ctx.dbs
        state_dir = self._state_dir()

        def measure() -> DiskFacts:
            usage = shutil.disk_usage(state_dir)
            files: dict[str, tuple[int, int]] = {}
            for db in dbs.all():
                path = Path(db.path)
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
                try:
                    wal = Path(f"{path}-wal").stat().st_size
                except OSError:
                    wal = 0
                files[path.name] = (int(size), int(wal))
            return DiskFacts(int(usage.total), int(usage.free), files)

        return await asyncio.to_thread(measure)

    async def quick_check(self, db_name: str) -> list[str]:
        from roxy.storage import retention

        problems: list[str] = await self._ctx.dbs.get(db_name).maintenance(retention.quick_check)
        return problems

    # --- fleet -------------------------------------------------------------------------------------------------

    async def leader_jobs(self) -> list[JobFact] | None:
        """The leader's job status: this worker's own runner when it leads, else what the leader published."""
        leader = getattr(self._ctx, "leader", None)
        runner = getattr(self._ctx, "jobs", None)
        if leader is not None and runner is not None and bool(getattr(leader, "is_leader", False)):
            return [job_fact(row) for row in runner.status() if row.get("leader_only", True)]
        from roxy.health import store

        now = float(self._ctx.clock.now())
        rows = await self._ctx.dbs.metrics.read(lambda conn: store.read_job_status(conn, now - JOB_STATUS_FRESH_S))
        return rows or None

    async def loop_lag(self, window_s: float) -> list[LagSample]:
        """Fresh heartbeats' loop lag p99 (each row covers about the last minute of its worker)."""
        from roxy.scheduler.heartbeat import HEARTBEAT_STALE_S

        now = float(self._ctx.clock.now())

        def read(conn: Any) -> list[LagSample]:
            rows = conn.execute(
                "SELECT pid, worker_id, loop_lag_ms_p99 FROM worker_heartbeat "
                "WHERE last_seen >= ? AND loop_lag_ms_p99 IS NOT NULL ORDER BY pid LIMIT 256",
                (int(now - HEARTBEAT_STALE_S),),
            ).fetchall()
            return [LagSample(str(r["worker_id"] or r["pid"]), float(r["loop_lag_ms_p99"])) for r in rows]

        samples: list[LagSample] = await self._ctx.dbs.metrics.read(read)
        return samples


def job_fact(row: Mapping[str, Any]) -> JobFact:
    """A `JobFact` from one `JobRunner.status()` row."""
    last_ok = row.get("last_ok")
    return JobFact(
        name=str(row.get("name", ""))[:64],
        interval_s=float(row.get("interval_s") or 0.0),
        last_started_at=_float_or_none(row.get("last_started_at")),
        last_finished_at=_float_or_none(row.get("last_finished_at")),
        last_ok=None if last_ok is None else bool(last_ok),
    )


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


__all__ = [
    "ADVISORY_FILES",
    "DEPLOYED_VERSION_FILES",
    "AlertChannels",
    "BackupFacts",
    "CommandResult",
    "DiskFacts",
    "DnsAnswer",
    "DnsFailure",
    "JobFact",
    "LagSample",
    "LiveFacts",
    "OriginAnswer",
    "OriginFailure",
    "SmtpProbe",
    "SystemFacts",
    "TlsAnswer",
    "TlsFailure",
    "VersionFacts",
    "WebhookProbe",
    "advisories_from",
    "backup_facts_from",
    "is_global_address",
    "job_fact",
    "parse_iso_time",
    "read_json_file",
]
