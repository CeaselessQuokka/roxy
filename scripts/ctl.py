#!/usr/bin/env python3
"""ctl.py: the operator CLI for the server shell, for when the dashboard cannot be reached.

What this is
    `python scripts/ctl.py <command>` on the server. Commands (each one prints plain text, or JSON with `--json`):
      status                         both colors' internal sockets, the switches, the leader, bans, last backup
      pause / resume                 the maintenance switch (503 for every proxy request), with a reason
      throttle-all on|off            the emergency per-IP limit
      purge-cache                    a cache purge (--all, --host, --pattern, --id, --rule, --expired), --preview first
      reset preview|run              a data reset scope with its exact preview (plan 6.8), then the previewed run
      export-llm                     the plan 12 LLM export to a file (`--window 7d --detail full --out <path>`)
      health-run                     Check Proxy Health, waiting for the result (exit 1 when a check fails)
      backup-now                     ask the root backup (backup.sh) to run now, through roxy-backup-request.path
      leader / jobs                  who leads the fleet, and what the leader last published about its jobs
      bans list / bans lift          the ban list, and lifting every ban of one subject
      flush-metrics                  every worker flushes its buffered metrics within about a second
      settings show / settings set   runtime settings, through the same validated, audited service as the dashboard
    Every change is audited with an actor of kind `cli` (`cli:<your login name>`). Nothing secret is ever printed:
    the commands never read a credential, and every line goes through the same redaction as the logs.

Why it exists
    The dashboard can be out of reach exactly when it is needed: nginx is down, the admin is locked out, the
    allowlist hides /admin, or the box is under attack. Plan 17.8's runbooks ("Emergency: stop all upstream
    traffic: pause from the dashboard or `scripts/ctl.py pause`") and plan 12.2 (the LLM export from the server
    shell) need a way in that only someone with a shell on the server has. ctl.py is that way, and it uses the same
    services as the dashboard, so its changes are validated, audited and reach every worker the same way.

How it works
    Two doors, chosen per command:
      * The databases, directly (status, pause, resume, throttle-all, purge-cache, backup-now, leader, jobs, bans,
        flush-metrics, settings). These are control-plane rows that every worker already watches through
        `config_version` and `service_state` (plan 5.7), so a change made here reaches the fleet within about a
        second, and they work while every color is stopped. The databases belong to the `roxy` user and SQLite
        creates `-wal` and `-shm` files next to them, so these commands refuse to run as anyone else (a file made
        by root would lock the service out): run them as `sudo -u roxy`.
      * A color's internal Unix socket (export-llm, health-run, reset), for what only a running worker can do:
        `/internal/*` routes of `roxy/internal_app.py`, reached through `httpx.HTTPTransport(uds=...)` with
        `trust_env=False`. The color nginx points at is tried first, then the other one. A reset, a full-detail
        export and a health run with the credential check also send a one-use proof that the caller can write the
        state directory (`Roxy-Ctl-Proof`, explained in `internal_app.py`), so the deploy user, which may open the
        socket, can never destroy data or export raw addresses through it.
    Paths come from the same files the service reads: `/etc/roxy/roxy.env` and `/etc/roxy/<color>.env`
    (`ROXY_STATE_DIR`, `ROXY_*_DB`, `ROXY_INTERNAL_SOCKET`), overridable with `--env-dir`, `--state-dir` and
    `--socket`. Exit status: 0 done, 1 refused or failed (the message says why), 2 bad arguments, 3 nothing to
    talk to (no database, or no color answers on its socket).

What to read next
    `roxy/internal_app.py` (the socket routes and the proof), `roxy/abuse/pause.py` and `throttle_all.py` (the
    switches), `roxy/admin/api/data.py` (the reset scopes), then `deploy/README.md` ("Operator CLI").
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import getpass
import json
import os
import pwd
import re
import secrets
import sqlite3
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TextIO

_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))  # run from a release or a checkout without installing the package

import httpx  # noqa: E402 (after the path fix above)

from roxy.config.audit import Actor  # noqa: E402
from roxy.core.clock import SystemClock  # noqa: E402
from roxy.core.redact import redact_text  # noqa: E402
from roxy.internal_app import ACTOR_HEADER, PROOF_DIR_NAME, PROOF_HEADER, PROOF_MAX_AGE_S  # noqa: E402

EXIT_OK: Final = 0
EXIT_FAILED: Final = 1
EXIT_USAGE: Final = 2
EXIT_UNREACHABLE: Final = 3

COLORS: Final = ("blue", "green")
DEFAULT_ENV_DIR: Final = Path("/etc/roxy")
DEFAULT_NGINX_DIR: Final = Path("/etc/nginx")
DEFAULT_DEPLOY_STATE_DIR: Final = Path("/var/lib/roxy-deploy")
DB_NAMES: Final = ("control", "hot", "metrics", "cache")

SOCKET_TIMEOUT: Final = httpx.Timeout(30.0, connect=3.0)
EXPORT_TIMEOUT_S: Final = 330.0
"""An export build has a 300 s budget on the leader; a CLI build gets the same plus a margin."""
HEALTH_TIMEOUT_S: Final = 1000.0
"""The health run timeout (900 s) plus the internal route's wait margin and some slack."""
RESET_TIMEOUT_S: Final = 3600.0
"""A reset of a large metrics.db deletes in 5,000-row batches; an hour covers the largest the disk budget allows."""

BACKUP_REQUEST_NAME: Final = "backup-request"
"""The file `roxy-backup-request.path` watches (`PathExists=/var/lib/roxy/backup-request`)."""
BACKUP_STATUS: Final = Path("audit") / "backup.json"
BACKUP_POLL_S: Final = 2.0
JOB_STATUS_FRESH_S: Final = 180.0
"""The leader publishes job status every 30 s; older rows are reported as stale."""

MAX_PROOFS_KEPT: Final = 64
"""Proof files the CLI looks at when it prunes stale ones (a bounded directory listing, plan P9)."""

_NAME_RE: Final = re.compile(r"[^A-Za-z0-9_.@-]")


class CliError(Exception):
    """A problem the operator can fix: printed without a traceback, with its exit status."""

    def __init__(self, message: str, status: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.status = status


# ================================================================================================ configuration


def read_env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE lines (no shell expansion), like systemd's EnvironmentFile; a missing file is empty."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def operator_name(environ: Mapping[str, str] | None = None) -> str:
    """Who is typing: the login name behind sudo (`SUDO_USER`), else this account; letters, digits, `_ . @ -`."""
    source = os.environ if environ is None else environ
    raw = source.get("SUDO_USER") or ""
    if not raw:
        try:
            raw = getpass.getuser()
        except (KeyError, OSError):
            raw = ""
    name = _NAME_RE.sub("", raw)[:64]
    return name or "ctl"


@dataclass
class Config:
    """Where everything is, and how to print."""

    env_dir: Path
    nginx_dir: Path
    deploy_state_dir: Path
    state_dir: Path
    db_paths: dict[str, Path]
    sockets: list[tuple[str, Path]]
    explicit_socket: bool
    as_json: bool
    actor_name: str
    out: TextIO
    transport: Callable[[Path], httpx.BaseTransport] | None = None
    """Tests replace the Unix socket transport (production always uses `httpx.HTTPTransport(uds=...)`)."""

    @property
    def actor(self) -> Actor:
        return Actor("cli", self.actor_name)


def active_color(nginx_dir: Path) -> str | None:
    """The color `/etc/nginx/roxy-active-upstream.conf` points at, like deploy.sh reads it."""
    try:
        target = os.readlink(nginx_dir / "roxy-active-upstream.conf")
    except OSError:
        return None
    name = Path(target).name
    for color in COLORS:
        if name == f"roxy-upstream-{color}.conf":
            return color
    return None


def resolve_config(args: argparse.Namespace, out: TextIO) -> Config:
    """Merge the env files, this process's environment and the flags (flags win, then the environment)."""
    env_dir = Path(args.env_dir)
    shared = read_env_file(env_dir / "roxy.env")
    for key, value in os.environ.items():
        if key.startswith("ROXY_") and value:
            shared[key] = value
    state_dir = Path(args.state_dir or shared.get("ROXY_STATE_DIR") or "/var/lib/roxy")
    db_paths: dict[str, Path] = {}
    for name in DB_NAMES:
        explicit = None if args.state_dir else shared.get(f"ROXY_{name.upper()}_DB")
        db_paths[name] = Path(explicit) if explicit else state_dir / f"{name}.db"
    nginx_dir = Path(args.nginx_dir)
    sockets: list[tuple[str, Path]] = []
    if args.socket:
        sockets.append((args.color or "given", Path(args.socket)))
    else:
        first = args.color or active_color(nginx_dir)
        order = [first] if first else []
        if not args.color:
            order += [color for color in COLORS if color != first]
        for color in order:
            per_color = read_env_file(env_dir / f"{color}.env")
            path = per_color.get("ROXY_INTERNAL_SOCKET") or f"/run/roxy-{color}/internal.sock"
            sockets.append((color, Path(path)))
        if os.environ.get("ROXY_INTERNAL_SOCKET") and not args.color:
            sockets.insert(0, (os.environ.get("ROXY_COLOR") or "dev", Path(os.environ["ROXY_INTERNAL_SOCKET"])))
    return Config(
        env_dir=env_dir,
        nginx_dir=nginx_dir,
        deploy_state_dir=Path(args.deploy_state_dir),
        state_dir=state_dir,
        db_paths=db_paths,
        sockets=sockets,
        explicit_socket=bool(args.socket),
        as_json=bool(args.json),
        actor_name=operator_name(),
        out=out,
    )


# ================================================================================================ output


def clean(text: str) -> str:
    """One output line: secrets scrubbed (registered values, cookie shapes, URL passwords), no control bytes."""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", redact_text(text))


def emit(cfg: Config, data: Any, lines: Sequence[str]) -> None:
    """Print `data` as JSON (`--json`) or `lines` as text; either way through `clean`."""
    if cfg.as_json:
        text = json.dumps(data, indent=2, sort_keys=True, default=str, ensure_ascii=False)
        cfg.out.write(clean(text) + "\n")
        return
    for line in lines:
        cfg.out.write(clean(line) + "\n")


def when(ts: float | int | None) -> str:
    """A Unix time as `YYYY-MM-DD HH:MM:SS UTC`, or `never`."""
    if not ts:
        return "never"
    return dt.datetime.fromtimestamp(float(ts), dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def iso_now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ================================================================================================ the databases


def _owner_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def check_owner(cfg: Config) -> None:
    """Refuse unless this process runs as the user that owns the databases (see the module docstring)."""
    control = cfg.db_paths["control"]
    try:
        info = control.stat()
    except FileNotFoundError:
        raise CliError(
            f"no Roxy database at {control} (wrong --state-dir, or no color has started yet)", EXIT_UNREACHABLE
        ) from None
    except PermissionError:
        raise CliError(f"cannot read {control}: run as the roxy user (sudo -u roxy ...)") from None
    if os.geteuid() != info.st_uid:
        owner = _owner_name(info.st_uid)
        raise CliError(
            f"the databases belong to {owner}; run this command as that user (sudo -u {owner} ...), so that SQLite "
            "never creates a file the service cannot open"
        )


@contextlib.contextmanager
def open_store(cfg: Config, names: Sequence[str] = ("control", "hot", "metrics")) -> Iterator[Any]:
    """The four databases (schema checked for `names`), closed afterwards. Never migrates (plan 5.5)."""
    check_owner(cfg)
    from roxy.storage.db import open_databases
    from roxy.storage.migrate import SchemaTooOld, check_schema

    env = {"ROXY_STATE_DIR": str(cfg.state_dir)}
    env.update({f"ROXY_{name.upper()}_DB": str(path) for name, path in cfg.db_paths.items()})
    dbs = open_databases(env)
    try:
        try:
            check_schema(dbs, names=list(names))
        except SchemaTooOld as exc:
            raise CliError(f"the database schema is older than this release needs: {exc}") from None
        yield dbs
    finally:
        dbs.close_all_sync()


def _state_value(conn: sqlite3.Connection, key: str) -> Any:
    row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        return None


def _bounded_json_file(path: Path, limit: int = 1_000_000) -> Any:
    """A small JSON status file, read without following a link; None when missing or unreadable."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


# ================================================================================================ the sockets


def _client(cfg: Config, path: Path, timeout: httpx.Timeout | float = SOCKET_TIMEOUT) -> httpx.Client:
    transport = cfg.transport(path) if cfg.transport is not None else httpx.HTTPTransport(uds=str(path))
    headers = {ACTOR_HEADER: cfg.actor_name, "User-Agent": "roxy-ctl"}
    # trust_env=False: no HTTP_PROXY or .netrc in the operator's shell can redirect or decorate these calls.
    return httpx.Client(
        transport=transport, base_url="http://internal", timeout=timeout, headers=headers, trust_env=False
    )


def probe_socket(cfg: Config, color: str, path: Path) -> dict[str, Any]:
    """`/internal/version` and `/internal/ready` of one color (one worker answers)."""
    view: dict[str, Any] = {"color": color, "socket": str(path), "reachable": False}
    if cfg.transport is None and not path.exists():
        view["error"] = "no socket (the color is not running)"
        return view
    try:
        with _client(cfg, path, httpx.Timeout(5.0, connect=2.0)) as client:
            version = client.get("/internal/version")
            ready = client.get("/internal/ready")
    except httpx.HTTPError as exc:
        view["error"] = type(exc).__name__
        return view
    except OSError as exc:
        view["error"] = type(exc).__name__
        return view
    view["reachable"] = True
    if version.status_code == 200:
        body = version.json()
        view.update(
            version=body.get("Version"),
            worker_id=body.get("WorkerId"),
            config_version=body.get("ConfigVersion"),
            env=body.get("Env"),
        )
    try:
        state = ready.json()
    except ValueError:
        state = {}
    view.update(ready=bool(state.get("Ready")), persistence_ok=bool(state.get("PersistenceOK")))
    view["leader_answered"] = bool(state.get("IsLeader"))
    return view


def pick_socket(cfg: Config) -> tuple[str, Path]:
    """The first color whose worker answers Ready (nginx's color first). Exit 3 when none does."""
    tried: list[str] = []
    for color, path in cfg.sockets:
        view = probe_socket(cfg, color, path)
        if view.get("ready"):
            return color, path
        tried.append(f"{color} ({view.get('error') or 'not ready'})")
    raise CliError(
        "no color answers Ready on its internal socket: " + ", ".join(tried or ["no socket configured"]),
        EXIT_UNREACHABLE,
    )


def write_proof(cfg: Config) -> str:
    """A one-use proof that this process can write the state directory (`internal_app.check_proof`).

    Only the state directory's owner may write one: a proof made by root would be refused by the service anyway
    (it must own the file), and a `ctl-proofs` directory root created would lock the roxy user out of it.
    """
    directory = cfg.state_dir / PROOF_DIR_NAME
    try:
        owner = cfg.state_dir.stat().st_uid
    except OSError:
        raise CliError(f"cannot reach the state directory {cfg.state_dir} (wrong --state-dir?)") from None
    if os.geteuid() != owner:
        name = _owner_name(owner)
        raise CliError(f"this action needs the state directory's owner: run it as sudo -u {name} ...")
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        _prune_proofs(directory)
        name = secrets.token_hex(8)
        secret = secrets.token_hex(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(directory / name, flags, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(secret)
    except PermissionError:
        raise CliError(
            "this action needs the roxy user (it changes data or reveals more than the deploy user may see): "
            "run it as sudo -u roxy ..."
        ) from None
    except OSError as exc:
        raise CliError(f"could not write the proof file in {directory}: {type(exc).__name__}") from None
    return f"{name}:{secret}"


def _prune_proofs(directory: Path) -> None:
    """Remove proofs a failed request left behind (older than the server accepts); bounded."""
    cutoff = time.time() - 2 * PROOF_MAX_AGE_S
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries):
            if count >= MAX_PROOFS_KEPT:
                break
            with contextlib.suppress(OSError):
                if entry.is_file(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_mtime < cutoff:
                    os.unlink(entry.path)


def _api_error(response: httpx.Response) -> str:
    """The message of a section 13 error answer (`{"error": {"code", "message", "fields"}}`)."""
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return f"HTTP {response.status_code}"
    message = str(error.get("message") or error.get("code") or response.status_code)
    fields = error.get("fields")
    if isinstance(fields, dict) and fields:
        message += " (" + "; ".join(f"{k}: {v}" for k, v in fields.items()) + ")"
    return message


def call(
    cfg: Config,
    method: str,
    route: str,
    *,
    body: Mapping[str, Any] | None = None,
    params: Mapping[str, str] | None = None,
    proof: bool = False,
    timeout_s: float = 30.0,
) -> tuple[str, httpx.Response]:
    """One request to the first Ready color; a refusal becomes a CliError with the server's message."""
    color, path = pick_socket(cfg)
    headers = {PROOF_HEADER: write_proof(cfg)} if proof else {}
    try:
        with _client(cfg, path, httpx.Timeout(timeout_s, connect=3.0)) as client:
            response = client.request(method, route, json=body, params=params, headers=headers)
    except httpx.HTTPError as exc:
        raise CliError(f"{color}: the request failed ({type(exc).__name__})", EXIT_UNREACHABLE) from None
    if response.status_code >= 400:
        raise CliError(f"{color}: {_api_error(response)}")
    return color, response


# ================================================================================================ commands


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.scheduler.leader import LEADER_LEASE
    from roxy.storage import leases

    sockets = [probe_socket(cfg, color, path) for color, path in cfg.sockets]
    data: dict[str, Any] = {
        "active_color": active_color(cfg.nginx_dir),
        "sockets": sockets,
        "deployed_version": _first_line(cfg.deploy_state_dir / "deployed_version"),
    }
    lines = [f"nginx sends traffic to: {data['active_color'] or 'unknown (no active upstream link)'}"]
    for item in sockets:
        if item["reachable"]:
            lines.append(
                f"{item['color']}: {'ready' if item.get('ready') else 'NOT ready'}, version {item.get('version')}, "
                f"config version {item.get('config_version')} ({item['socket']})"
            )
        else:
            lines.append(f"{item['color']}: unreachable, {item.get('error')} ({item['socket']})")
    lines.append(f"deployed version: {data['deployed_version'] or 'not recorded'}")
    try:
        with open_store(cfg) as dbs:
            now = time.time()

            def control(conn: sqlite3.Connection) -> dict[str, Any]:
                active = conn.execute(
                    "SELECT count(*) FROM bans WHERE expires_at IS NULL OR expires_at > ?", (int(now),)
                ).fetchone()[0]
                return {
                    "pause": _state_value(conn, "pause") or {},
                    "throttle_all": _state_value(conn, "throttle_all") or {},
                    "config_version": _state_value(conn, "config_version"),
                    "active_bans": int(active),
                }

            facts = dbs.control.read_sync(control)
            lease = dbs.hot.read_sync(lambda conn: leases.holder_epoch(conn, LEADER_LEASE))
    except CliError as exc:
        data["databases"] = {"skipped": str(exc)}
        lines.append(f"databases: not read ({exc})")
    else:
        pause, tall = facts["pause"], facts["throttle_all"]
        leader = None
        if lease is not None:
            leader = {"holder": lease[0], "epoch": lease[1], "valid": lease[2] > now * 1000}
        backup = _bounded_json_file(cfg.state_dir / BACKUP_STATUS)
        data["databases"] = {
            "paused": bool(pause.get("paused")),
            "pause_reason": pause.get("reason") or "",
            "scheduled_pause": [pause.get("scheduled_start"), pause.get("scheduled_end")],
            "throttle_all": bool(tall.get("enabled")),
            "throttle_all_reason": tall.get("reason") or "",
            "config_version": facts["config_version"],
            "active_bans": facts["active_bans"],
            "leader": leader,
            "backup": backup if isinstance(backup, dict) else None,
        }
        lines.append(f"proxy paused: {'YES' if pause.get('paused') else 'no'}{_reason(pause.get('reason'))}")
        if pause.get("scheduled_start") and pause.get("scheduled_end"):
            lines.append(f"scheduled pause: {when(pause['scheduled_start'])} to {when(pause['scheduled_end'])}")
        lines.append(f"throttle-all: {'ON' if tall.get('enabled') else 'off'}{_reason(tall.get('reason'))}")
        lines.append(f"config version: {facts['config_version']}")
        lines.append(f"active bans: {facts['active_bans']}")
        if leader is None:
            lines.append("leader: none")
        else:
            state = "valid" if leader["valid"] else "EXPIRED"
            lines.append(f"leader: {leader['holder']} (epoch {leader['epoch']}, {state})")
        lines.append(_backup_line(backup))
    emit(cfg, data, lines)
    return EXIT_OK


def _reason(text: Any) -> str:
    return f" (reason: {text})" if text else ""


def _first_line(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            text = handle.read(256).strip()
    except OSError:
        return None
    return text.splitlines()[0][:64] if text else None


def _part(document: Mapping[str, Any], key: str) -> dict[str, Any]:
    """`document[key]` when it is an object, else an empty one (status files are read defensively)."""
    value = document.get(key)
    return dict(value) if isinstance(value, dict) else {}


def _backup_line(status: Any) -> str:
    if not isinstance(status, dict):
        return "last backup: none recorded"
    success = _part(status, "last_success")
    failure = _part(status, "last_failure")
    line = f"last backup: {success.get('at') or 'never'}"
    if failure:
        line += f"; last failure {failure.get('at')} at step {failure.get('step')}"
    return line


def _run_async(make: Callable[[], Any]) -> Any:
    """Run one coroutine (the services are async; their database work runs on the writer threads)."""
    return asyncio.run(make())


def cmd_pause(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.abuse.pause import set_pause

    paused = args.command == "pause"
    with open_store(cfg, ("control",)) as dbs:
        try:
            state = _run_async(
                lambda: set_pause(dbs.control, SystemClock(), cfg.actor, paused=paused, reason=args.reason)
            )
        except ValueError as exc:
            raise CliError(str(exc)) from None
    word = "paused: every proxy request now gets 503" if paused else "resumed: proxy requests are served again"
    lines = [f"Roxy is {word} (every worker within about a second; audited as {cfg.actor.label})."]
    if paused:
        lines.append(f"Callers read: {state.reason or 'the default pause message (setting pause_message_default)'}")
    emit(cfg, {"paused": state.paused, "reason": state.reason, "since": state.since}, lines)
    return EXIT_OK


def cmd_throttle_all(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.abuse.throttle_all import set_throttle_all

    enabled = args.state == "on"
    with open_store(cfg, ("control",)) as dbs:
        try:
            state = _run_async(
                lambda: set_throttle_all(dbs.control, SystemClock(), cfg.actor, enabled=enabled, reason=args.reason)
            )
        except ValueError as exc:
            raise CliError(str(exc)) from None
    word = "ON: every client gets the emergency per-IP limit" if enabled else "off"
    lines = [f"Throttle-all is {word} (every worker within about a second; audited as {cfg.actor.label})."]
    emit(cfg, {"enabled": state.enabled, "reason": state.reason, "since": state.since}, lines)
    return EXIT_OK


def purge_scope(args: argparse.Namespace) -> Any:
    from roxy.cache.store import PurgeScope

    if args.all:
        return PurgeScope.all()
    if args.host:
        return PurgeScope.host(args.host)
    if args.pattern:
        return PurgeScope.pattern(args.pattern, "regex" if args.regex else "glob")
    if args.id:
        return PurgeScope.entry(args.id)
    if args.rule is not None:
        return PurgeScope.rule(args.rule)
    return PurgeScope.expired(include_stale=args.include_stale)


def cmd_purge_cache(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.cache.read_purge_counts import purge_preview
    from roxy.cache.store import CacheStore, PurgeKind
    from roxy.config import audit

    try:
        scope = purge_scope(args).validated()
    except ValueError as exc:
        raise CliError(f"the purge is not valid: {exc}") from None
    with open_store(cfg, ("control", "cache")) as dbs:
        now = time.time()
        found = dbs.cache.read_sync(lambda conn: purge_preview(conn, scope, int(now)))
        if args.preview:
            emit(cfg, {"scope": scope.label, "preview": found}, [f"Purge {scope.label} would remove: {found}"])
            return EXIT_OK
        if scope.kind == PurgeKind.ALL and not args.yes:
            raise CliError("purging the whole cache needs --yes (every caller goes to Roblox until it refills)")
        details = {"scope": scope.label, "kind": scope.kind.value, "cause": "cli", "preview": found}
        actor = cfg.actor

        def write(conn: sqlite3.Connection) -> int:
            target = f"cache:{scope.label}"[:200]
            return audit.record(
                conn, actor, "cache.purge", target, None, details, args.reason or None, None, at=int(now)
            )

        audit_id = dbs.control.write_sync(write)  # audited first: no audit row, no purge (plan 9.7, C7)
        clock = SystemClock()
        result = _run_async(lambda: CacheStore(dbs.cache, clock).purge(scope, now=clock.now()))
    data = {"scope": scope.label, "removed": result.removed, "generation": result.floor, "audit_id": audit_id}
    lines = [
        f"Purged {scope.label}: {result.removed} entries removed; every worker drops its memory copies within a "
        f"quarter second (audit row {audit_id})."
    ]
    emit(cfg, data, lines)
    return EXIT_OK


def reset_body(args: argparse.Namespace) -> dict[str, Any]:
    """The `ResetBody` JSON of the Data page's reset form, from the flags (unset flags are left out)."""
    body: dict[str, Any] = {"scope": args.scope}
    optional = {
        "families": args.family or None,
        "from": args.start,
        "to": args.end,
        "client_type": args.client_type,
        "client": args.client,
        "template": args.template,
        "cache": args.cache,
        "value": args.value,
        "bans": args.bans,
        "detector": args.detector,
        "recommendations": args.recommendations,
    }
    body.update({key: value for key, value in optional.items() if value is not None})
    if args.pattern_type != "glob":
        body["pattern_type"] = args.pattern_type
    if args.include_stale:
        body["include_stale"] = True
    if args.action == "run":
        body["preview"] = args.digest
        body["reason"] = args.reason or ""
        if args.confirm is not None:
            body["confirm"] = args.confirm
    return body


def cmd_reset(cfg: Config, args: argparse.Namespace) -> int:
    body = reset_body(args)
    if args.action == "preview":
        color, response = call(cfg, "POST", "/internal/data/resets/preview", body=body)
        preview = response.json()
        lines = [f"{preview.get('summary')}", ""]
        for table in preview.get("tables", []):
            lines.append(f"  {table.get('db')}.{table.get('table')}: {table.get('rows')} rows")
        for action in preview.get("actions", []):
            lines.append(f"  action: {action.get('action')} {action.get('scope') or action.get('note') or ''}".rstrip())
        for snapshot in preview.get("snapshots", []):
            state = "will be taken" if snapshot.get("feasible") else f"skipped ({snapshot.get('reason')})"
            lines.append(f"  snapshot of {snapshot.get('db')}.db: {state}")
        lines.append("")
        lines.append(f"To run exactly this reset: --digest {preview.get('preview')}")
        if preview.get("confirm_phrase"):
            lines.append(f'It also needs --confirm "{preview["confirm_phrase"]}" and a --reason.')
        lines.append(f"(previewed by {color})")
        emit(cfg, preview, lines)
        return EXIT_OK
    if not args.digest or not re.fullmatch(r"[0-9a-f]{64}", args.digest):
        raise CliError("reset run needs --digest: the 64 character value `reset preview` printed", EXIT_USAGE)
    color, response = call(cfg, "POST", "/internal/data/resets", body=body, proof=True, timeout_s=RESET_TIMEOUT_S)
    outcome = response.json()
    lines = [f"Reset done on {color}: {outcome.get('total_rows')} rows deleted (audit row {outcome.get('audit_id')})."]
    for label, rows in sorted((outcome.get("deleted") or {}).items()):
        lines.append(f"  {label}: {rows}")
    for snapshot in outcome.get("snapshots") or []:
        lines.append(f"  snapshot: {snapshot.get('file')} ({snapshot.get('bytes')} bytes)")
    emit(cfg, outcome, lines)
    return EXIT_OK


def cmd_export_llm(cfg: Config, args: argparse.Namespace) -> int:
    out_path = Path(args.out)
    if out_path.is_dir():
        raise CliError(f"--out names a directory: {out_path}", EXIT_USAGE)
    params = {"window": args.window, "detail": args.detail, "format": args.format}
    color, response = call(
        cfg, "GET", "/internal/export/llm", params=params, proof=args.detail == "full", timeout_s=EXPORT_TIMEOUT_S
    )
    tmp = out_path.with_name(f".{out_path.name}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(tmp, flags, 0o600)  # private by default: the file leaves Roxy's audit trail at this point
        with os.fdopen(fd, "wb") as handle:
            handle.write(response.content)
        os.replace(tmp, out_path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise CliError(f"could not write {out_path}: {type(exc).__name__}") from None
    data = {
        "path": str(out_path),
        "bytes": len(response.content),
        "window": args.window,
        "detail": args.detail,
        "format": args.format,
        "untrusted_entries": response.headers.get("Roxy-Export-Untrusted"),
        "audit_id": response.headers.get("Roxy-Audit-Id"),
        "color": color,
    }
    lines = [
        f"Wrote {len(response.content)} bytes to {out_path} (mode 0600; {args.detail} detail, {args.window}; "
        f"{data['untrusted_entries']} untrusted entries; audit row {data['audit_id']})."
    ]
    emit(cfg, data, lines)
    return EXIT_OK


def cmd_health_run(cfg: Config, args: argparse.Namespace) -> int:
    body = {
        "checks": list(args.check or []),
        "include_credential": bool(args.include_credential),
        "wait": not args.no_wait,
    }
    color, response = call(
        cfg, "POST", "/internal/health/run", body=body, proof=bool(args.include_credential), timeout_s=HEALTH_TIMEOUT_S
    )
    answer = response.json()
    run = answer.get("run") or {}
    results = run.get("results") or []
    lines = [f"Health run {answer.get('run_id')} on {color} ({answer.get('checks')} checks): {run.get('state')}"]
    for result in results:
        lines.append(f"  {str(result.get('status')).upper():4}  {result.get('check_id')}  {result.get('explanation')}")
    summary = run.get("summary") or {}
    if summary:
        lines.append(
            f"pass {summary.get('pass', 0)}, warn {summary.get('warn', 0)}, fail {summary.get('fail', 0)}, "
            f"n/a {summary.get('n/a', 0)}"
        )
    emit(cfg, answer, lines)
    failed = any(str(result.get("status")) == "fail" for result in results)
    return EXIT_FAILED if failed else EXIT_OK


def write_backup_request(state_dir: Path, by: str, audit_id: int | None) -> Path:
    """Write `<state dir>/backup-request` atomically (a new file renamed into place, mode 0640)."""
    target = state_dir / BACKUP_REQUEST_NAME
    tmp = state_dir / f".{BACKUP_REQUEST_NAME}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp, flags, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"requested_at": iso_now(), "by": by, "audit_id": audit_id}, handle)
            handle.write("\n")
        os.replace(tmp, target)  # PathExists= sees the complete file only
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    return target


def cmd_backup_now(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.config import audit

    with open_store(cfg, ("control",)) as dbs:
        now = int(time.time())
        actor = cfg.actor

        def write(conn: sqlite3.Connection) -> int:
            details = {"request_file": BACKUP_REQUEST_NAME, "via": "roxy-backup-request.path"}
            return audit.record(
                conn, actor, "backup.request", "backup:root", None, details, args.reason or None, None, at=now
            )

        audit_id = dbs.control.write_sync(write)
        try:
            path = write_backup_request(cfg.state_dir, actor.label, audit_id)
        except OSError as exc:
            raise CliError(f"could not write the backup request: {type(exc).__name__}") from None
    data: dict[str, Any] = {"request": str(path), "audit_id": audit_id, "outcome": "requested"}
    lines = [
        f"Backup requested ({path}, audit row {audit_id}). roxy-backup-request.path starts the root backup "
        "(backup.sh) within seconds; its result lands in audit/backup.json and on the Data page."
    ]
    if args.wait > 0:
        outcome = _wait_for_backup(cfg, now, args.wait)
        data["outcome"] = outcome
        lines.append(f"Result: {outcome}")
        emit(cfg, data, lines)
        return EXIT_OK if outcome.startswith(("done", "skipped")) else EXIT_FAILED
    emit(cfg, data, lines)
    return EXIT_OK


def _wait_for_backup(cfg: Config, since: int, wait_s: float) -> str:
    """Poll backup.json until it records an answer to a request made at `since` (or the wait ends)."""
    deadline = time.monotonic() + wait_s
    while True:
        status = _bounded_json_file(cfg.state_dir / BACKUP_STATUS)
        if isinstance(status, dict):
            request = _part(status, "last_request")
            if _iso_seconds(request.get("at")) >= since - 1:
                outcome = str(request.get("outcome") or "")
                if outcome == "ran":
                    failure = _part(status, "last_failure")
                    if failure and _iso_seconds(failure.get("at")) >= since - 1:
                        return f"failed at step {failure.get('step')}"
                    success = _part(status, "last_success")
                    if success and _iso_seconds(success.get("at")) >= since - 1:
                        return f"done at {success.get('at')}"
                elif outcome:
                    return f"skipped ({outcome})"
        if time.monotonic() >= deadline:
            request_file = cfg.state_dir / BACKUP_REQUEST_NAME
            pending = "the request is still waiting" if request_file.exists() else "the backup is still running"
            return f"no result after {wait_s:g} s ({pending}; is roxy-backup-request.path enabled?)"
        time.sleep(BACKUP_POLL_S)


def _iso_seconds(text: Any) -> float:
    try:
        return dt.datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC).timestamp()
    except ValueError:
        return 0.0


def cmd_leader(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.scheduler.heartbeat import fleet_view
    from roxy.scheduler.leader import LEADER_LEASE
    from roxy.storage import leases

    with open_store(cfg) as dbs:
        now = time.time()
        lease = dbs.hot.read_sync(lambda conn: leases.holder_epoch(conn, LEADER_LEASE))
        workers = dbs.metrics.read_sync(lambda conn: fleet_view(conn, now))
    data: dict[str, Any] = {"leader": None, "workers": []}
    if lease is None:
        lines = ["No worker holds the leader lease (no color running, or the lease just expired)."]
    else:
        valid = lease[2] > now * 1000
        data["leader"] = {
            "holder": lease[0],
            "epoch": lease[1],
            "expires_in_s": round((lease[2] - now * 1000) / 1000, 1),
            "valid": valid,
        }
        lines = [
            f"Leader: {lease[0]} (epoch {lease[1]}, "
            + (f"renews within {data['leader']['expires_in_s']} s)" if valid else "EXPIRED, a takeover is due)")
        ]
    for worker in workers:
        row = {
            key: worker.get(key)
            for key in ("pid", "color", "worker_id", "version", "fresh", "is_leader", "uptime_s", "rss", "requests")
        }
        data["workers"].append(row)
        lines.append(
            f"  pid {row['pid']} {row['color']} {'fresh' if row['fresh'] else 'STALE'}"
            f"{' leader' if row['is_leader'] else ''}, up {row['uptime_s']} s, version {row['version']}"
        )
    emit(cfg, data, lines)
    return EXIT_OK


def cmd_jobs(cfg: Config, args: argparse.Namespace) -> int:
    with open_store(cfg) as dbs:
        now = time.time()

        def read(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(health_job_status)").fetchall()]
            wanted = [
                name
                for name in (
                    "name",
                    "interval_s",
                    "last_started_at",
                    "last_finished_at",
                    "last_ok",
                    "holder",
                    "published_at",
                )
                if name in columns
            ]
            if not wanted:
                return []
            rows = conn.execute(
                f"SELECT {', '.join(wanted)} FROM health_job_status ORDER BY name LIMIT 200"  # noqa: S608 (fixed names)
            ).fetchall()
            return [dict(zip(wanted, tuple(row), strict=True)) for row in rows]

        jobs = dbs.metrics.read_sync(read)
    lines = []
    if not jobs:
        lines.append("The leader has not published any job status yet.")
    for job in jobs:
        published = float(job.get("published_at") or 0)
        job["stale"] = now - published > JOB_STATUS_FRESH_S if published else True
        ok = {1: "ok", 0: "FAILED", None: "not run yet"}.get(job.get("last_ok"), str(job.get("last_ok")))
        lines.append(
            f"  {job['name']}: every {job.get('interval_s')} s, last run {when(job.get('last_started_at'))} ({ok})"
            f"{', published by ' + str(job.get('holder')) if job.get('holder') else ''}"
            f"{' [stale]' if job['stale'] else ''}"
        )
    emit(cfg, {"jobs": jobs}, lines)
    return EXIT_OK


def cmd_bans(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.abuse import read_bans

    if args.action == "list":
        with open_store(cfg, ("control",)) as dbs:
            now = int(time.time())
            try:
                page = dbs.control.read_sync(
                    lambda conn: read_bans.ban_page(
                        conn, now=now, state=args.state, search=args.search or "", limit=args.limit
                    )
                )
            except ValueError as exc:
                raise CliError(str(exc), EXIT_USAGE) from None
        lines = [f"{page['total']} bans ({args.state}); {page['active_total']} active in all"]
        for ban in page["rows"]:
            until = "permanent" if ban["permanent"] else f"until {when(ban['expires_at'])}"
            lines.append(
                f"  {ban['subject_type']} {ban['subject']}: {until}, by {ban['created_by'] or 'unknown'}, "
                f"{ban['hits']} hits"
            )
        emit(cfg, page, lines)
        return EXIT_OK
    from roxy.rules.service import RuleNotFound, RulesError, RulesService

    with open_store(cfg, ("control",)) as dbs:
        service = RulesService(dbs.control, clock=SystemClock())
        try:
            change = _run_async(lambda: service.unban(args.subject_type, args.subject, cfg.actor, args.reason or ""))
        except RuleNotFound as exc:
            raise CliError(exc.message) from None
        except RulesError as exc:
            raise CliError(getattr(exc, "message", str(exc))) from None
    rows = len(change.before or [])
    lines = [
        f"Lifted {rows} ban row(s) of {change.key}; every worker drops it within about a second "
        f"(audit row {change.audit_id})."
    ]
    emit(cfg, {"subject": change.key, "rows": rows, "audit_id": change.audit_id}, lines)
    return EXIT_OK


def cmd_flush_metrics(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.admin.api.system import FLUSH_KEY
    from roxy.config import audit

    with open_store(cfg, ("control",)) as dbs:
        now = time.time()
        actor = cfg.actor

        def write(conn: sqlite3.Connection) -> int:
            audit_id = audit.record(
                conn,
                actor,
                "system.flush",
                f"service_state:{FLUSH_KEY}",
                None,
                {FLUSH_KEY: now},
                args.reason or None,
                None,
                at=int(now),
            )
            conn.execute(
                "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                (FLUSH_KEY, json.dumps(now), int(now)),
            )
            return audit_id

        audit_id = dbs.control.write_sync(write)
    lines = [f"Every worker flushes its buffered metrics within about a second (audit row {audit_id})."]
    emit(cfg, {"requested_at": now, "audit_id": audit_id}, lines)
    return EXIT_OK


def _setting_value(spec: Any, value: Any) -> Any:
    return "[redacted]" if getattr(spec, "sensitive", False) else value


def cmd_settings(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.config import catalog

    if args.action == "show":
        keys = []
        for raw in args.keys or sorted(catalog.CATALOG):
            key = catalog.resolve_key(raw) or raw
            if key not in catalog.CATALOG:
                raise CliError(f"unknown setting: {raw}", EXIT_USAGE)
            keys.append(key)
        with open_store(cfg, ("control",)) as dbs:

            def read(conn: sqlite3.Connection) -> dict[str, Any]:
                rows = conn.execute("SELECT key, value_json FROM settings").fetchall()
                return {str(key): json.loads(text) for key, text in rows}

            overrides = dbs.control.read_sync(read)
        items = []
        lines = []
        for key in keys:
            spec = catalog.CATALOG[key]
            default = catalog.DEFAULTS.get(key, spec.default)
            overridden = key in overrides
            value = overrides[key] if overridden else default
            item = {
                "key": key,
                "value": _setting_value(spec, value),
                "default": _setting_value(spec, default),
                "overridden": overridden,
            }
            items.append(item)
            lines.append(f"{key} = {json.dumps(item['value'], default=str)}{'' if overridden else '  (default)'}")
        emit(cfg, {"settings": items}, lines)
        return EXIT_OK
    return _settings_set(cfg, args)


def _current_setting(dbs: Any, key: str) -> Any:
    """A setting's value now: its override in control.db, else the catalog default."""
    from roxy.config import catalog

    def read(conn: sqlite3.Connection) -> Any:
        row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row is not None else catalog.DEFAULTS.get(key)

    return dbs.control.read_sync(read)


def _parse_assignment(text: str) -> tuple[str, Any]:
    key, sep, raw = text.partition("=")
    if not sep or not key.strip():
        raise CliError(f"expected KEY=VALUE, got {text[:80]!r}", EXIT_USAGE)
    value: Any = raw
    with contextlib.suppress(ValueError):
        value = json.loads(raw)  # numbers, true/false, lists; anything else stays text
    return key.strip(), value


def _settings_set(cfg: Config, args: argparse.Namespace) -> int:
    from roxy.admin.api.settings import ARM_ONLY_MESSAGE, ARM_ONLY_SETTINGS
    from roxy.config import catalog
    from roxy.config.settings_service import SettingsService, SettingsUpdateError
    from roxy.config.spec import Risk

    changes: dict[str, Any] = {}
    risky: list[str] = []
    for text in args.assignments:
        raw_key, raw_value = _parse_assignment(text)
        key = catalog.resolve_key(raw_key) or raw_key
        spec = catalog.CATALOG.get(key)
        if spec is None:
            raise CliError(f"unknown setting: {raw_key}", EXIT_USAGE)
        if spec.sensitive:
            raise CliError(f"{key} is sensitive; change it from the dashboard (its history fingerprint needs a key)")
        try:
            value = catalog.validate_value(key, raw_value)
        except catalog.SettingValidationError as exc:
            raise CliError(f"{key}: {exc.message}") from None
        why = spec.is_high_risk_value(value)
        if spec.risk == Risk.HIGH or why:
            risky.append(f"{key} ({why or 'a high-risk setting'})")
        changes[key] = raw_value
    if risky and not (args.confirm_high_risk and (args.reason or "").strip()):
        raise CliError("high risk: " + "; ".join(risky) + ". Give --reason and --confirm-high-risk to go ahead.")
    with open_store(cfg, ("control",)) as dbs:
        # Plan 10.3, as in the dashboard: an ARM_ONLY setting is never switched OFF here (arming shows its
        # collateral preview first, on the Protection page); setting it on, or to the value it has, is allowed.
        for key in [key for key in changes if key in ARM_ONLY_SETTINGS]:
            current = _current_setting(dbs, key)
            if not catalog.validate_value(key, changes[key]) and bool(current):
                raise CliError(f"{key}: {ARM_ONLY_MESSAGE}")
        service = SettingsService(dbs.control, clock=SystemClock())
        try:
            result = _run_async(lambda: service.update(changes, cfg.actor, args.reason or "", source="cli"))
        except SettingsUpdateError as exc:
            problems = dict(exc.errors)
            for issue in exc.cross:
                problems.setdefault(", ".join(issue.keys), issue.message)
            raise CliError("refused, nothing saved: " + "; ".join(f"{k}: {v}" for k, v in problems.items())) from None
    changed = [change.key for change in getattr(result, "changes", [])]
    lines = [
        f"Saved {len(changed)} setting(s): {', '.join(changed) or 'nothing changed'}; every worker reloads within "
        "about a second."
    ]
    emit(cfg, {"changed": changed, "config_version": getattr(result, "config_version", None)}, lines)
    return EXIT_OK


COMMANDS: Final[dict[str, Callable[[Config, argparse.Namespace], int]]] = {
    "status": cmd_status,
    "pause": cmd_pause,
    "resume": cmd_pause,
    "throttle-all": cmd_throttle_all,
    "purge-cache": cmd_purge_cache,
    "reset": cmd_reset,
    "export-llm": cmd_export_llm,
    "health-run": cmd_health_run,
    "backup-now": cmd_backup_now,
    "leader": cmd_leader,
    "jobs": cmd_jobs,
    "bans": cmd_bans,
    "flush-metrics": cmd_flush_metrics,
    "settings": cmd_settings,
}


# ================================================================================================ arguments


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctl.py",
        description="Roxy operator CLI for the server shell (run as the roxy user: sudo -u roxy ...).",
    )
    parser.add_argument("--env-dir", default=str(DEFAULT_ENV_DIR), help="where roxy.env and <color>.env are")
    parser.add_argument("--state-dir", help="the databases' directory (default: ROXY_STATE_DIR from roxy.env)")
    parser.add_argument("--socket", help="one internal socket to use instead of both colors'")
    parser.add_argument("--color", choices=COLORS, help="use only this color's socket")
    parser.add_argument("--nginx-dir", default=str(DEFAULT_NGINX_DIR), help="where roxy-active-upstream.conf is")
    parser.add_argument("--deploy-state-dir", default=str(DEFAULT_DEPLOY_STATE_DIR), help="deploy.sh's records")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    sub.add_parser("status", help="sockets, switches, leader, bans and the last backup")
    for name, text in (("pause", "pause the proxy (503 for every proxy request)"), ("resume", "resume the proxy")):
        command = sub.add_parser(name, help=text)
        command.add_argument("--reason", help="what callers read in the 503 body (kept when omitted); also audited")

    throttle = sub.add_parser("throttle-all", help="switch the emergency per-IP limit on or off")
    throttle.add_argument("state", choices=("on", "off"))
    throttle.add_argument("--reason", help="what refused callers read (kept when omitted); also audited")

    purge = sub.add_parser("purge-cache", help="purge cache entries fleet-wide")
    what = purge.add_mutually_exclusive_group(required=True)
    what.add_argument("--all", action="store_true", help="every entry (needs --yes)")
    what.add_argument("--host", help="every entry of one Roblox host")
    what.add_argument("--pattern", help="entries whose host/path match a glob (or a regex with --regex)")
    what.add_argument("--id", help="one entry by its id")
    what.add_argument("--rule", type=int, help="entries stored under one cache rule id")
    what.add_argument("--expired", action="store_true", help="entries past their lifetime and stale window")
    purge.add_argument("--regex", action="store_true", help="--pattern is a regular expression")
    purge.add_argument("--include-stale", action="store_true", help="with --expired: also those in their stale window")
    purge.add_argument("--preview", action="store_true", help="count what would go; remove nothing")
    purge.add_argument("--yes", action="store_true", help="confirm --all")
    purge.add_argument("--reason", help="for the audit log")

    reset = sub.add_parser("reset", help="data reset scopes (plan 6.8): preview, then run what was previewed")
    reset.add_argument("action", choices=("preview", "run"))
    reset.add_argument("--scope", required=True, help="the scope name (the Data page lists them)")
    reset.add_argument("--family", action="append", help="a metric family (repeat for several)")
    reset.add_argument("--from", dest="start", help="range start (ISO 8601 or Unix seconds)")
    reset.add_argument("--to", dest="end", help="range end (ISO 8601 or Unix seconds)")
    reset.add_argument("--client-type", choices=("ip", "place"))
    reset.add_argument("--client", help="the IP address or place id")
    reset.add_argument("--template", help="an endpoint template")
    reset.add_argument("--cache", choices=("all", "host", "rule", "pattern", "expired"))
    reset.add_argument("--value", help="the host, rule id or pattern of --cache")
    reset.add_argument("--pattern-type", choices=("glob", "regex"), default="glob")
    reset.add_argument("--include-stale", action="store_true")
    reset.add_argument("--bans", choices=("all", "auto", "expired", "detector"))
    reset.add_argument("--detector")
    reset.add_argument("--recommendations", choices=("history", "all"))
    reset.add_argument("--digest", help="run: the preview digest `reset preview` printed")
    reset.add_argument("--reason", help="run: the reason (required when a phrase is asked for)")
    reset.add_argument("--confirm", help="run: the phrase the preview asked to type")

    export = sub.add_parser("export-llm", help="the LLM export (plan 12) to a file")
    export.add_argument("--window", choices=("24h", "7d", "30d"), default="7d")
    export.add_argument("--detail", choices=("summary", "full"), default="summary")
    export.add_argument("--format", choices=("json", "text"), default="json")
    export.add_argument("--out", required=True, help="the file to write (mode 0600)")

    health = sub.add_parser("health-run", help="Check Proxy Health; exit 1 when a check fails")
    health.add_argument("--check", action="append", help="a check id (repeat; default: every check)")
    health.add_argument("--include-credential", action="store_true", help="also H-CRED-AUTH (one Roblox call)")
    health.add_argument("--no-wait", action="store_true", help="start the run and return at once")

    backup = sub.add_parser("backup-now", help="ask the root backup to run now")
    backup.add_argument("--reason", help="for the audit log")
    backup.add_argument("--wait", type=float, default=0.0, help="seconds to wait for the result (default 0)")

    sub.add_parser("leader", help="who leads the fleet, and every worker's heartbeat")
    sub.add_parser("jobs", help="the leader's published job status")

    bans = sub.add_parser("bans", help="list bans, or lift every ban of one subject")
    bans_sub = bans.add_subparsers(dest="action", required=True)
    listing = bans_sub.add_parser("list")
    listing.add_argument("--state", choices=("active", "expired", "all"), default="active")
    listing.add_argument("--search", help="text in the subject or the reason")
    listing.add_argument("--limit", type=int, default=50)
    lift = bans_sub.add_parser("lift")
    lift.add_argument("subject_type", choices=("ip", "cidr", "place", "ua_hash"))
    lift.add_argument("subject")
    lift.add_argument("--reason", help="for the audit log")

    flush = sub.add_parser("flush-metrics", help="every worker flushes its buffered metrics")
    flush.add_argument("--reason", help="for the audit log")

    settings = sub.add_parser("settings", help="show or set runtime settings")
    settings_sub = settings.add_subparsers(dest="action", required=True)
    show = settings_sub.add_parser("show")
    show.add_argument("keys", nargs="*", help="setting keys (default: all)")
    assign = settings_sub.add_parser("set")
    assign.add_argument("assignments", nargs="+", metavar="KEY=VALUE")
    assign.add_argument("--reason", help="for the audit log and the settings history")
    assign.add_argument("--confirm-high-risk", action="store_true", help="confirm a high-risk value")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    out: TextIO | None = None,
    transport: Callable[[Path], httpx.BaseTransport] | None = None,
) -> int:
    output = out or sys.stdout
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0) if isinstance(exc.code, int) else EXIT_USAGE
    cfg = resolve_config(args, output)
    cfg.transport = transport
    try:
        return COMMANDS[args.command](cfg, args)
    except CliError as exc:
        output.write(clean(f"error: {exc}") + "\n")
        return exc.status


if __name__ == "__main__":
    sys.exit(main())
