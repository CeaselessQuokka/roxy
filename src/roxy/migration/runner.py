"""The migrator's main sequence: read v1, migrate the v2 databases, import each part, write the report.

What this is
    `run_migration(options)` performs one migrator run (real or dry) and returns the `MigrationReport`. The
    command line wrapper (`roxy/migration/cli.py`) parses arguments, calls it, and writes the report files.

Why it exists
    Plan 18.3 and MIGRATION.md: the owner runs the migrator once with `--dry-run`, reads the report, then runs it
    for real during the maintenance window, and may run it again safely. The order of the steps matters: the
    built-in defaults are seeded first, so an imported v1 ladder or cache rule replaces a shipped default instead
    of being shadowed by it later, and a deliberately flat v1 ladder stays flat.

How it works
    0. Refuse, writing nothing at all, when `--state-dir` or `--credentials-out` is the v1 root itself, or when the
       v1 root holds no v1 file (a wrong `--v1-root`; otherwise a later run on the right root would be told
       "already imported").
    1. Read the v1 tree (`v1_tree.read_v1_tree`); nothing in it is ever written.
    2. Pick the workspace. A real run uses `--state-dir` and `--credentials-out` directly. A dry run copies the
       existing database files and credential files into a private temporary directory and runs the very same
       steps there, so the report shows exactly what a real run would do; the copies are deleted afterwards.
    3. Apply the expand migrations with the existing runner (`storage.migrate.migrate_paths`), then open the
       databases with the normal storage layer.
    4. Run each step in its own transaction(s); a failing step is reported and the others still run: defaults
       seed, settings (settings service, source `import`), allowed hosts, rules table by table, the ladder,
       pause and throttle-all, the admin account (only with `--import-admin-password`), credential files,
       statistics (metrics.db). Each step consults the import ledger (`roxy/migration/ledger.py`) of earlier
       runs and returns what it handled.
    5. Record the run in `service_state.v1_import`: the ledger of every step that finished, and whether the import
       is complete (an earlier or this run finished with no error), with an audit row. Later runs report "already
       imported", add only v1 items that no earlier run placed, and never put back what the owner changed or
       deleted in v2 since. A run that finds nothing new writes nothing at all.
    6. Scrub the report with every secret value read, then hand it back.

What to read next
    `roxy/migration/cli.py` (arguments and exit codes), `roxy/migration/ledger.py`, then the step modules in the
    order above.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import shutil
import sqlite3
import tempfile
from collections.abc import Awaitable, Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from roxy.config import audit, catalog
from roxy.config.defaults import seed_control_defaults
from roxy.config.runtime import same_value
from roxy.config.settings_service import SettingsService, SettingsUpdateError
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.migration.admin_import import import_admin
from roxy.migration.hosts import HOST_KEY, as_list, collect_hosts, default_hosts, plan_hosts
from roxy.migration.ledger import ImportLedger
from roxy.migration.report import (
    ALREADY,
    IMPORTED,
    INVALID,
    KEPT,
    MIN_SECRET,
    REFUSED,
    REMOVED,
    SKIPPED,
    MigrationReport,
    SecretScrubber,
)
from roxy.migration.rules_import import (
    IMPORT_ACTOR,
    IMPORT_REASON,
    PLACED,
    RULE_ORDER,
    RowPlan,
    apply_rule_table,
    build_rule_plans,
    import_ladder,
    import_service_state,
    plan_service_state,
)
from roxy.migration.secrets_out import write_credential_files
from roxy.migration.stats_import import import_statistics
from roxy.migration.v1_settings import Action, plan_settings
from roxy.migration.v1_tree import V1Tree, read_v1_tree
from roxy.rules.service import RulesService
from roxy.storage.db import DB_NAMES, Databases, open_databases
from roxy.storage.migrate import migrate_paths

log = logging.getLogger(__name__)

MARKER_KEY: Final = "v1_import"
MARKER_VERSION: Final = 2  # 2 added `complete`, `completed_at` and the import ledger
BYPASS_EXPIRY_KEY: Final = "bypass_default_expiry_h"
SETTING_HANDLED: Final = frozenset({IMPORTED, ALREADY, KEPT, REMOVED})

_RECENT_STORES: Final[tuple[str, ...]] = (
    "exploit_attempts",
    "login_attempts",
    "live_requests",
    "traffic_minutes",
    "cache_minutes",
    "tarpit_minutes",
    "token_budget_minutes",
    "ip_activity",
    "callers",
    "endpoints",
    "cache_endpoints",
    "blocked_endpoint_attempts",
    "rate_limited_attempts",
    "header_blocked_attempts",
    "crawls",
    "throttled_ips",
    "rotate_ips",
    "token_usage",
    "tarpit_ips",
    "tarpit_reasons",
    "throttle_tiers",
    "user_agent_rule_hits",
    "proxy_request_counts",
    "method_timings",
)
"""v1 stores that are recent-event rings, per-minute buckets or per-client tables: v2 rebuilds them from its own
rollups, so they are listed as not migrated (their lifetime totals are in legacy_totals where they have one)."""


@dataclass(frozen=True, slots=True)
class Options:
    """One migrator run, as given on the command line."""

    v1_root: Path
    state_dir: Path
    credentials_out: Path | None = None
    dry_run: bool = False
    import_admin_password: bool = False
    v1_state_file: str | None = None  # the v1 ROXY_STATE_FILE value (`--v1-state-file`), read inside the root
    v1_data_file: str | None = None  # the v1 ROXY_DATA_FILE value (`--v1-data-file`), read inside the root


def read_tree(options: Options) -> V1Tree:
    """The v1 tree `options` names (the root, plus the state and data file names v1 was told to use)."""
    return read_v1_tree(options.v1_root, state_file=options.v1_state_file, data_file=options.v1_data_file)


def resolves_inside(path: Path, root: Path) -> bool:
    """Whether `path` is `root` or lies below it once links and `..` are resolved (False when unresolvable)."""
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):
        return False


def _same_directory(path: Path, other: Path) -> bool:
    try:
        return path.resolve() == other.resolve()
    except (OSError, RuntimeError):
        return False


def path_refusals(options: Options) -> list[str]:
    """Why the run must not start, or an empty list. `--credentials-out /etc/roxy` is an easy slip for
    `/etc/roxy/credentials`, and it would set the live v1 directory to mode 0700 and add files to it; the same
    goes for `--state-dir` and the databases (review finding 11). A directory below the v1 root is fine (the plan's
    own layout puts the credentials in `/etc/roxy/credentials`)."""
    problems = []
    for flag, path in (("--state-dir", options.state_dir), ("--credentials-out", options.credentials_out)):
        if path is not None and _same_directory(path, options.v1_root):
            problems.append(
                f"{flag} is the v1 root itself; the migrator never writes into the v1 root. Use another directory "
                "(for the credentials, a subdirectory such as <v1 root>/credentials). Nothing was written"
            )
    return problems


def _no_v1_files(options: Options) -> str:
    return (
        f"--v1-root {str(options.v1_root)[:200]!r} holds none of the v1 files (roxy_state.json, roxy_data.json, "
        "the token, admin, app password and emails files, rotate_proxy.txt); check that it is the copy of "
        "/etc/roxy. Nothing was written"
    )


# --- workspace -------------------------------------------------------------------------------------------------------


@contextlib.contextmanager
def workspace(options: Options) -> Iterator[tuple[Path, Path | None]]:
    """(state directory, credentials directory) to work in: the real ones, or private copies for a dry run."""
    if not options.dry_run:
        yield options.state_dir, options.credentials_out
        return
    with tempfile.TemporaryDirectory(prefix="roxy-migrate-dry-run-") as scratch:
        base = Path(scratch)
        base.chmod(0o700)  # the copies hold secrets and the admin hash; only this user may read them
        state = base / "state"
        state.mkdir(mode=0o700)
        for name in DB_NAMES:
            for suffix in ("", "-wal"):
                source = options.state_dir / f"{name}.db{suffix}"
                if source.is_file():
                    shutil.copy2(source, state / source.name)  # read only on the real directory
        credentials: Path | None = None
        if options.credentials_out is not None:
            credentials = base / "credentials"
            if options.credentials_out.is_dir():
                shutil.copytree(options.credentials_out, credentials)
        yield state, credentials


def _ledger_directory(options: Options) -> str:
    """The credentials directory as the ledger names it: the real one, also in a dry run (which works on a copy)."""
    assert options.credentials_out is not None
    return str(options.credentials_out.resolve())


# --- steps -----------------------------------------------------------------------------------------------------------


async def _step(
    report: MigrationReport,
    name: str,
    run: Callable[[], Awaitable[Any]],
    found: ImportLedger | None = None,
) -> None:
    """Run one step; a failure is recorded (type and a short message) and the next step still runs. What a step
    handled (an `ImportLedger` it returns) joins `found` only when the step finished: a failed step is done in full
    by the next run."""
    try:
        handled = await run()
    except Exception as exc:  # each step is independent; the report says what failed
        log.error("v1_migration_step_failed", extra={"fields": {"step": name, "error": type(exc).__name__}})
        report.error(f"step {name} failed: {type(exc).__name__}: {str(exc)[:300]}")
        return
    if found is not None and isinstance(handled, ImportLedger):
        found.merge(handled)


async def _read_marker(dbs: Databases) -> dict[str, Any] | None:
    row = await dbs.control.read(
        lambda conn: conn.execute("SELECT value_json FROM service_state WHERE key = ?", (MARKER_KEY,)).fetchone()
    )
    if row is None:
        return None
    try:
        value = json.loads(row[0])
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _marker_complete(marker: Mapping[str, Any] | None) -> bool:
    # A version 1 marker has no flag; it was written by a run that counted as complete.
    return marker is not None and marker.get("complete", True) is True


async def _seed(dbs: Databases, report: MigrationReport, clock: Clock) -> None:
    seed = await seed_control_defaults(dbs.control, clock)
    report.defaults_seed = seed.as_dict()
    if not seed.already_seeded:
        report.changed(seed.total_inserted + 1)  # the rows plus the seed marker


async def _current_overrides(service: SettingsService) -> dict[str, Any]:
    exported = await service.export_overrides()
    overrides = exported.get("overrides", {})
    return dict(overrides) if isinstance(overrides, Mapping) else {}


async def _import_settings(
    dbs: Databases, tree: V1Tree, report: MigrationReport, clock: Clock, previous: ImportLedger
) -> ImportLedger:
    decisions = plan_settings(tree.runtime)
    service = SettingsService(dbs.control, clock=clock)
    current = await _current_overrides(service)
    status: dict[str, str] = {}
    pending: dict[str, Any] = {}
    owner: dict[str, str] = {}  # v2 key -> v1 key
    for decision in decisions:
        key = decision.v1_key
        if decision.action is not Action.IMPORT:
            bad = decision.action in (Action.SKIP_INVALID, Action.SKIP_UNREADABLE)
            status[key] = INVALID if bad else SKIPPED
            continue
        target = str(decision.v2_key)
        if key in previous.settings:
            # An earlier run imported this key: never write it again (the owner may have changed or reset it).
            if target in current and same_value(current[target], decision.value):
                status[key] = ALREADY
            elif target in current:
                status[key] = KEPT
                decision.notes.append(
                    f"an earlier run imported it and v2 has {current[target]!r} now; it was not changed"
                )
            else:
                status[key] = REMOVED
                decision.notes.append(
                    "an earlier run imported it and it was reset to the v2 default since; it was not imported again"
                )
            continue
        if target in current:
            if same_value(current[target], decision.value):
                status[key] = ALREADY
            else:
                status[key] = KEPT
                decision.notes.append(f"v2 already has the value {current[target]!r}; it was not changed")
            continue
        if same_value(decision.value, catalog.DEFAULTS[target]):
            status[key] = SKIPPED
            decision.notes.append("the v1 value equals the v2 default, so no override is needed")
            continue
        pending[target] = decision.value
        owner[target] = key

    # Cross-field rules (plan 15.2): leave out every imported key involved in a broken rule, then check again.
    for _ in range(len(pending) + 1):
        merged = {**current, **pending}
        issues = [issue for issue in catalog.validate_cross(merged) if set(issue.keys) & set(pending)]
        if not issues:
            break
        for issue in issues:
            for target in set(issue.keys) & set(pending):
                pending.pop(target)
                status[owner[target]] = SKIPPED
                decision = next(d for d in decisions if d.v1_key == owner[target])
                decision.notes.append(f"not imported: {issue.message}")

    if pending:
        try:
            result = await service.update(pending, IMPORT_ACTOR, IMPORT_REASON, source="import")
            changed = set(result.changed_keys)
        except SettingsUpdateError:
            # Should not happen after the checks above; fall back to one key at a time so one bad value cannot
            # block the rest, and report the refusal of each.
            changed = set()
            for target, value in pending.items():
                try:
                    single = await service.update({target: value}, IMPORT_ACTOR, IMPORT_REASON, source="import")
                    changed |= set(single.changed_keys)
                except SettingsUpdateError as exc:
                    status[owner[target]] = INVALID
                    decision = next(d for d in decisions if d.v1_key == owner[target])
                    decision.notes.append(f"refused by the settings service: {exc}")
        for target in pending:
            if owner[target] in status:
                continue
            status[owner[target]] = IMPORTED if target in changed else ALREADY
        report.changed(len(changed))
    report.settings = [decision.as_report(status.get(decision.v1_key, SKIPPED)) for decision in decisions]
    for decision in decisions:
        # Plan 18.3 asks for a high-risk warning in the report (cache_post_requests), not only a table note
        # (review finding 15): whenever the risky value is in v2 because of the import.
        if decision.warning and status.get(decision.v1_key) in (IMPORTED, ALREADY):
            report.warn(decision.warning)
    return ImportLedger(settings={key for key, value in status.items() if value in SETTING_HANDLED})


def _host_name(host: str) -> str:
    return str(host).lower().removesuffix(".")


async def _import_hosts(
    dbs: Databases, tree: V1Tree, report: MigrationReport, clock: Clock, previous: ImportLedger
) -> ImportLedger:
    evidence = collect_hosts(tree.diagnostics)
    service = SettingsService(dbs.control, clock=clock)
    current = as_list((await _current_overrides(service)).get(HOST_KEY, catalog.DEFAULTS[HOST_KEY]))
    present = {_host_name(host) for host in current}
    # A host an earlier run handled and the owner removed since is never added again (review finding 2).
    removed = sorted(host for host in evidence if host in previous.hosts and host not in present)
    plan = plan_hosts(current, {host: item for host, item in evidence.items() if host not in previous.hosts})
    shipped = set(default_hosts())
    added_now = {item.host for item in plan.added}
    final = {_host_name(host) for host in (plan.new_list or current)}
    status = SKIPPED
    if plan.new_list is not None:
        result = await service.update({HOST_KEY: plan.new_list}, IMPORT_ACTOR, IMPORT_REASON, source="import")
        report.changed(len(result.changes))
        status = IMPORTED
    elif any(host not in shipped for host in evidence):
        status = ALREADY
    report.hosts = {
        "status": status,
        "default_count": len(shipped),
        "seen_count": len(evidence),
        "added": [
            {**item.as_report(), "new_this_run": item.host in added_now}
            for host, item in sorted(evidence.items())
            if host not in shipped and host in final
        ],
        "not_added": plan.not_added,
        "removed_in_v2": removed,
    }
    if plan.not_added:
        report.warn(f"{len(plan.not_added)} host(s) seen in v1 did not fit in allowed_roblox_hosts (200 at most)")
    return ImportLedger(hosts={host for host in evidence if host in final} | set(removed))


def _table_writer(
    table: str, plans: list[RowPlan], now: int, previous: ImportLedger
) -> Callable[[sqlite3.Connection], int]:
    """The transaction body for one rule table (a function, so each loop iteration binds its own table)."""

    def placed_before(v1_key: str) -> bool:
        return previous.has_rule(table, v1_key)

    return lambda conn: apply_rule_table(conn, table, plans, now=now, placed_before=placed_before)


async def _import_rules(
    dbs: Databases,
    tree: V1Tree,
    report: MigrationReport,
    clock: Clock,
    scrubber: SecretScrubber,
    previous: ImportLedger,
) -> ImportLedger:
    service = SettingsService(dbs.control, clock=clock)
    hours_raw = (await _current_overrides(service)).get(BYPASS_EXPIRY_KEY, catalog.DEFAULTS[BYPASS_EXPIRY_KEY])
    now = int(clock.now())
    plans = build_rule_plans(
        tree.runtime, report, now=now, bypass_expiry_hours=int(hours_raw), scrub=scrubber.clean_known
    )
    handled = ImportLedger()
    for table in RULE_ORDER:
        table_plans = plans[table]
        if not table_plans:
            continue
        try:
            written = await dbs.control.write(_table_writer(table, table_plans, now, previous))
            report.changed(written)
            handled.add_rules(table, [plan.v1_key for plan in table_plans if plan.status in PLACED])
        except Exception as exc:  # the table's transaction rolled back: nothing of it was written
            log.error("v1_migration_step_failed", extra={"fields": {"step": table, "error": type(exc).__name__}})
            report.error(f"rules {table} failed: {type(exc).__name__}: {str(exc)[:300]}")
            for plan in table_plans:
                plan.status = INVALID
                plan.v2_id = None
                plan.notes.append("not written: the table's transaction failed and was rolled back")
        for plan in table_plans:
            report.rule_item(table, plan.report_item())
    return handled


async def _import_ladder(
    dbs: Databases,
    tree: V1Tree,
    report: MigrationReport,
    clock: Clock,
    scrubber: SecretScrubber,
    previous: ImportLedger,
) -> ImportLedger:
    written, handled = await import_ladder(
        dbs.control,
        tree.runtime,
        report,
        RulesService(dbs.control, clock=clock),
        scrub=scrubber.clean_known,
        imported_before=previous.ladder,
    )
    report.changed(written)
    return ImportLedger(ladder=handled)


async def _import_service_state(
    dbs: Databases,
    tree: V1Tree,
    report: MigrationReport,
    clock: Clock,
    scrubber: SecretScrubber,
    previous: ImportLedger,
) -> ImportLedger:
    plans = plan_service_state(tree.runtime, report, scrubber.clean_known)
    written = await import_service_state(
        dbs.control, plans, report, now=int(clock.now()), imported_before=previous.service_state
    )
    report.changed(written)
    return ImportLedger(service_state=True)


async def _import_admin(
    dbs: Databases, tree: V1Tree, report: MigrationReport, clock: Clock, options: Options, previous: ImportLedger
) -> ImportLedger:
    handled = await import_admin(
        dbs.control,
        tree.secrets,
        report,
        clock,
        enabled=options.import_admin_password,
        previously=frozenset(previous.admin),
    )
    return ImportLedger(admin=handled)


async def _write_credentials(
    directory: Path, options: Options, tree: V1Tree, report: MigrationReport, previous: ImportLedger
) -> ImportLedger:
    key = _ledger_directory(options)
    names = await asyncio.to_thread(
        write_credential_files,
        directory,
        tree.secrets,
        report,
        previously=frozenset(previous.credential_files(key)),
    )
    return ImportLedger(credentials={key: names})


async def _import_statistics(
    dbs: Databases, tree: V1Tree, report: MigrationReport, clock: Clock, scrubber: SecretScrubber
) -> None:
    if not tree.diagnostics:
        report.statistics["detail"] = "no v1 statistics were readable; nothing was imported"
        return
    await import_statistics(
        dbs.metrics,
        tree.diagnostics,
        report,
        now=int(clock.now()),
        source=tree.statistics_source,
        clean=scrubber.clean_text,
    )


def _not_migrated(tree: V1Tree, report: MigrationReport) -> None:
    runtime = tree.runtime

    def count(name: str) -> int:
        value = runtime.get(name)
        return len(value) if isinstance(value, Mapping) else 0

    security = "security reset: every admin signs in again with the v2 login flow"
    report.not_migrated += [
        {"what": "admin sessions (session epoch)", "count": runtime.get("SessionEpoch", ""), "why": security},
        {"what": "emailed 2FA codes", "count": count("TwoFACodes"), "why": security},
        {"what": "login challenges", "count": count("Challenges"), "why": security},
        {"what": "trusted devices", "count": count("TrustedDevices"), "why": security},
        {"what": "session invalidation links", "count": count("InvalidationTokens"), "why": security},
        {
            "what": "admin HMAC key and Flask session secret",
            "count": sum(1 for v in (tree.secrets.hmac_key, tree.secrets.session_secret) if v),
            "why": "v2 sessions are random ids stored hashed, so these keys have no use",
        },
        {"what": "response cache files", "count": tree.cache_files, "why": "the cache is disposable; v2 starts empty"},
    ]
    if tree.runtime_files:
        report.not_migrated.append(
            {
                "what": "per-worker coordination files: " + ", ".join(tree.runtime_files),
                "count": len(tree.runtime_files),
                "why": "live counters, leases and buckets; v2 keeps them in hot.db and starts fresh",
            }
        )
    present = [name for name in _RECENT_STORES if name in tree.diagnostics]
    if present:
        report.not_migrated.append(
            {
                "what": "recent-event rings, per-minute buckets and per-client tables: " + ", ".join(present),
                "count": len(present),
                "why": "not time series v2 can use (owner decision D17); lifetime totals are in legacy_totals",
            }
        )


async def _write_marker(
    dbs: Databases,
    tree: V1Tree,
    report: MigrationReport,
    clock: Clock,
    marker: dict[str, Any] | None,
    previous: ImportLedger,
    found: ImportLedger,
) -> None:
    """Record this run: the merged import ledger and whether the import is complete (review findings 2 and 6).

    A run with an error leaves `complete` false (unless an earlier run completed), so the next run does not claim
    "already imported" while it still imports what this one left out. Nothing is written when nothing changed.
    """
    now = int(clock.now())
    ledger = ImportLedger()
    ledger.merge(previous)
    ledger.merge(found)
    inputs = dict(sorted(tree.content_hashes.items()))
    was_complete = _marker_complete(marker)
    complete = was_complete or not report.errors
    old = marker or {}
    imported_at = old.get("imported_at") if isinstance(old.get("imported_at"), int) else now
    completed_at = old.get("completed_at") if isinstance(old.get("completed_at"), int) else None
    if complete and completed_at is None:
        completed_at = imported_at if was_complete else now
    value = {
        "version": MARKER_VERSION,
        "imported_at": imported_at,
        "complete": complete,
        "completed_at": completed_at,
        "inputs": old.get("inputs") if isinstance(old.get("inputs"), dict) and old.get("inputs") else inputs,
        "ledger": ledger.to_json(),
    }
    if marker is not None and value == marker and report.changes == 0:
        return  # nothing new: a rerun writes nothing at all
    summary = {"counts": report.counts(), "changes": report.changes, "complete": complete, "inputs": inputs}

    def write(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            (MARKER_KEY, json.dumps(value, sort_keys=True), now),
        )
        audit.record(
            conn, IMPORT_ACTOR, "v1.import", "v1_import", None, summary, IMPORT_REASON, None, at=now, secret=False
        )

    await dbs.control.write(write)
    report.changed()
    if marker is None:
        report.first_imported_at = now


async def _run_steps(
    dbs: Databases,
    tree: V1Tree,
    report: MigrationReport,
    options: Options,
    credentials: Path | None,
    clock: Clock,
    scrubber: SecretScrubber,
) -> None:
    marker = await _read_marker(dbs)
    previous = ImportLedger.from_json(marker.get("ledger")) if marker is not None else ImportLedger()
    if marker is not None:
        imported_at = marker.get("imported_at")
        report.first_imported_at = int(imported_at) if isinstance(imported_at, int) else None
        if _marker_complete(marker):
            report.already_imported = True
        else:
            report.resumed_incomplete_import = True
        if marker.get("inputs") and marker.get("inputs") != dict(sorted(tree.content_hashes.items())):
            report.warn("the v1 state or data file changed since the first import; only new items are added")
    found = ImportLedger()
    await _step(report, "defaults", lambda: _seed(dbs, report, clock))
    await _step(report, "settings", lambda: _import_settings(dbs, tree, report, clock, previous), found)
    await _step(report, "hosts", lambda: _import_hosts(dbs, tree, report, clock, previous), found)
    await _step(report, "rules", lambda: _import_rules(dbs, tree, report, clock, scrubber, previous), found)
    await _step(report, "ladder", lambda: _import_ladder(dbs, tree, report, clock, scrubber, previous), found)
    await _step(
        report,
        "service_state",
        lambda: _import_service_state(dbs, tree, report, clock, scrubber, previous),
        found,
    )
    await _step(report, "admin", lambda: _import_admin(dbs, tree, report, clock, options, previous), found)
    if credentials is not None:
        await _step(
            report, "credentials", lambda: _write_credentials(credentials, options, tree, report, previous), found
        )
    else:
        report.credentials.append(
            {"name": "all", "status": SKIPPED, "detail": "no --credentials-out was given; no credential files written"}
        )
    await _step(report, "statistics", lambda: _import_statistics(dbs, tree, report, clock, scrubber))
    _not_migrated(tree, report)
    await _step(report, "marker", lambda: _write_marker(dbs, tree, report, clock, marker, previous, found))


def _final_status(report: MigrationReport) -> str:
    if report.dry_run:
        return "dry_run_would_change" if report.changes else "dry_run_nothing_to_do"
    if report.errors:
        return "completed_with_errors"
    if report.changes == 0:
        return "already_imported"
    return "imported"


def _refused(report: MigrationReport, problems: list[str], clock: Clock) -> MigrationReport:
    for message in problems:
        report.error(message)
    report.status = REFUSED
    report.finished_at = int(clock.now())
    log.error("v1_migration_refused", extra={"fields": {"problems": len(problems)}})
    return report


async def run_migration(options: Options, *, clock: Clock | None = None) -> MigrationReport:
    """One migrator run (see the module docstring). A refused run (status `refused`) writes nothing at all.
    Raises `V1ReadError` only when the v1 root is not a directory."""
    clock = clock or SYSTEM_CLOCK
    report = MigrationReport(
        dry_run=options.dry_run,
        started_at=int(clock.now()),
        v1_root=str(options.v1_root),
        state_dir=str(options.state_dir),
        credentials_out=str(options.credentials_out) if options.credentials_out else None,
        import_admin_password=options.import_admin_password,
    )
    problems = path_refusals(options)
    if problems:
        return _refused(report, problems, clock)
    tree = await asyncio.to_thread(read_tree, options)
    report.inputs = tree.inputs
    if not tree.has_v1_files:
        return _refused(report, [_no_v1_files(options)], clock)
    for message in tree.warnings:
        report.warn(message)
    for message in tree.errors:
        report.error(message)
    report.sources = {
        "control_plane": tree.runtime_source,
        "statistics": tree.statistics_source,
        "legacy_runtime_ignored": tree.legacy_runtime_ignored,
    }
    if tree.legacy_runtime_ignored:
        report.warn(
            "roxy_data.json still holds a legacy Runtime blob; v1 ignored it because roxy_state.json has one, and "
            "so does the import"
        )
    password = tree.secrets.admin_password
    if password and len(password) < MIN_SECRET:
        report.warn(
            f"the v1 admin password has fewer than {MIN_SECRET} characters, too few to mask in this report and in "
            "imported text without hiding ordinary words, so it is not masked; change it (v2 asks for 14 or more)"
        )
    scrubber = SecretScrubber(
        tree.secrets.secret_values(), credentials=tree.secrets.tokens, pieces=tree.secrets.piece_values()
    )
    log.info("v1_migration_started", extra={"fields": {"dry_run": options.dry_run}})
    try:
        with workspace(options) as (state_dir, credentials):
            paths = {name: state_dir / f"{name}.db" for name in DB_NAMES}
            await asyncio.to_thread(migrate_paths, paths)  # expand migrations, the same runner deploy.sh uses
            dbs = open_databases({"ROXY_STATE_DIR": str(state_dir)})
            try:
                await _run_steps(dbs, tree, report, options, credentials, clock, scrubber)
            finally:
                await dbs.close_all()
    finally:
        report.finished_at = int(clock.now())
        report.status = _final_status(report)
        report.scrub(scrubber)
    log.info(
        "v1_migration_finished",
        extra={"fields": {"status": report.status, "changes": report.changes, "errors": len(report.errors)}},
    )
    return report


__all__ = [
    "MARKER_KEY",
    "Options",
    "path_refusals",
    "read_tree",
    "resolves_inside",
    "run_migration",
    "workspace",
]
