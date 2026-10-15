"""deploy/gunicorn.conf.py and deploy/prestart.py, on paper and with real gunicorn masters (plan 5.2, 5.8, 17.1).

What this is
    Unit tests of the gunicorn settings (every plan 5.2 value, the low-memory marker rules, per-color sockets) and
    of the pre-start step (pending migrations, the VACUUM INTO snapshot, snapshot pruning), plus live tests that
    start the real app under gunicorn with this config: both listeners with 0660 sockets, readiness on the
    internal socket and 404 for /internal on TCP, a graceful stop that runs the lifespan shutdown, the low-memory
    start with one worker and `worker add`, and exactly one leader across a blue and a green master.

Why it exists
    The config is only proven by running it: gunicorn silently ignores a misspelled setting, and the socket mode
    depends on a umask that applies only while gunicorn binds. Plan 19.9 asks for "one leader across colors" and
    "stop flushes metrics" in the deploy tests; plan 17.4 for low-memory mode.

How it works
    Live tests run tests/deploy/gunicorn_live_driver.py inside `unshare -rn` (a private user and network
    namespace with only loopback), so nothing the app does can reach a real system; they are skipped where
    unprivileged namespaces are not allowed. "Stop flushes metrics" stops a master under load (OPTIONS requests
    through the proxy route, which the app answers and records without any upstream) and compares the requests
    the clients saw answered with the totals in metrics.db.

What to read next
    deploy/gunicorn.conf.py, deploy/prestart.py, tests/deploy/gunicorn_live_driver.py.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from deploy_sandbox import DEPLOY, REPO, can_unshare, load_script

pytestmark = [pytest.mark.deploy]


def load_conf(monkeypatch: pytest.MonkeyPatch, **env: str) -> ModuleType:
    for name in list(os.environ):
        if name.startswith("ROXY_"):
            monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return load_script(DEPLOY / "gunicorn.conf.py", f"gunicorn_conf_{abs(hash(tuple(env.items())))}")


def listeners(conf: ModuleType) -> list[str]:
    """Both plan 5.8 listeners, however the config opens them: both in `bind`, or the TCP address in `bind` (each
    worker opening its own with `reuse_port`) and the internal Unix socket that the master creates once
    (`INTERNAL_SOCKET`). The live `sockets` test proves the socket really exists with mode 0660."""
    found = list(conf.bind)
    internal = getattr(conf, "INTERNAL_SOCKET", None)
    if internal is not None and f"unix:{internal}" not in found:
        found.append(f"unix:{internal}")
    return found


# ------------------------------------------------------------------------------------------ gunicorn.conf.py


def test_settings_follow_plan_5_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    conf = load_conf(
        monkeypatch,
        ROXY_COLOR="green",
        ROXY_BIND="127.0.0.1:8002",
        ROXY_INTERNAL_SOCKET="/run/roxy-green/internal.sock",
        ROXY_WORKERS="2",
        ROXY_DEPLOY_STATE_DIR=str(tmp_path),
    )
    assert conf.worker_class == "roxy.worker.RoxyUvicornWorker"
    assert conf.workers == 2
    assert listeners(conf) == ["127.0.0.1:8002", "unix:/run/roxy-green/internal.sock"]
    # Each worker opens its own TCP listener (SO_REUSEPORT) so the kernel spreads connections; the Unix socket
    # cannot be shared that way, so it stays out of `bind` and the master's hooks create and hand it out.
    assert conf.reuse_port is True
    assert conf.bind == ["127.0.0.1:8002"]
    assert conf.INTERNAL_SOCKET == "/run/roxy-green/internal.sock"
    assert all(callable(getattr(conf, hook)) for hook in ("on_starting", "pre_fork", "post_fork", "on_exit"))
    assert 0o777 & ~conf.umask == 0o660, "the internal socket is created 0660"
    assert conf.timeout == 30
    assert conf.graceful_timeout == 30
    assert conf.keepalive == 75
    assert conf.max_requests == 20000
    assert conf.max_requests_jitter == 2000
    assert conf.preload_app is False
    assert conf.accesslog is None
    assert conf.errorlog == "-"
    assert conf.proc_name == "roxy-green"
    assert conf.control_socket == "/run/roxy-green/gunicorn.ctl"
    assert conf.control_socket_mode == 0o660
    assert not hasattr(conf, "forwarded_allow_ips"), "proxy headers are off; client_ip.py reads XFF (plan 9.11)"


def test_every_setting_is_a_real_gunicorn_setting_and_commented() -> None:
    """gunicorn ignores unknown names, so a typo would silently do nothing. Every setting has a comment above it."""
    from gunicorn.config import KNOWN_SETTINGS

    known = {setting.name for setting in KNOWN_SETTINGS}
    lines = (DEPLOY / "gunicorn.conf.py").read_text().splitlines()
    settings_seen = []
    for index, line in enumerate(lines):
        if line and not line.startswith((" ", "#", "_", "def", "class", "from", "import", '"""')) and " = " in line:
            name = line.split(" = ", 1)[0]
            if name.isupper():
                continue  # module constants such as START_WORKERS_MAX_AGE_S
            settings_seen.append(name)
            assert name in known, f"{name} is not a gunicorn setting"
            assert lines[index - 1].startswith("#"), f"{name} has no comment above it"
    assert {
        "worker_class",
        "workers",
        "reuse_port",
        "bind",
        "umask",
        "timeout",
        "graceful_timeout",
        "keepalive",
        "max_requests",
        "max_requests_jitter",
        "preload_app",
        "accesslog",
        "errorlog",
        "loglevel",
        "control_socket",
    } <= set(settings_seen)


def test_max_requests_zero_disables_recycling(monkeypatch: pytest.MonkeyPatch) -> None:
    conf = load_conf(monkeypatch, ROXY_MAX_REQUESTS="0")
    assert conf.max_requests == 0
    assert conf.max_requests_jitter == 0


@pytest.mark.parametrize(("raw", "expected"), [("x", 2), ("0", 2), ("99", 2), ("4", 4), ("", 2)])
def test_bad_worker_counts_fall_back(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw: str, expected: int) -> None:
    conf = load_conf(monkeypatch, ROXY_WORKERS=raw, ROXY_DEPLOY_STATE_DIR=str(tmp_path))
    assert conf.workers == expected


def test_low_memory_marker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    conf = load_conf(monkeypatch, ROXY_DEPLOY_STATE_DIR=str(tmp_path))
    marker = tmp_path / "start-workers-blue"
    assert conf.start_workers(2, marker) == 2  # no marker: normal start
    marker.write_text("1\n")
    assert conf.start_workers(2, marker) == 1
    for garbage in ("0", "3", "one", "", "-1", "1; rm -rf /"):
        marker.write_text(garbage)
        assert conf.start_workers(2, marker) == 2, garbage
    marker.write_text("1")
    old = time.time() - conf.START_WORKERS_MAX_AGE_S - 60
    os.utime(marker, (old, old))
    assert conf.start_workers(2, marker) == 2, "a stale marker from a failed deploy is ignored"
    assert conf.start_workers(2, marker, now=old + 10) == 1


def test_low_memory_marker_is_per_color(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "start-workers-green").write_text("1")
    blue = load_conf(monkeypatch, ROXY_COLOR="blue", ROXY_DEPLOY_STATE_DIR=str(tmp_path))
    green = load_conf(monkeypatch, ROXY_COLOR="green", ROXY_DEPLOY_STATE_DIR=str(tmp_path), ROXY_WORKERS="2")
    assert blue.workers == 2
    assert green.workers == 1


def test_internal_socket_default_is_per_color(monkeypatch: pytest.MonkeyPatch) -> None:
    conf = load_conf(monkeypatch, ROXY_COLOR="blue")
    assert listeners(conf)[1] == "unix:/run/roxy-blue/internal.sock"
    assert conf.control_socket == "/run/roxy-blue/gunicorn.ctl"


# ------------------------------------------------------------------------------------------------ prestart


@pytest.fixture
def prestart() -> ModuleType:
    return load_script(DEPLOY / "prestart.py", "roxy_prestart_for_tests")


def test_prestart_snapshot_and_prune(prestart: ModuleType, tmp_path: Path) -> None:
    from roxy.storage.migrate import migrate_paths

    paths = {name: tmp_path / f"{name}.db" for name in ("control", "hot", "metrics", "cache")}
    migrate_paths(paths)
    assert prestart.pending_migrations(paths) == {}
    conn = sqlite3.connect(paths["control"])
    conn.execute("DELETE FROM schema_version")  # pretend this release ships a migration control.db lacks
    conn.commit()
    conn.close()
    assert prestart.pending_migrations(paths) == {"control": ["0001_initial"]}
    snapshots = tmp_path / "snapshots"
    for second in range(12):
        target = prestart.snapshot_control(paths["control"], snapshots, "abc123", now=1_700_000_000 + second)
        os.utime(target, (1_700_000_000 + second, 1_700_000_000 + second))
    kept = sorted(p.name for p in snapshots.iterdir())
    assert len(kept) == prestart.KEEP_SNAPSHOTS
    assert kept[0].startswith("pre-migrate-")
    assert kept[0].endswith("-abc123.db")
    copy = sqlite3.connect(snapshots / kept[-1])
    assert copy.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert copy.execute("SELECT count(*) FROM sqlite_master WHERE name = 'settings'").fetchone()[0] == 1
    copy.close()
    assert (snapshots / kept[-1]).stat().st_mode & 0o777 == 0o640


def test_prestart_release_label(prestart: ModuleType, tmp_path: Path) -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    release = tmp_path / "opt" / "roxy" / "releases" / sha
    release.mkdir(parents=True)
    link = tmp_path / "opt" / "roxy" / "releases" / "current-blue"
    link.symlink_to(release)
    assert prestart.release_label(link) == sha[:12]
    assert prestart.release_label(tmp_path) == "unknown"


def test_prestart_end_to_end(tmp_path: Path, credentials_dir: Path) -> None:
    """The unit's ExecStartPre: creates and migrates the databases, seeds defaults once, and is idempotent."""
    env = {
        "PATH": f"{REPO / '.venv' / 'bin'}:/usr/bin:/bin",
        "ROXY_ENV": "production",
        "ROXY_STATE_DIR": str(tmp_path / "state"),
        "CREDENTIALS_DIRECTORY": str(credentials_dir),
    }
    python = str(REPO / ".venv" / "bin" / "python")
    first = subprocess.run([python, str(DEPLOY / "prestart.py")], env=env, capture_output=True, text=True, check=False)
    assert first.returncode == 0, first.stdout + first.stderr
    assert "creating control.db, hot.db, metrics.db, cache.db" in first.stdout
    second = subprocess.run([python, str(DEPLOY / "prestart.py")], env=env, capture_output=True, text=True, check=False)
    assert second.returncode == 0, second.stderr
    assert "schema is current; nothing to migrate" in second.stdout
    conn = sqlite3.connect(tmp_path / "state" / "control.db")
    seeded = conn.execute("SELECT count(*) FROM service_state WHERE key LIKE 'defaults%'").fetchone()[0]
    conn.close()
    assert seeded == 1


def test_prestart_reports_contract_migrations_and_never_runs_them(
    prestart: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Plan 17.4 step 3: contract migrations run "one release later". Run automatically they would break every
    older kept release a rollback can start, so the pre-start step only names them (the owner runs them by hand,
    deploy/README.md) and applies expand migrations only."""
    from roxy.storage.migrate import discover, migrate_paths

    state = tmp_path / "state"
    state.mkdir()
    paths = {name: state / f"{name}.db" for name in ("control", "hot", "metrics", "cache")}
    migrate_paths(paths)
    contract = SimpleNamespace(kind="contract", version=9999, label="9999_drop_old_column")
    monkeypatch.setattr(
        prestart, "discover", lambda name: [*discover(name), *([contract] if name == "control" else [])]
    )
    assert prestart.pending_migrations(paths, "contract") == {"control": ["9999_drop_old_column"]}
    assert prestart.pending_migrations(paths) == {}, "a contract migration is never counted as an expand one"
    migrate_calls: list[list[str]] = []

    def fake_migrate(argv: list[str]) -> int:
        migrate_calls.append(list(argv))
        return 0

    monkeypatch.setattr(prestart, "migrate_main", fake_migrate)
    monkeypatch.setattr("roxy.config.defaults.main", lambda argv: 0)
    assert prestart.main(environ={"ROXY_STATE_DIR": str(state)}) == 0
    out = capsys.readouterr().out
    assert "contract migrations pending (control: 9999_drop_old_column)" in out
    assert "never run automatically" in out
    assert migrate_calls == [["--expand"]]


def test_prestart_fails_cleanly_on_a_broken_database(tmp_path: Path, credentials_dir: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    (state / "control.db").write_bytes(b"this is not a database" * 100)
    env = {"PATH": "/usr/bin:/bin", "ROXY_STATE_DIR": str(state), "CREDENTIALS_DIRECTORY": str(credentials_dir)}
    result = subprocess.run(
        [str(REPO / ".venv" / "bin" / "python"), str(DEPLOY / "prestart.py")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "prestart:" in result.stderr


# -------------------------------------------------------------------------------------------- live gunicorn


def run_driver(scenario: str, tmp_path: Path, credentials_dir: Path, timeout: float = 150) -> dict[str, Any]:
    if sys.platform != "linux" or not can_unshare() or not (shutil.which("ip") or Path("/usr/sbin/ip").exists()):
        pytest.skip("live gunicorn tests need unprivileged user and network namespaces (unshare -rn) and ip")
    if not (REPO / ".venv" / "bin" / "gunicornc").exists():
        pytest.skip("gunicorn 25.1 or later (gunicornc) is not installed")
    work = tmp_path / "work"
    work.mkdir()
    result = subprocess.run(
        [
            "unshare",
            "-rn",
            str(REPO / ".venv" / "bin" / "python"),
            str(Path(__file__).parent / "gunicorn_live_driver.py"),
            scenario,
            str(work),
            str(credentials_dir),
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    return dict(json.loads(result.stdout.strip().splitlines()[-1]))


@pytest.mark.multiprocess
def test_gunicorn_listeners_sockets_and_graceful_stop(tmp_path: Path, credentials_dir: Path) -> None:
    """Plan 5.8 and 17.1: TCP and a 0660 internal socket; /internal only on the socket; SIGTERM (systemd's
    KillMode=mixed stop) runs every worker's lifespan shutdown and the master exits 0 in time."""
    out = run_driver("sockets", tmp_path, credentials_dir)
    log = out["log_tail"]
    assert out["prestart_code"] == 0, out["prestart_output"]
    assert out["prestart_again_code"] == 0
    assert out["ready"] is True, log
    assert out["ready_body"]["Ready"] is True
    assert out["ready_body"]["PersistenceOK"] is True
    assert out["internal_socket_mode"] == "0660"
    assert out["control_socket_mode"] == "0660"
    assert out["tcp_internal_version"] == 404, "internal endpoints never answer on the public port"
    assert out["tcp_internal_version_detail"] == '"Not Found"\n', "the public app's own 404, not a proxy refusal"
    assert out["tcp_internal_version_seconds"] < 5, "answered at once, never held by the tarpit"
    assert out["uds_version"][0] == 200
    assert json.loads(out["uds_version"][1])["Color"] == "blue"
    assert out["tcp_home"] == 200
    # scripts/smoke_remote.py against the real app. Checks whose router another phase has not built yet may fail
    # (they then name exactly that check); once the router module exists, its check must pass.
    not_built = {
        name
        for name, module in (("health", "roxy.public.health"), ("admin_login", "roxy.admin.router"))
        if importlib.util.find_spec(module) is None
    }
    failed = {line.split()[1] for line in out["smoke_output"].splitlines() if line.startswith("FAIL")}
    assert failed <= not_built, out["smoke_output"]
    assert out["smoke_code"] == (1 if failed else 0), out["smoke_output"]
    assert out["stats"]["workers_current"] == 2
    assert out["master_ready_line"] is True, log
    assert out["heartbeats_running"] == 2
    assert out["stop_code"] == 0, log
    assert out["stop_seconds"] < 45, "inside TimeoutStopSec"


@pytest.mark.multiprocess
def test_stop_flushes_metrics(tmp_path: Path, credentials_dir: Path) -> None:
    """Plan 17.1 test_stop_flushes_metrics: a color stopped (SIGTERM, systemd's KillMode=mixed stop) while eight
    clients keep sending requests; afterwards the request totals in metrics.db equal the requests the clients saw
    answered. Every worker ran its lifespan shutdown, which flushes the batch writer synchronously and removes
    its heartbeat row, and the master exited 0 inside TimeoutStopSec."""
    out = run_driver("flush", tmp_path, credentials_dir)
    log = out["log_tail"]
    assert out["prestart_code"] == 0, out["prestart_output"]
    assert out["ready"] is True, log
    assert out["served_before_stop"] > 0, out
    assert out["served"] >= out["served_before_stop"]
    assert out["recorded"] == out["served"], out
    assert out["stop_code"] == 0, log
    assert out["stop_seconds"] < 45, "inside TimeoutStopSec"
    assert out["worker_stopped_lines"] >= 2, log
    assert out["heartbeats_after"] == 0, "every worker ran its shutdown (heartbeat rows are removed there)"
    assert set(out["other_statuses"]) <= {"0"}, "requests either got their 204 or never reached a worker"


@pytest.mark.multiprocess
def test_low_memory_start_then_worker_add(tmp_path: Path, credentials_dir: Path) -> None:
    """DESIGN.md section 0: the marker starts the color with 1 worker; `gunicornc worker add` (SIGTTIN's code path)
    brings it to ROXY_WORKERS without restarting the running worker."""
    out = run_driver("lowmem", tmp_path, credentials_dir)
    assert out["ready"] is True, out["log_tail"]
    assert out["master_ready_line"] is True, out["log_tail"]
    assert out["stats_start"]["workers_current"] == 1
    assert out["worker_add"].get("total") == 2
    assert out["stats_after"]["workers_current"] == 2
    assert out["ready_after"] is True
    assert out["stop_code"] == 0


@pytest.mark.multiprocess
def test_one_leader_across_colors(tmp_path: Path, credentials_dir: Path) -> None:
    """Plan 17.4 and 19.9: during a deploy both colors run on the same databases, and exactly one worker in total
    leads; when the leading color stops, a worker of the other color takes over under a higher epoch."""
    out = run_driver("leader", tmp_path, credentials_dir, timeout=200)
    assert out["ready"] is True, out["log_tail_blue"] + out["log_tail_green"]
    for sample in out["steady_samples"]:
        colors = {row["color"] for row in sample}
        assert colors == {"blue", "green"}, sample
        leaders = [row for row in sample if row["is_leader"]]
        assert len(leaders) == 1, f"exactly one leader across both colors: {sample}"
        assert leaders[0]["worker_id"] == out["lease_before"]["holder"]
    assert out["stop_code"] == 0
    assert out["after_rows"], "the other color took over leadership"
    assert out["lease_after"]["epoch"] > out["lease_before"]["epoch"]
    new_leader = [row for row in out["after_rows"] if row["is_leader"]]
    assert len(new_leader) == 1
    assert new_leader[0]["color"] == out["other_color"]
