"""Final review, operations lens: deploy, the systemd and nginx pieces, and the migration from v1 (plan 17, 18.2, 18.3).

What this is
    One reproduction per finding of `.remake/final_review/find_ops.md`. Each was a strict xfail until the final
    review fixed its finding; each is a regression test now.

Why it exists
    The final review before go-live: these are the problems the owner would hit while running MIGRATION.md and the
    first deploys on the 909 MB server.

How it works
    The fixtures of the suites the code belongs to: the fake v1 trees and the in-process migrator runner of
    tests/migration, the deploy.sh sandbox of tests/deploy (stub sudo, systemctl, curl and uv), `install-system.sh
    --prefix`, and the production ASGI dispatcher under uvicorn in a thread (as tests/unit/test_ctl.py does) for the
    smoke test. Nothing leaves the machine: the root conftest's socket guard covers the in-process app.

What to read next
    `.remake/final_review/find_ops.md`, then the files each test names.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import os
import socket
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from migration.conftest import _no_v1_environment, migrate, v1, ws  # noqa: F401  (the migration fixtures)
from roxy.config.audit import Actor
from roxy.core.clock import SYSTEM_CLOCK, FakeClock

REPO = Path(__file__).resolve().parents[2]
DEPLOY = REPO / "deploy"
sys.path.insert(0, str(REPO / "tests" / "deploy"))  # deploy_sandbox, a plain module next to the deploy tests

from deploy_sandbox import DeploySandbox  # noqa: E402

ADMIN = Actor("admin", "review", "127.0.0.1")


def load_script(path: Path, name: str) -> ModuleType:
    """A script loaded by path (scripts/ is not a package)."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ============================================================================================ the migrator


async def test_migrator_gives_new_databases_the_state_directory_owner_and_group(v1: Any, ws: Any, migrate: Any) -> None:
    """MIGRATION.md runs the migrator with sudo; every file it creates in /var/lib/roxy (roxy:roxy 0750) is then
    root:root, prestart.py (as roxy) cannot even read control.db, the first deploy fails at step 4 inside the
    outage window, and `ctl.py` refuses ("the databases belong to root"). Lead decision (2): each database file
    the migrator creates gets the state directory's owner and group, mode 0640. Here the state directory belongs
    to another group of the test user, as /var/lib/roxy belongs to roxy while root runs the migrator."""
    other_groups = [gid for gid in os.getgroups() if gid != os.getegid()]
    if not other_groups:
        pytest.skip("the test user belongs to no second group")
    ws.state.mkdir(mode=0o750)
    os.chown(ws.state, -1, other_groups[0])
    v1.small_tree(ws.v1).write()
    old_umask = os.umask(0o022)  # root's usual umask under sudo
    try:
        report = await migrate()
    finally:
        os.umask(old_umask)
    assert report.status == "imported", report.errors
    want = ws.state.stat()
    created = sorted(p for p in ws.state.iterdir() if ".db" in p.name)
    assert created, "the migrator created no database"
    wrong = {
        p.name: (p.stat().st_uid, p.stat().st_gid, oct(stat.S_IMODE(p.stat().st_mode)))
        for p in created
        if (p.stat().st_uid, p.stat().st_gid, stat.S_IMODE(p.stat().st_mode)) != (want.st_uid, want.st_gid, 0o640)
    }
    assert not wrong, f"expected owner {want.st_uid}, group {want.st_gid}, mode 0o640 on every file: {wrong}"


async def test_migrator_fills_an_empty_optional_credential_file(v1: Any, ws: Any, migrate: Any) -> None:
    """install-system.sh creates `rotator_url` empty ("not configured") when it is missing. A migrator run after it
    (MIGRATION.md 6.7's second try, or steps 2.4 and 2.5 done the other way round) finds the file, compares the
    empty text with v1's URL, reports `kept_existing_different` and never writes the URL: v2 runs without the
    rotator. Lead decision (3): an existing EMPTY optional credential file counts as absent."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    ws.credentials.mkdir(mode=0o700)
    empty = ws.credentials / "rotator_url"
    empty.touch(mode=0o600)  # `install -m 0600 /dev/null` in install-system.sh
    report = await migrate()
    item = next(entry for entry in report.credentials if entry["name"] == "rotator_url")
    assert item["status"] == "written", item
    assert empty.read_text(encoding="utf-8").strip() == builder.secrets.rotator_url


FAR_FUTURE_S = 10 * 365 * 86400  # ten years ahead of the migrator's clock


async def test_migrator_rejects_far_future_and_huge_timestamps(v1: Any, ws: Any, migrate: Any) -> None:
    """Lead decision (4): a timestamp more than one day ahead is damage, like a negative one (the patched v1 drops
    such values to 0 itself, `_plausible_time`). Today a far-future LastSeen goes into metrics.db unchanged (the
    Clients and Protection tables sort it first for ten years, and retention never ages it out), and a huge finite
    value, what v1's swinging merge produced on its way to infinity, raises OverflowError in the SQLite insert: the
    whole statistics step rolls back (no v1 429 baseline, no fingerprints, no errors) and a rule table with one
    such `Added` time is not imported at all. Every rerun fails the same way."""
    clock = FakeClock()
    now = int(clock.now())
    builder = v1.small_tree(ws.v1)
    diag = builder.diagnostics
    diag["header_names"]["user-agent"]["LastSeen"] = float(now + FAR_FUTURE_S)
    diag["user_agents"]["Roblox/WinInet"]["LastSeen"] = float(now + FAR_FUTURE_S)
    diag["errors"]["ValueError: bad thing"]["LastSeen"] = float(now + FAR_FUTURE_S)
    diag["exploit_summary"]["Invalid 2FA code"]["LastSeen"] = float(now + FAR_FUTURE_S)
    diag["header_names"]["cookie"]["LastSeen"] = 1e300  # a value on its way to infinity
    builder.runtime["EndpointBlocks"]["games.roblox.com/v1/games/*/servers"]["Added"] = 1e300
    builder.write()
    report = await migrate(clock=clock)
    assert report.errors == [], report.errors
    metrics = sqlite3.connect(f"file:{ws.state / 'metrics.db'}?mode=ro", uri=True)
    control = sqlite3.connect(f"file:{ws.state / 'control.db'}?mode=ro", uri=True)
    try:
        newest = [
            metrics.execute(f"SELECT max(last_seen) FROM {table}").fetchone()[0]
            for table in ("fingerprint_headers", "fingerprint_user_agents", "errors")
        ]
        newest_event_ms = metrics.execute("SELECT max(at_ms) FROM events").fetchone()[0]
        baseline = metrics.execute("SELECT 1 FROM legacy_totals WHERE key = 'v1.roblox_429_total'").fetchone()
        blocks = control.execute("SELECT count(*) FROM rules_endpoint_block").fetchone()[0]
    finally:
        metrics.close()
        control.close()
    assert baseline is not None, "the v1 429 baseline was not imported"
    assert blocks == 2, "the endpoint blocks were not imported"
    assert all(value is not None and value <= now + 86400 for value in newest), newest
    assert newest_event_ms is not None
    assert newest_event_ms <= (now + 86400) * 1000


# ===================================================================================== deploy.sh in its sandbox


@pytest.fixture
def sandbox(tmp_path: Path) -> DeploySandbox:
    """The fake server of tests/deploy with the repository's deploy scripts in /opt/roxy (its conftest fixture)."""
    box = DeploySandbox(tmp_path)
    box.install_deploy_script()
    return box


@pytest.mark.deploy
def test_deploy_can_build_a_release_without_starting_it(sandbox: DeploySandbox) -> None:
    """Lead decision (5). MIGRATION.md 4.6 runs the first deploy after v1 was stopped (4.1), and that deploy first
    fetches the repository and builds the release's Python environment: 5 to 10 minutes of the 15 to 25 minute
    outage. A build-only run (fetch, build the venv, the static files and the stamp; no start, no nginx change)
    done before the window makes 4.6 reuse the built release ("Release ... is already built")."""
    sha = sandbox.make_commit("BUILD_AHEAD")
    result = sandbox.run("--build-only", sha)
    assert result.returncode == 0, result.stdout + result.stderr
    release = sandbox.releases / sha
    assert (release / ".roxy-release-complete").exists()
    assert (release / ".venv" / "bin" / "python").exists()
    calls = sandbox.calls()
    assert not any(call.startswith(("systemctl", "sudo", "roxy-switch-color", "roxy-nginx-apply")) for call in calls)
    assert sandbox.active_color() is None
    sandbox.clear_calls()
    result = sandbox.run(sha, ROXY_DEPLOY_PUBLIC_CHECK="0")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "is already built" in result.stdout
    assert not any(call.startswith("uv sync") for call in sandbox.calls())


@pytest.mark.deploy
def test_retry_of_a_failed_first_deploy_starts_blue_again(sandbox: DeploySandbox) -> None:
    """MIGRATION.md 4.6: "If it fails ... fix the cause and run the same deploy command again", then 4.7 to 4.9 and the
    rollback 6.3 use blue, current-blue and /run/roxy-blue. A first deploy that fails after step 6 (here: blue turns
    unhealthy during the watch) stops blue and removes current-blue, but the active-upstream link it created stays
    on blue. The retry then reads blue as the live color and deploys green: the health gate of 4.7 asks a socket
    that does not exist, the smoke test of 4.8 runs against a stopped color, and 6.3's `systemctl stop roxy@blue`
    leaves green running beside v1 on the 909 MB server."""
    sandbox.flag("unhealthy-after-switch-blue")
    sha = sandbox.make_commit("CUTOVER")
    failed = sandbox.run(sha, ROXY_DEPLOY_PUBLIC_CHECK="0")
    assert failed.returncode != 0, failed.stdout
    assert not sandbox.running("blue")
    sandbox.unflag("unhealthy-after-switch-blue")
    retry = sandbox.run(sha, ROXY_DEPLOY_PUBLIC_CHECK="0")
    assert retry.returncode == 0, retry.stdout + retry.stderr
    assert sandbox.active_color() == "blue", retry.stdout
    assert sandbox.running("blue")
    assert not sandbox.running("green")


# ===================================================================================== the smoke test of a deploy


class LiveColor:
    """The production ASGI dispatcher under uvicorn in a thread: TCP on loopback and the internal Unix socket."""

    def __init__(self, port: int, socket_path: Path) -> None:
        self.port = port
        self.socket_path = socket_path


@pytest.fixture
def live_color(env: Any, dbs: Any, credentials_dir: Path) -> Iterator[Any]:
    """Start a color like roxy@.service would serve it (`create_asgi_app`, both listeners); `start()` returns it."""
    import uvicorn

    from roxy.main import create_asgi_app

    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).write_text("", encoding="utf-8")  # empty: alerts go to the log only
    socket_path = Path(env.internal_socket)
    if len(str(socket_path)) > 100:
        pytest.skip("temporary path too long for a Unix socket")
    started: list[tuple[Any, threading.Thread, list[socket.socket]]] = []

    def start() -> LiveColor:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", 0))
        uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        uds.bind(str(socket_path))
        config = uvicorn.Config(
            create_asgi_app(env), lifespan="on", log_config=None, access_log=False, proxy_headers=False
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=lambda: asyncio.run(server.serve(sockets=[tcp, uds])), daemon=True)
        thread.start()
        started.append((server, thread, [tcp, uds]))
        deadline = time.monotonic() + 90
        while not server.started and time.monotonic() < deadline and thread.is_alive():
            time.sleep(0.05)
        assert server.started, "uvicorn did not start"
        return LiveColor(tcp.getsockname()[1], socket_path)

    try:
        yield start
    finally:
        for server, thread, sockets in started:
            server.should_exit = True
            thread.join(timeout=30)
            for sock in sockets:
                sock.close()


def run_smoke(color: LiveColor, tmp_path: Path) -> tuple[int, str]:
    """scripts/smoke_remote.py exactly as deploy.sh step 5 runs it (proxy check included), against `color`."""
    smoke = load_script(REPO / "scripts" / "smoke_remote.py", "roxy_review_smoke_remote")
    out = io.StringIO()
    with redirect_stdout(out):
        code = smoke.main(
            [
                "--color",
                "dev",
                "--env-dir",
                str(tmp_path / "no-env-files"),
                "--bind",
                f"127.0.0.1:{color.port}",
                "--socket",
                str(color.socket_path),
                "--site-origin",
                "http://localhost",
            ]
        )
    return code, out.getvalue()


async def test_smoke_test_passes_on_a_paused_color_and_says_why(live_color: Any, dbs: Any, tmp_path: Path) -> None:
    """Lead decision (1). v1 paused at copy time makes v2 start paused (parity, it stays), and an owner may pause on
    purpose (the emergency stop of plan 17.8). The smoke test of deploy.sh step 5 then gets Roxy's own 503 pause
    answer for its proxy request, finds no Roxy-Cache header and fails, so the first deploy of the cutover fails in
    the outage window, and later no fix can be deployed while the owner keeps the proxy paused. With /health saying
    Paused, the proxy check must accept Roxy's own pause refusal and say so."""
    from roxy.abuse.pause import set_pause

    await set_pause(dbs.control, SYSTEM_CLOCK, ADMIN, paused=True, reason="Back soon")
    color = await asyncio.to_thread(live_color)
    code, output = await asyncio.to_thread(run_smoke, color, tmp_path)
    proxy_line = next((line for line in output.splitlines() if " proxy " in f" {line} "), "")
    assert code == 0, output
    assert proxy_line.startswith(("PASS", "SKIP")), output
    assert "pause" in proxy_line.lower(), f"the proxy line must say the color is paused: {proxy_line!r}"


async def test_smoke_test_passes_on_a_color_in_throttle_all_and_says_why(
    live_color: Any, dbs: Any, tmp_path: Path, respx_mock: Any
) -> None:
    """The same for throttle-all (v1's emergency limit is imported on the first run too): the smoke test's second
    proxy request gets Roxy's own 429 throttle-all answer (1 request a minute per address by default) and the check
    fails on the missing Roxy-Cache header. Roblox is played by respx; the smoke test's own loopback and socket
    requests pass through to the live color."""
    from roxy.abuse.throttle_all import set_throttle_all

    respx_mock.route(host="127.0.0.1").pass_through()
    respx_mock.route(host="internal").pass_through()
    respx_mock.route(host="users.roblox.com").respond(200, json={"id": 1, "name": "Roblox"})
    await set_throttle_all(dbs.control, SYSTEM_CLOCK, ADMIN, enabled=True, reason="Under attack")
    color = await asyncio.to_thread(live_color)
    code, output = await asyncio.to_thread(run_smoke, color, tmp_path)
    proxy_line = next((line for line in output.splitlines() if " proxy " in f" {line} "), "")
    assert code == 0, output
    assert proxy_line.startswith(("PASS", "SKIP")), output
    assert "throttle" in proxy_line.lower(), f"the proxy line must say throttle-all is on: {proxy_line!r}"


# ===================================================================================== the systemd units


def unit_lines(name: str) -> list[str]:
    """The directive lines of one unit file (comments and blank lines left out)."""
    text = (DEPLOY / "systemd" / name).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


@pytest.mark.deploy
def test_an_oom_kill_of_one_worker_does_not_stop_the_whole_color() -> None:
    """systemd's DefaultOOMPolicy is `stop`: when the kernel OOM-kills any process of the unit (here: one gunicorn
    worker passing the color's MemoryMax=500M), systemd stops the whole unit, then Restart=on-failure starts it
    again after RestartSec, the pre-start step and a cold app start. Only one color serves outside a deploy, so
    every caller gets nginx's 502 for that time. With `OOMPolicy=continue` the kernel's victim is the only casualty
    and gunicorn replaces that worker while the other keeps serving; a killed master still ends the unit and
    Restart= still brings it back. The 909 MB box runs a warm color within 80 MiB of the limit by design (deploy
    README "Memory and swap"), and RUNBOOKS.md "Workers or leader missing" tells the owner to `systemctl reload` a
    warm color, which makes gunicorn start two new workers before the old two leave."""
    lines = unit_lines("roxy@.service")
    assert "OOMPolicy=continue" in lines, [line for line in lines if line.startswith(("OOMPolicy", "Memory"))]


# ======================================================================================= settings import rules


async def test_v1_zero_capture_limits_keep_their_meaning(v1: Any, ws: Any, migrate: Any) -> None:
    """v1 `app/capture.py`: `truncate` cuts a body only `if limit`, and `_prune` drops old captures only `if ttl`, so
    0 meant "no limit" for `capture_max_body` and `capture_ttl_seconds`. In v2, 0 means "store no body text" and
    "captures expire at once". The catalog notes of both settings say the migrator maps a v1 0 to the v2 maximum
    (512 KiB, 86400 s); `v1_settings.py` has no such rule, so plan 18.3's "import only if different from the v1
    default" imports 0 and turns "keep everything" into "keep nothing"."""
    builder = v1.small_tree(ws.v1)
    v1.set_setting(builder.runtime, "capture_max_body", 0)
    v1.set_setting(builder.runtime, "capture_ttl_seconds", 0)
    builder.write()
    await migrate()
    conn = sqlite3.connect(f"file:{ws.state / 'control.db'}?mode=ro", uri=True)
    try:
        stored = {
            key: json.loads(value)
            for key, value in conn.execute(
                "SELECT key, value_json FROM settings WHERE key IN ('capture_max_body', 'capture_ttl_seconds')"
            )
        }
    finally:
        conn.close()
    assert stored.get("capture_max_body") != 0, "v1's 'no limit' became v2's 'no body text'"
    assert stored.get("capture_ttl_seconds") != 0, "v1's 'no age limit' became v2's 'expire at once'"
    if "capture_max_body" in stored:
        assert stored["capture_max_body"] == 512 * 1024, "the catalog note promises the v2 maximum"
    if "capture_ttl_seconds" in stored:
        assert stored["capture_ttl_seconds"] == 86400, "the catalog note promises the v2 maximum"


# ===================================================================================== the shipped package


def test_auth_test_helpers_are_not_in_the_shipped_package() -> None:
    """Lead decision (8): the test helpers (a fast argon2 hasher, test admin accounts, a software passkey, an
    `ensure_auth_routes` that mounts the auth routes on any app) move to tests/ like tests/pages_harness.py, since
    no production module imports them. deploy.sh exports `src/roxy` with `git archive`, so today every release and
    every installed wheel carries them."""
    helper = REPO / "src" / "roxy" / "admin" / "auth" / "testing.py"
    importers = [
        str(path.relative_to(REPO))
        for path in (REPO / "src").rglob("*.py")
        if path != helper and "roxy.admin.auth.testing" in path.read_text(encoding="utf-8")
    ]
    assert not importers, f"production code imports the test helpers: {importers}"
    assert not helper.exists(), "src/roxy/admin/auth/testing.py is part of the shipped package"
