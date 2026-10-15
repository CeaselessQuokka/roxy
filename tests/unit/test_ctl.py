"""scripts/ctl.py and the operator routes of roxy/internal_app.py: the server shell CLI (plan 9.14 list, 12.2, 17.8).

What this is
    Tests of every ctl.py command against real temporary databases (status, pause, resume, throttle-all, purge-cache,
    backup-now, leader, jobs, bans, flush-metrics, settings), and of the socket commands (export-llm, health-run,
    reset preview and run) against the real app served by uvicorn on a real Unix socket in a background thread,
    which is exactly how the CLI reaches a color on the server. Also the one-use proof that guards the destructive
    and revealing socket routes, and the refusals (wrong user, no proof, wrong digest, factory reset).

Why it exists
    The CLI is the way in when the dashboard is unreachable, so it must do what the dashboard does: the same
    validation, an audit row of kind `cli` for every change, changes that reach every worker, and nothing secret
    on the terminal. The deploy user may open the internal socket, so the routes that delete data or reveal raw
    addresses must refuse a caller that cannot write the state directory.

How it works
    `scripts/ctl.py` is loaded by path (scripts are not a package) and `main(argv, out=...)` runs in the test
    thread with a StringIO as its terminal. The databases come from the shared `dbs` fixture (migrated in a temp
    state directory). For the socket tests, `live` starts `create_asgi_app(env)` under uvicorn with only the
    internal Unix socket bound (lifespan on), so the dispatcher, the internal app and the worker context are the
    production ones. Results are read back from the databases with plain sqlite3.

What to read next
    scripts/ctl.py, src/roxy/internal_app.py, then tests/deploy/test_deploy_backup_request.py (the backup request).
"""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import os
import socket
import sqlite3
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

from roxy.internal_app import PROOF_DIR_NAME, PROOF_HEADER, check_proof

REPO = Path(__file__).resolve().parents[2]
OPERATOR = "opsadmin"


@pytest.fixture(scope="module")
def ctl() -> ModuleType:
    spec = importlib.util.spec_from_file_location("roxy_ctl_script", REPO / "scripts" / "ctl.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["roxy_ctl_script"] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def operator(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("SUDO_USER", OPERATOR)
    return OPERATOR


@pytest.fixture
def run(ctl: ModuleType, state_dir: Path, dbs: Any, operator: str, tmp_path: Path) -> Any:
    """`run(*argv) -> (status, output)` against the migrated databases of this test."""
    nginx = tmp_path / "nginx"
    nginx.mkdir()
    deploy_state = tmp_path / "deploy-state"
    deploy_state.mkdir()

    def call(*argv: str, socket_path: Path | None = None) -> tuple[int, str]:
        out = io.StringIO()
        base = [
            "--env-dir",
            str(tmp_path / "no-env"),
            "--state-dir",
            str(state_dir),
            "--nginx-dir",
            str(nginx),
            "--deploy-state-dir",
            str(deploy_state),
        ]
        if socket_path is not None:
            base += ["--socket", str(socket_path)]
        status = ctl.main([*base, *argv], out=out)
        return status, out.getvalue()

    return call


def query(path: Path, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(path)
    try:
        return [tuple(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def audit_rows(state_dir: Path, action: str) -> list[tuple[Any, ...]]:
    return query(
        state_dir / "control.db", "SELECT actor, target, after_json, reason FROM audit_log WHERE action = ?", action
    )


def state_value(state_dir: Path, key: str) -> Any:
    rows = query(state_dir / "control.db", "SELECT value_json FROM service_state WHERE key = ?", key)
    return json.loads(rows[0][0]) if rows else None


# ================================================================================================ pure helpers


def test_operator_name_is_the_login_behind_sudo_and_sanitized(ctl: ModuleType) -> None:
    assert ctl.operator_name({"SUDO_USER": "ali ce;rm -rf"}) == "alicerm-rf"
    assert ctl.operator_name({"SUDO_USER": "x" * 100}) == "x" * 64
    assert ctl.operator_name({"SUDO_USER": ";;;"}) == "ctl"


def test_env_files_and_flags_decide_the_paths(ctl: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("ROXY_"):
            monkeypatch.delenv(name, raising=False)
    env_dir = tmp_path / "etc"
    env_dir.mkdir()
    (env_dir / "roxy.env").write_text('# comment\nROXY_STATE_DIR="/srv/roxy-state"\nROXY_HOT_DB=/fast/hot.db\n')
    (env_dir / "green.env").write_text("ROXY_INTERNAL_SOCKET=/run/roxy-green/custom.sock\n")
    nginx = tmp_path / "nginx"
    nginx.mkdir()
    (nginx / "roxy-active-upstream.conf").symlink_to(nginx / "roxy-upstream-green.conf")
    args = ctl.build_parser().parse_args(["--env-dir", str(env_dir), "--nginx-dir", str(nginx), "status"])
    cfg = ctl.resolve_config(args, io.StringIO())
    assert cfg.state_dir == Path("/srv/roxy-state")
    assert cfg.db_paths["hot"] == Path("/fast/hot.db")
    assert cfg.db_paths["control"] == Path("/srv/roxy-state/control.db")
    assert cfg.sockets == [
        ("green", Path("/run/roxy-green/custom.sock")),
        ("blue", Path("/run/roxy-blue/internal.sock")),
    ], "nginx's color first, then the other"
    args = ctl.build_parser().parse_args(["--env-dir", str(env_dir), "--state-dir", "/x", "--socket", "/s", "status"])
    cfg = ctl.resolve_config(args, io.StringIO())
    assert cfg.db_paths["hot"] == Path("/x/hot.db"), "--state-dir wins over every database path"
    assert cfg.sockets == [("given", Path("/s"))]


def test_output_is_redacted(ctl: ModuleType, fake_secrets: dict[str, str]) -> None:
    out = io.StringIO()
    args = ctl.build_parser().parse_args(["status"])
    cfg = ctl.resolve_config(args, out)
    cookie = fake_secrets["roblox_credential"]
    ctl.emit(cfg, None, [f"leaked .ROBLOSECURITY={cookie}", "bell \x07 here"])
    text = out.getvalue()
    assert cookie not in text
    assert cookie[-30:] not in text
    assert "\x07" not in text
    cfg.as_json = True
    ctl.emit(cfg, {"note": f"https://user:hunter2hunter2@proxy.example.invalid:8000/{cookie}"}, [])
    assert "hunter2hunter2" not in out.getvalue()
    assert cookie not in out.getvalue()


def test_reset_body_matches_the_data_page_form(ctl: ModuleType) -> None:
    parser = ctl.build_parser()
    args = parser.parse_args(
        ["reset", "run", "--scope", "date_range", "--family", "traffic", "--family", "probes", "--from", "2026-09-01",
         "--to", "2026-09-30", "--digest", "a" * 64, "--reason", "clean slate"]
    )  # fmt: skip
    body = ctl.reset_body(args)
    assert body == {
        "scope": "date_range",
        "families": ["traffic", "probes"],
        "from": "2026-09-01",
        "to": "2026-09-30",
        "preview": "a" * 64,
        "reason": "clean slate",
    }
    from roxy.admin.api.data import RunResetBody

    RunResetBody.model_validate(body)  # the shape the internal route validates


# ================================================================================================ the databases


def test_pause_and_resume_are_audited_as_cli(run: Any, state_dir: Path) -> None:
    before = state_value(state_dir, "config_version")
    status, out = run("pause", "--reason", "Maintenance until noon.")
    assert status == 0, out
    assert "paused" in out
    pause = state_value(state_dir, "pause")
    assert pause["paused"] is True
    assert pause["reason"] == "Maintenance until noon."
    assert state_value(state_dir, "config_version") != before, "every worker reloads on the version change"
    rows = audit_rows(state_dir, "pause.set")
    assert rows[-1][0] == f"cli:{OPERATOR}"
    status, out = run("resume")
    assert status == 0, out
    assert state_value(state_dir, "pause")["paused"] is False
    assert state_value(state_dir, "pause")["reason"] == "Maintenance until noon.", "kept across toggles (v1)"
    assert len(audit_rows(state_dir, "pause.set")) == 2


def test_a_reason_with_a_dash_is_refused(run: Any, state_dir: Path) -> None:
    status, out = run("pause", "--reason", "Down " + chr(0x2014) + " back soon")
    assert status == 1
    assert out.startswith("error:")
    assert (state_value(state_dir, "pause") or {}).get("paused") is not True, "nothing was written"


def test_throttle_all_on_and_off(run: Any, state_dir: Path) -> None:
    status, out = run("throttle-all", "on", "--reason", "Flood from a botnet.")
    assert status == 0, out
    state = state_value(state_dir, "throttle_all")
    assert state["enabled"] is True
    assert state["since"] > 0
    assert audit_rows(state_dir, "throttle_all.set")[-1][0] == f"cli:{OPERATOR}"
    status, _ = run("--json", "throttle-all", "off")
    assert status == 0
    assert state_value(state_dir, "throttle_all")["enabled"] is False


def test_purge_cache_previews_audits_and_moves_the_generation(run: Any, state_dir: Path) -> None:
    status, out = run("purge-cache", "--host", "games.roblox.com", "--preview")
    assert status == 0, out
    assert audit_rows(state_dir, "cache.purge") == [], "a preview changes nothing"
    status, out = run("purge-cache", "--all")
    assert status == 1
    assert "--yes" in out
    before = query(state_dir / "cache.db", "SELECT * FROM generation")
    status, out = run("--json", "purge-cache", "--all", "--yes", "--reason", "poisoned entry")
    assert status == 0, out
    answer = json.loads(out)
    assert answer["removed"] == 0
    after = query(state_dir / "cache.db", "SELECT * FROM generation")
    assert after != before, "the generation row moved: every worker drops its memory tier"
    rows = audit_rows(state_dir, "cache.purge")
    assert len(rows) == 1
    assert rows[0][0] == f"cli:{OPERATOR}"
    assert rows[0][1] == "cache:all"
    assert rows[0][3] == "poisoned entry"


def test_purge_with_a_bad_pattern_is_refused(run: Any) -> None:
    status, out = run("purge-cache", "--pattern", "(a|aa)+", "--regex")
    assert status == 1
    assert "not valid" in out


def _ban(state_dir: Path, subject: str, expires_at: int | None) -> None:
    from roxy.config.audit import Actor
    from roxy.rules.service import RulesService
    from roxy.storage.db import open_databases

    dbs = open_databases({"ROXY_STATE_DIR": str(state_dir)})
    try:
        service = RulesService(dbs.control)
        row = {"subject_type": "ip", "subject": subject, "reason_text": "test ban", "expires_at": expires_at}
        asyncio.run(service.create("bans", row, Actor("admin", "owner")))
    finally:
        dbs.close_all_sync()


def test_bans_list_and_lift(run: Any, state_dir: Path) -> None:
    _ban(state_dir, "192.0.2.10", int(time.time()) + 3600)
    status, out = run("bans", "list")
    assert status == 0, out
    assert "192.0.2.10" in out
    status, out = run("bans", "lift", "ip", "192.0.2.10", "--reason", "false positive")
    assert status == 0, out
    assert query(state_dir / "control.db", "SELECT count(*) FROM bans") == [(0,)]
    rows = [row for row in audit_rows(state_dir, "rule.delete") if row[1] == "bans:ip:192.0.2.10"]
    assert rows
    assert rows[-1][0] == f"cli:{OPERATOR}"
    status, out = run("bans", "lift", "ip", "192.0.2.10")
    assert status == 1
    assert "not banned" in out


def test_flush_metrics_asks_every_worker(run: Any, state_dir: Path) -> None:
    status, out = run("flush-metrics", "--reason", "before a restart")
    assert status == 0, out
    assert isinstance(state_value(state_dir, "flush_requested_at"), float)
    assert audit_rows(state_dir, "system.flush")[-1][0] == f"cli:{OPERATOR}"


def test_settings_show_and_set_through_the_settings_service(run: Any, state_dir: Path) -> None:
    status, out = run("settings", "show", "cache_ttl_seconds")
    assert status == 0, out
    assert "(default)" in out
    status, out = run("settings", "set", "cache_ttl_seconds=300", "--reason", "fewer refetches")
    assert status == 0, out
    rows = query(
        state_dir / "control.db", "SELECT value_json, updated_by FROM settings WHERE key = 'cache_ttl_seconds'"
    )
    assert rows == [("300", f"cli:{OPERATOR}")]
    history = query(state_dir / "control.db", "SELECT source FROM settings_history WHERE key = 'cache_ttl_seconds'")
    assert history[-1] == ("cli",)
    status, out = run("--json", "settings", "show", "cache_ttl_seconds")
    assert json.loads(out)["settings"][0]["value"] == 300
    status, out = run("settings", "set", "cache_ttl_seconds=-5")
    assert status == 1
    assert "cache_ttl_seconds" in out
    status, out = run("settings", "set", "no_such_setting=1")
    assert status == 2


def test_high_risk_and_arm_only_settings_need_the_dashboard_rules(run: Any) -> None:
    from roxy.config import catalog
    from roxy.config.spec import Risk, SettingType

    status, out = run("settings", "set", "spam_dry_run=0", "--reason", "arm", "--confirm-high-risk")
    assert status == 1
    assert "Protection page" in out, "arming has its own flow with a collateral preview (plan 10.3)"
    risky = next(
        (
            key
            for key, spec in sorted(catalog.CATALOG.items())
            if spec.risk == Risk.HIGH and spec.type == SettingType.BOOL and not spec.sensitive
        ),
        None,
    )
    if risky is None:
        pytest.skip("no boolean high-risk setting in the catalog")
    value = "0" if catalog.DEFAULTS[risky] else "1"
    status, out = run("settings", "set", f"{risky}={value}")
    assert status == 1
    assert "--confirm-high-risk" in out


def test_backup_now_writes_the_request_the_path_unit_watches(run: Any, state_dir: Path) -> None:
    status, out = run("backup-now", "--reason", "before the migration")
    assert status == 0, out
    request = state_dir / "backup-request"
    document = json.loads(request.read_text())
    assert document["by"] == f"cli:{OPERATOR}"
    assert document["audit_id"] > 0
    assert oct(request.stat().st_mode & 0o777) == oct(0o640)
    assert audit_rows(state_dir, "backup.request")[-1][0] == f"cli:{OPERATOR}"
    assert not list(state_dir.glob(".backup-request.*")), "the temporary file was renamed into place"


def test_backup_now_wait_reads_the_status_file(run: Any, state_dir: Path) -> None:
    audit = state_dir / "audit"
    audit.mkdir()
    later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 5))
    (audit / "backup.json").write_text(
        json.dumps({"last_request": {"at": later, "outcome": "skipped_recent"}, "last_success": {"at": later}})
    )
    status, out = run("backup-now", "--wait", "1")
    assert status == 0, out
    assert "skipped (skipped_recent)" in out


def test_leader_and_jobs(run: Any, state_dir: Path) -> None:
    status, out = run("leader")
    assert status == 0, out
    assert "No worker holds" in out
    from roxy.storage import leases

    conn = sqlite3.connect(state_dir / "hot.db", isolation_level=None)
    conn.execute("BEGIN IMMEDIATE")
    leases.acquire(conn, "leader", "host:1:abcd1234", 15000, int(time.time() * 1000))
    conn.execute("COMMIT")
    conn.close()
    status, out = run("--json", "leader")
    assert json.loads(out)["leader"]["holder"] == "host:1:abcd1234"
    status, out = run("jobs")
    assert "not published" in out
    conn = sqlite3.connect(state_dir / "metrics.db")
    conn.execute(
        "INSERT INTO health_job_status (name, interval_s, last_started_at, last_finished_at, last_ok, holder, "
        "published_at) VALUES ('insights_evaluate', 30, ?, ?, 1, 'host:1:abcd1234', ?)",
        (time.time() - 5, time.time() - 4, int(time.time())),
    )
    conn.commit()
    conn.close()
    status, out = run("jobs")
    assert status == 0, out
    assert "insights_evaluate" in out
    assert "(ok)" in out


def test_status_without_any_color_running(run: Any) -> None:
    status, out = run("--json", "status")
    assert status == 0, out
    data = json.loads(out)
    assert all(item["reachable"] is False for item in data["sockets"])
    assert data["databases"]["paused"] is False
    assert data["databases"]["active_bans"] == 0


def test_database_commands_refuse_another_user(run: Any, monkeypatch: pytest.MonkeyPatch, state_dir: Path) -> None:
    owner = (state_dir / "control.db").stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    status, out = run("pause")
    assert status == 1
    assert "sudo -u" in out
    status, out = run("status")
    assert status == 0, "status still reports the sockets"
    assert "databases: not read" in out


def test_a_missing_database_is_exit_3(ctl: ModuleType, tmp_path: Path, operator: str) -> None:
    out = io.StringIO()
    status = ctl.main(["--state-dir", str(tmp_path / "nothing"), "--env-dir", str(tmp_path), "leader"], out=out)
    assert status == 3
    assert "no Roxy database" in out.getvalue()
    assert not (tmp_path / "nothing").exists(), "the CLI never creates a state directory"


# ================================================================================================ the proof


def _proof(state_dir: Path, *, mode: int = 0o600, age_s: float = 0.0) -> str:
    directory = state_dir / PROOF_DIR_NAME
    directory.mkdir(mode=0o700, exist_ok=True)
    name, secret = os.urandom(8).hex(), os.urandom(32).hex()
    path = directory / name
    path.write_text(secret)
    path.chmod(mode)
    if age_s:
        os.utime(path, (time.time() - age_s, time.time() - age_s))
    return f"{name}:{secret}"


def test_check_proof_accepts_a_fresh_proof_once(state_dir: Path) -> None:
    header = _proof(state_dir)
    assert check_proof(state_dir, header) is True
    assert check_proof(state_dir, header) is False, "one use"
    assert list((state_dir / PROOF_DIR_NAME).iterdir()) == []


@pytest.mark.parametrize("problem", ["wrong_secret", "too_old", "group_readable", "bad_header", "missing"])
def test_check_proof_refuses(state_dir: Path, problem: str) -> None:
    header = _proof(
        state_dir, mode=0o640 if problem == "group_readable" else 0o600, age_s=600 if problem == "too_old" else 0
    )
    if problem == "wrong_secret":
        header = header.split(":")[0] + ":" + "0" * 64
    elif problem == "bad_header":
        header = "../../etc/passwd:" + "0" * 64
    elif problem == "missing":
        header = "0" * 16 + ":" + "0" * 64
    assert check_proof(state_dir, header) is False
    assert check_proof(state_dir, None) is False


def test_check_proof_never_follows_a_linked_directory(state_dir: Path, tmp_path: Path) -> None:
    """A proof directory that is a link proves nothing, even when the file behind it holds the right secret."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (state_dir / PROOF_DIR_NAME).symlink_to(elsewhere)
    name, secret = "ab" * 8, "cd" * 32
    (elsewhere / name).write_text(secret)
    (elsewhere / name).chmod(0o600)
    assert check_proof(state_dir, f"{name}:{secret}") is False
    assert (elsewhere / name).exists(), "nothing behind the link was touched"


def test_check_proof_refuses_a_directory_others_can_write(state_dir: Path) -> None:
    header = _proof(state_dir)
    (state_dir / PROOF_DIR_NAME).chmod(0o770)
    assert check_proof(state_dir, header) is False


# ================================================================================================ the socket


class LiveServer:
    def __init__(self, app: Any, socket_path: Path) -> None:
        self.app = app
        self.socket_path = socket_path


@pytest.fixture
def live(env: Any, dbs: Any) -> Iterator[LiveServer]:
    """The production ASGI dispatcher under uvicorn, bound to the internal Unix socket only, in a thread."""
    import uvicorn

    from roxy.main import create_asgi_app

    socket_path = Path(env.internal_socket)
    if len(str(socket_path)) > 100:
        pytest.skip("temporary path too long for a Unix socket")
    uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uds.bind(str(socket_path))
    app = create_asgi_app(env)
    config = uvicorn.Config(
        app, lifespan="on", log_config=None, access_log=False, proxy_headers=False, server_header=False
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve(sockets=[uds])), daemon=True)
    thread.start()
    deadline = time.monotonic() + 90
    while not server.started and time.monotonic() < deadline and thread.is_alive():
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"
    try:
        yield LiveServer(app, socket_path)
    finally:
        server.should_exit = True
        thread.join(timeout=30)
        uds.close()


def raw_client(live: LiveServer) -> httpx.Client:
    return httpx.Client(
        transport=httpx.HTTPTransport(uds=str(live.socket_path)),
        base_url="http://internal",
        timeout=60,
        trust_env=False,
    )


def test_status_sees_the_running_color(run: Any, live: LiveServer) -> None:
    status, out = run("--json", "status", socket_path=live.socket_path)
    assert status == 0, out
    data = json.loads(out)
    assert data["sockets"][0]["reachable"] is True
    assert data["sockets"][0]["ready"] is True
    assert data["sockets"][0]["config_version"] is not None


def test_export_llm_summary_is_written_private_and_audited(
    run: Any, live: LiveServer, state_dir: Path, tmp_path: Path
) -> None:
    target = tmp_path / "out" / "export.json"
    target.parent.mkdir()
    status, out = run("export-llm", "--window", "24h", "--out", str(target), socket_path=live.socket_path)
    assert status == 0, out
    document = json.loads(target.read_text())
    assert document["schema_version"] == "roxy.llm_export/1"
    assert document["meta"]["generated_by"] == "cli"
    assert target.stat().st_mode & 0o777 == 0o600
    rows = audit_rows(state_dir, "export.download")
    assert rows[-1][0] == f"cli:{OPERATOR}"
    assert rows[-1][1] == "llm_export:summary"
    assert json.loads(rows[-1][2])["ip_addresses"] != "raw"


def test_full_export_needs_the_proof(run: Any, live: LiveServer, tmp_path: Path, state_dir: Path) -> None:
    with raw_client(live) as client:
        refused = client.get("/internal/export/llm", params={"detail": "full"})
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "forbidden"
    assert refused.headers["cache-control"] == "no-store"
    target = tmp_path / "full.json"
    status, out = run("export-llm", "--detail", "full", "--out", str(target), socket_path=live.socket_path)
    assert status == 0, out
    assert json.loads(target.read_text())["meta"]["detail"] == "full"
    assert list((state_dir / PROOF_DIR_NAME).iterdir()) == [], "the proof was used up"


def test_a_caller_that_cannot_write_the_state_directory_cannot_reset(
    ctl: ModuleType, live: LiveServer, tmp_path: Path, operator: str
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        out = io.StringIO()
        status = ctl.main(
            ["--state-dir", str(locked), "--socket", str(live.socket_path), "reset", "run", "--scope", "upstream",
             "--digest", "0" * 64],
            out=out,
        )  # fmt: skip
    finally:
        locked.chmod(0o700)
    assert status == 1
    assert "roxy user" in out.getvalue()


def test_reset_preview_then_run_exactly_what_was_previewed(run: Any, live: LiveServer, state_dir: Path) -> None:
    _ban(state_dir, "198.51.100.7", int(time.time()) - 60)  # expired
    _ban(state_dir, "198.51.100.8", int(time.time()) + 3600)  # still active: stays
    status, out = run(
        "--json", "reset", "preview", "--scope", "bans", "--bans", "expired", socket_path=live.socket_path
    )
    assert status == 0, out
    preview = json.loads(out)
    assert preview["total_rows"] == 1
    digest = preview["preview"]
    status, out = run(
        "reset", "run", "--scope", "bans", "--bans", "all", "--digest", digest, socket_path=live.socket_path
    )
    assert status == 1, "a different scope than the one previewed"
    assert "previewed" in out
    with raw_client(live) as client:
        refused = client.post(
            "/internal/data/resets", json={"scope": "bans", "bans": "expired", "preview": digest, "reason": "x"}
        )
    assert refused.status_code == 403, "no proof"
    status, out = run(
        "reset", "run", "--scope", "bans", "--bans", "expired", "--digest", digest, "--reason", "old bans",
        socket_path=live.socket_path,
    )  # fmt: skip
    assert status == 0, out
    assert query(state_dir / "control.db", "SELECT subject FROM bans") == [("198.51.100.8",)]
    intent = audit_rows(state_dir, "data.reset")
    done = audit_rows(state_dir, "data.reset.done")
    assert intent[-1][0] == f"cli:{OPERATOR}"
    assert done[-1][0] == f"cli:{OPERATOR}"
    assert json.loads(done[-1][2])["deleted"]["control.bans"] == 1


def test_a_reset_that_asks_for_a_phrase_needs_it(run: Any, live: LiveServer) -> None:
    status, out = run("--json", "reset", "preview", "--scope", "limiter", socket_path=live.socket_path)
    assert status == 0, out
    preview = json.loads(out)
    assert preview["confirm_phrase"] == "reset limiters"
    base = ["reset", "run", "--scope", "limiter", "--digest", preview["preview"]]
    status, out = run(*base, "--reason", "forgive everyone", socket_path=live.socket_path)
    assert status == 1
    assert "reset limiters" in out
    status, out = run(*base, "--confirm", "reset limiters", socket_path=live.socket_path)
    assert status == 1, "a phrase-protected reset needs a reason too"
    status, out = run(
        *base, "--confirm", "reset limiters", "--reason", "forgive everyone", socket_path=live.socket_path
    )
    assert status == 0, out


def test_factory_reset_is_dashboard_only(live: LiveServer) -> None:
    with raw_client(live) as client:
        answer = client.post("/internal/data/resets/preview", json={"scope": "factory"})
    assert answer.status_code == 403
    assert "dashboard" in answer.json()["error"]["message"]


def test_route_bodies_are_validated(live: LiveServer) -> None:
    with raw_client(live) as client:
        not_json = client.post(
            "/internal/data/resets/preview", content=b"{oops", headers={"content-type": "application/json"}
        )
        extra = client.post("/internal/data/resets/preview", json={"scope": "upstream", "drop_tables": True})
        unknown = client.post("/internal/health/run", json={"checks": ["H-NOPE"]})
        window = client.get("/internal/export/llm", params={"window": "1y"})
    assert not_json.status_code == 400
    assert not_json.json()["error"]["code"] == "invalid_json"
    assert extra.status_code == 422
    assert unknown.status_code == 422
    assert window.status_code == 422


def test_health_run_over_the_socket(run: Any, live: LiveServer, state_dir: Path) -> None:
    status, out = run("health-run", "--check", "H-CONFIG", socket_path=live.socket_path)
    assert status in (0, 1), out
    assert "H-CONFIG" in out
    runs = query(state_dir / "metrics.db", "SELECT trigger, actor, finished_at FROM health_runs")
    assert runs[-1][0] == "cli"
    assert runs[-1][1] == f"cli:{OPERATOR}"
    assert runs[-1][2] is not None
    assert audit_rows(state_dir, "health.run")[-1][0] == f"cli:{OPERATOR}"
    with raw_client(live) as client:
        refused = client.post("/internal/health/run", json={"checks": ["H-CRED-AUTH"], "include_credential": True})
    assert refused.status_code == 403, "the credential check spends a Roblox call: it needs the proof"


def test_operator_routes_are_not_on_the_public_side(live: LiveServer) -> None:
    from roxy.internal_app import OPERATOR_ROUTES

    async def probe() -> list[int]:
        public = live.app.public
        transport = httpx.ASGITransport(app=public, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return [(await client.request(method, route)).status_code for method, route in OPERATOR_ROUTES]

    assert asyncio.run(probe()) == [404] * len(OPERATOR_ROUTES)


def test_no_color_answering_is_exit_3(run: Any, tmp_path: Path) -> None:
    status, out = run("export-llm", "--out", str(tmp_path / "x.json"), socket_path=tmp_path / "missing.sock")
    assert status == 3
    assert "no color answers" in out


def test_proof_header_name_is_shared(ctl: ModuleType) -> None:
    assert ctl.PROOF_HEADER == PROOF_HEADER


def test_only_the_state_directory_owner_writes_a_proof(
    ctl: ModuleType, state_dir: Path, monkeypatch: pytest.MonkeyPatch, operator: str
) -> None:
    """Root (or anyone else) would leave a proof directory the service refuses and the roxy user cannot use."""
    args = ctl.build_parser().parse_args(["--state-dir", str(state_dir), "status"])
    cfg = ctl.resolve_config(args, io.StringIO())
    owner = state_dir.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    with pytest.raises(ctl.CliError, match="sudo -u"):
        ctl.write_proof(cfg)
    assert not (state_dir / PROOF_DIR_NAME).exists()
    monkeypatch.setattr(os, "geteuid", lambda: owner)
    header = ctl.write_proof(cfg)
    assert check_proof(state_dir, header) is True
