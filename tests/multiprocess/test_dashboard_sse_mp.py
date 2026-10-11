"""The dashboard's event stream across real gunicorn workers (plan 14.11, C6): a page on worker B sees worker A.

What this is
    One test that starts gunicorn as roxy@.service does (`gunicorn -c deploy/gunicorn.conf.py roxy.asgi:app`, 2
    workers, `reuse_port`) inside `unshare -rn` (a namespace with nothing but loopback), signs an admin in through the
    real password and TOTP steps, and opens the dashboard in headless Chromium. The browser's event streams all run
    on one worker, B; everything the dashboard must notice is done through the other worker, A:
      * a proxy request served by worker A appears as a row in the Live page's tail;
      * the Overview's `kpi` frames (computed by worker B from the shared metrics.db) count it, and the Overview's
        "Total requests" tile shows the new number on its next stream-driven refresh;
      * a settings change saved through worker A (`PUT /admin/api/v1/settings/{key}`) reaches worker B's stream as
        `settings_changed`, and the open inline editor of that setting on the Live page re-renders with the new value.
    This file is also its own driver: run as a script inside the namespace it prints one JSON object, and the test
    asserts on it.

Why it exists
    The in-process tests run every worker in one process, and `test_sse_mp.py` drives the stream over ASGI with a
    second process writing the database. Only real workers behind one port, with a real browser holding the streams,
    show that a dashboard connected to any worker follows what every worker does (plan 14.11: "a dashboard connected
    to worker A sees events produced on worker B"), including the page scripts that act on the frames.

How it works
    Which worker holds a stream: each stream takes a fleet-wide slot lease in hot.db (`sse:<session>:<n>`) whose
    holder starts with the worker id (`roxy/admin/sse.py`), read here from the database. The kernel spreads new
    connections over the workers' listeners by a hash of the client port (`reuse_port`), so a page is opened in a
    fresh browser context until all of its streams landed on one worker (bounded attempts; that worker is B), and a
    second page until its stream did too. Worker A is reached over one keep-alive connection that worker A accepted:
    a new connection is opened until `GET /admin/api/v1/system/leader` (its `this_worker`) names A, and every request
    of the producer goes over that connection, checked before and after by the same question and the same local
    port. The workers' heartbeats (`proxied`, per process) confirm that worker A served the proxy requests and worker
    B served none. Every wait is bounded; the port is the kernel's choice (never a fixed number).

What to read next
    roxy/admin/sse.py, static/js/sse.js, static/js/live_tail.js, static/js/cards.js, static/js/settings_api.js,
    tests/multiprocess/gunicorn_mp_driver.py (mock Roblox, state, `Master`), tests/multiprocess/test_sse_mp.py.
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
WORKERS = 2
SETTING = "capture_max_records"
"""An inline setting of the Live page (`live#capture`), low risk, no second factor."""
NEW_VALUE = 2345
PLACE = "73001942"
"""The `Roblox-Id` of the producer's proxy requests: the Live row is found by it."""
CLIENT = "198.51.100.73"
PRODUCED = 2
"""Proxy requests made through worker A."""

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform != "linux", reason="real gunicorn workers need Linux"),
]


# ------------------------------------------------------------------------------------------------- the test


def _can_unshare() -> bool:
    try:
        result = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


@pytest.mark.timeout(420)
def test_a_dashboard_on_worker_b_follows_what_worker_a_does(tmp_path: Path, credentials_dir: Path) -> None:
    if not _can_unshare() or not (shutil.which("ip") or Path("/usr/sbin/ip").exists()):
        pytest.skip("needs unprivileged user and network namespaces (unshare -rn) and ip")
    if not (REPO / ".venv" / "bin" / "gunicorn").exists():
        pytest.skip("gunicorn is not installed in .venv")
    pytest.importorskip("playwright.sync_api")
    quiet = tmp_path / "creds"
    quiet.mkdir(mode=0o700)
    for path in credentials_dir.iterdir():
        if path.name not in ("smtp_password", "alert_webhook_url"):  # alerts stay in the log
            (quiet / path.name).write_bytes(path.read_bytes())
            (quiet / path.name).chmod(0o600)
    work = tmp_path / "w"
    result = subprocess.run(
        ["unshare", "-rn", str(REPO / ".venv" / "bin" / "python"), __file__, str(work), str(quiet)],
        capture_output=True,
        text=True,
        timeout=400,
        check=False,
        cwd=REPO,
    )
    lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    failure = f"driver failed ({result.returncode}):\n{result.stderr[-4000:]}"
    assert result.returncode == 0, failure
    assert lines, failure
    out = json.loads(lines[-1])
    print("\n" + json.dumps({key: value for key, value in out.items() if key != "log_tail"}))
    log = out.get("log_tail", "")
    if out.get("skip"):
        pytest.skip(out["skip"])
    assert out["ready"], log
    assert out.get("error") is None, (out.get("error"), log)
    pids = out["worker_pids"]
    assert len(pids) == WORKERS, log
    b, a = out["worker_b"], out["worker_a"]
    assert a != b, out
    assert {a, b} == set(pids), out

    # Every stream of both pages runs on worker B (the slot leases name their holder).
    assert out["live_page_streams"] == [b, b], out
    assert out["overview_stream"] == b, out

    # Worker A served the producer: the same keep-alive connection before and after, and the heartbeats agree.
    for name in ("proxy", "setting"):
        producer = out["producer"][name]
        assert producer["before"] == producer["after"] == a, producer
        assert producer["same_connection"], producer
    proxied = {int(pid): delta for pid, delta in out["proxied_delta"].items()}
    assert proxied[a] == PRODUCED, proxied
    assert proxied[b] == 0, proxied
    assert out["proxy_statuses"] == [200] * PRODUCED, out["proxy_statuses"]

    # 1. The Live page on worker B shows worker A's request as a row.
    assert out["live_row"], out
    assert PLACE in out["live_row"], out["live_row"]
    assert CLIENT in out["live_row"], out["live_row"]

    # 2. Worker B's `kpi` frames count worker A's requests, and the Overview tile shows the new number.
    frames = out["kpi_requests"]
    assert frames, out
    assert frames[0] == 0, frames
    assert max(frames) >= PRODUCED, frames
    assert out["kpi_tile_before"] == "0", out
    assert out["kpi_tile_after"] == str(PRODUCED), out
    # ... on a stream-driven refresh, at most once a minute although a `kpi` frame comes every 2 seconds.
    loads = out["kpi_card_loads_ms"]
    assert loads, out
    assert all(later - earlier >= TILE_REFRESH_MIN_MS for earlier, later in itertools.pairwise(loads)), loads

    # 3. The settings change saved through worker A re-rendered the open inline editor on worker B.
    setting = out["setting"]
    assert setting["status"] == 200, setting
    assert setting["editor_before"] != str(NEW_VALUE), setting
    assert setting["editor_after"] == str(NEW_VALUE), setting
    assert setting["settings_changed_frames"] >= 1, setting

    assert out["browser_problems"] == [], out["browser_problems"]
    assert out["stop_code"] == 0, log


# ------------------------------------------------------------------------------------------------ the driver

ATTEMPTS = 12
"""Fresh browser contexts tried for a page whose streams must land on one worker (each try is a coin flip)."""
PRODUCER_ATTEMPTS = 40
"""Fresh connections tried until worker A accepts one (each about one in two)."""
STREAM_WAIT_S = 15.0
ROW_WAIT_S = 20.0
KPI_FRAME_WAIT_S = 20.0
TILE_WAIT_S = 90.0
"""The Overview's tiles refresh on a `kpi` frame at most once a minute (`overview.py kpis_card`, refresh_min_s 60)."""
EDITOR_WAIT_S = 20.0
HEARTBEAT_WAIT_S = 20.0
STATE_SETTINGS: dict[str, Any] = {
    "rotator_enabled": 0,
    "tarpit_enabled": 0,
    "health_auto_interval_h": 0,  # no scheduled health run probing in the background
    "insights_enabled": 0,  # no recommendation events: the frames counted here are the test's
}
SETTLED = "() => !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added')"
KPI_RECORDER = """() => {
  window.__kpiRequests = [];
  window.__kpiCardLoads = [];
  document.addEventListener("roxy:sse:kpi", (event) => {
    const data = event.detail && event.detail.data;
    if (data && data.values) window.__kpiRequests.push(Number(data.values.requests));
  });
  document.addEventListener("htmx:beforeRequest", (event) => {
    const config = event.detail && event.detail.requestConfig;
    if (config && String(config.path || "").includes("/fragment/kpis")) window.__kpiCardLoads.push(performance.now());
  });
}"""
"""Observers only (installed through the DevTools protocol, outside the page's CSP): the `kpi` frames' request
counts, and when the KPI tiles card asked the server for a refresh."""
TILE_REFRESH_MIN_MS = 59_000
"""Two refreshes of the tiles card are a minute apart (`refresh_min_s` 60; a millisecond of slack per second)."""
CHANGE_RECORDER = """() => {
  window.__settingsChanged = 0;
  document.addEventListener("roxy:sse:settings_changed", () => { window.__settingsChanged += 1; });
}"""
LIVE_ROW = """(place) => {
  const rows = [...document.querySelectorAll('[data-live-tail] .tail__row')].filter((row) => !row.hidden);
  const row = rows.find((node) => node.textContent.includes(place));
  return row ? row.textContent : "";
}"""


def _wait(predicate: Callable[[], Any], timeout_s: float, step_s: float = 0.2) -> Any:
    """Poll `predicate` until it returns something truthy or `timeout_s` passes; returns its last value."""
    deadline = time.monotonic() + timeout_s
    value = predicate()
    while not value and time.monotonic() < deadline:
        time.sleep(step_s)
        value = predicate()
    return value


def _js(page: Any, expression: str, timeout_s: float, arg: Any = None) -> Any:
    """Poll a JavaScript expression in the page (through the DevTools protocol, outside the page's CSP)."""
    return _wait(lambda: page.evaluate(expression, arg) if arg is not None else page.evaluate(expression), timeout_s)


def _driver(work: Path, credentials: Path) -> dict[str, Any]:
    sys.path.insert(0, str(HERE))
    import httpx
    from gunicorn_mp_driver import (
        VENV_BIN,
        Master,
        MockRoblox,
        base_env,
        default_behavior,
        make_test_admin,
        prepare_state,
        query,
    )

    # Chromium and its libraries are found from the real home, before `prepare_state` points HOME at the work
    # directory (the libraries are unpacked without root, AGENT_BRIEF).
    home = Path.home()
    browsers = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or str(home / ".cache" / "ms-playwright")
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = browsers
    libs = home / ".local" / "pwlibs" / "root" / "usr" / "lib" / "x86_64-linux-gnu"
    browser_env = {**os.environ, "HOME": str(home), "LD_LIBRARY_PATH": f"{libs}:{libs / 'nss'}"}

    class ConfigMaster(Master):
        """`Master` started from deploy/gunicorn.conf.py, as roxy@.service starts it (`reuse_port`)."""

        def start(self) -> None:
            self.env = {**self.env, "ROXY_DEPLOY_STATE_DIR": str(self.socket.parent)}
            handle = open(self.log, "ab")  # noqa: SIM115 (kept open for the child's lifetime)
            self.proc = subprocess.Popen(
                [str(VENV_BIN / "gunicorn"), "-c", str(REPO / "deploy" / "gunicorn.conf.py"), "roxy.asgi:app"],
                env=self.env,
                cwd=REPO,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

    mock = MockRoblox(default_behavior).start()
    env = base_env(work, credentials, mock)
    state = Path(env["ROXY_STATE_DIR"])
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o750)
    prepare_state(env, STATE_SETTINGS, [])
    admin = make_test_admin(env, credentials)
    master = ConfigMaster("dev", work, env, WORKERS)
    origin = f"http://127.0.0.1:{master.port}"
    master.env["ROXY_SITE_ORIGIN"] = origin  # the browser's Origin: the CSRF and origin checks compare it
    out: dict[str, Any] = {"workers": WORKERS, "error": None}
    try:
        master.start()
        out["ready"] = master.wait_ready()
        if not out["ready"]:
            out["log_tail"] = master.log_tail()
            return out
        rows = master.worker_rows()
        worker_ids = {str(row["worker_id"]): int(row["pid"]) for row in rows}
        out["worker_pids"] = sorted(worker_ids.values())
        cookie = _sign_in(httpx, origin, admin)
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as pw:
                try:
                    browser = pw.chromium.launch(env=browser_env)
                except Exception as error:  # the browser or its libraries are not installed here
                    out["skip"] = f"Chromium cannot start: {error}"[:300]
                    return out
                try:
                    _scenario(httpx, browser, origin, cookie, env, master, worker_ids, query, out)
                finally:
                    browser.close()
        except Exception as error:  # reported to the test with the log tail
            out["error"] = f"{type(error).__name__}: {error}"[:2000]
        out["stop_code"], out["stop_s"] = master.stop()
        out["log_tail"] = master.log_tail(30)
        return out
    finally:
        master.kill()
        mock.stop()


def _sign_in(httpx: Any, origin: str, admin: Any) -> str:
    """The session cookie of an admin signed in through the real password and TOTP steps."""
    from roxy.admin.auth import totp
    from roxy.admin.auth.testing import LOGIN_PATH, MFA_PATH, TEST_UA

    headers = {"Origin": origin, "Sec-Fetch-Site": "same-origin", "User-Agent": TEST_UA, "Accept": "application/json"}
    with httpx.Client(base_url=origin, timeout=30, trust_env=False) as client:
        first = client.post(LOGIN_PATH, json={"username": admin.username, "password": admin.password}, headers=headers)
        first.raise_for_status()
        code = totp.code_at(admin.totp_secret, time.time())
        second = client.post(
            MFA_PATH, json={"transaction": first.json()["Transaction"], "method": "totp", "code": code}, headers=headers
        )
        second.raise_for_status()
    for header in second.headers.get_list("set-cookie"):
        name, _, rest = header.partition("=")
        if name.strip() == "__Host-roxy_session":
            return rest.split(";", 1)[0]
    raise RuntimeError("the sign-in set no session cookie")


def _scenario(
    httpx: Any,
    browser: Any,
    origin: str,
    cookie: str,
    env: dict[str, str],
    master: Any,
    worker_ids: dict[str, int],
    query: Callable[..., list[tuple[Any, ...]]],
    out: dict[str, Any],
) -> None:
    from roxy.admin.auth.testing import TEST_UA

    admin_headers = {
        "Origin": origin,
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": TEST_UA,
        "Accept": "application/json",
        "Cookie": f"__Host-roxy_session={cookie}",
    }
    problems: list[str] = []
    contexts: list[Any] = []

    def holders() -> dict[str, int]:
        """Each open stream slot of the session (`sse:<session>:<n>`) and the pid of the worker holding it."""
        found = query(env["ROXY_HOT_DB"], "SELECT name, holder FROM lease WHERE name LIKE 'sse:%' ORDER BY name")
        return {
            str(name): next((pid for wid, pid in worker_ids.items() if str(holder).startswith(wid + ":")), -1)
            for name, holder in found
        }

    def open_page(path: str) -> tuple[Any, Any]:
        context = browser.new_context(viewport={"width": 1440, "height": 900}, base_url=origin)
        contexts.append(context)
        context.add_cookies(
            [
                {
                    "name": "__Host-roxy_session",
                    "value": cookie,
                    "domain": "127.0.0.1",
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Strict",
                }
            ]
        )
        page = context.new_page()
        page.on(
            "console",
            lambda message: (
                problems.append(f"{path} {message.type}: {message.text}")
                if message.type == "error" and "favicon.ico" not in message.text
                else None
            ),
        )
        page.on("pageerror", lambda error: problems.append(f"{path} page error: {error}"))
        page.goto(origin + path, wait_until="load")
        return context, page

    def open_on_one_worker(path: str, streams: int, want: int | None) -> tuple[Any, list[int], int]:
        """Open `path` in fresh contexts until its `streams` new stream slots are all held by one worker (`want`,
        or any one when None). Returns the page, the holders of its slots and the attempts it took."""
        before = set(holders())

        def added() -> dict[str, int]:
            return {name: pid for name, pid in holders().items() if name not in before}

        for attempt in range(1, ATTEMPTS + 1):
            context, page = open_page(path)
            mine = list((_wait(lambda: len(added()) >= streams and added(), STREAM_WAIT_S) or {}).values())
            if len(mine) == streams and len(set(mine)) == 1 and (want is None or mine[0] == want):
                return page, mine, attempt
            context.close()
            contexts.remove(context)
            _wait(lambda: not added(), STREAM_WAIT_S)  # the server released the closed page's streams
        raise RuntimeError(f"{path}: no context put its {streams} stream(s) on one worker in {ATTEMPTS} attempts")

    def whoami(client: Any) -> tuple[int, Any]:
        answer = client.get("/admin/api/v1/system/leader", headers=admin_headers)
        answer.raise_for_status()
        stream = answer.extensions.get("network_stream")
        port = stream.get_extra_info("client_addr") if stream is not None else None
        return worker_ids.get(str(answer.json()["this_worker"]["worker_id"]), -1), port

    def pinned_to(pid: int) -> tuple[Any, int]:
        """An HTTP keep-alive connection worker `pid` accepted (one connection per client, kept open)."""
        for attempt in range(1, PRODUCER_ATTEMPTS + 1):
            client = httpx.Client(
                base_url=origin,
                timeout=20,
                trust_env=False,
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            )
            if whoami(client)[0] == pid:
                return client, attempt
            client.close()
        raise RuntimeError(f"no new connection reached worker {pid} in {PRODUCER_ATTEMPTS} attempts")

    def through(client: Any, act: Callable[[], Any]) -> tuple[dict[str, Any], Any]:
        """Run `act` on the pinned connection, asking which worker answers before and after."""
        before, port_before = whoami(client)
        result = act()
        after, port_after = whoami(client)
        same = port_before is not None and port_before == port_after
        return {"before": before, "after": after, "same_connection": same, "port": str(port_before)}, result

    def proxied() -> dict[int, int]:
        rows = master.worker_rows()
        return {int(row["pid"]): int(row.get("proxied") or 0) for row in rows}

    try:
        # The Live page first: worker B is the one holding both its streams (the page-wide one and the tail's).
        # Then the Overview, on B too (its tiles refresh at most once a minute, so it opens before the requests).
        live_page, live_streams, live_attempts = open_on_one_worker("/admin/live", 2, None)
        b = live_streams[0]
        out["worker_b"] = b
        out["worker_a"] = next(pid for pid in worker_ids.values() if pid != b)
        out["live_page_streams"] = live_streams
        out["live_attempts"] = live_attempts
        overview, overview_streams, overview_attempts = open_on_one_worker("/admin/overview", 1, b)
        out["overview_stream"] = overview_streams[0]
        out["overview_attempts"] = overview_attempts
        overview.evaluate(KPI_RECORDER)
        live_page.evaluate(CHANGE_RECORDER)
        tile = '[data-kpi="requests"] .kpi__number'
        _js(overview, f"document.querySelector('{tile}') !== null", STREAM_WAIT_S)
        # The first `kpi` frame refreshes the tiles at once (cards.js): let that refresh pass, then read the tile.
        _js(overview, "window.__kpiRequests.length > 0", KPI_FRAME_WAIT_S)
        _js(overview, SETTLED, STREAM_WAIT_S)
        out["kpi_tile_before"] = overview.locator(tile).inner_text().strip()

        # The open inline editor of the setting on the Live page (the Capture card's settings are open).
        editor = live_page.locator(f'form[data-setting-key="{SETTING}"] [data-setting-input]')
        if not editor.is_visible():
            live_page.locator("#capture-settings > summary").click()
        _wait(editor.is_visible, STREAM_WAIT_S)
        editor_before = editor.input_value()

        # Worker A: two proxy requests over a connection it accepted.
        client, producer_attempts = pinned_to(out["worker_a"])
        out["producer_attempts"] = producer_attempts
        counts_before = proxied()
        try:
            proxy_check, statuses = through(
                client,
                lambda: [
                    client.get(
                        f"/games.roblox.com/v1/games?universeIds={9300 + n}",
                        headers={"X-Forwarded-For": CLIENT, "User-Agent": "Roblox/Linux", "Roblox-Id": PLACE},
                    ).status_code
                    for n in range(PRODUCED)
                ],
            )
            out["proxy_statuses"] = statuses
            out["producer"] = {"proxy": proxy_check}

            # 1. The Live row on worker B's tail.
            out["live_row"] = _js(live_page, LIVE_ROW, ROW_WAIT_S, PLACE) or ""

            # 2. Worker B's kpi frames count the requests worker A recorded.
            _js(overview, f"Math.max(...window.__kpiRequests) >= {PRODUCED}", KPI_FRAME_WAIT_S)

            # 3. A settings change saved through worker A.
            def save() -> int:
                token = client.get("/admin/api/v1/auth/session", headers=admin_headers).json()["CsrfToken"]
                answer = client.put(
                    f"/admin/api/v1/settings/{SETTING}",
                    json={"value": NEW_VALUE, "reason": "multi-process stream test"},
                    headers={**admin_headers, "X-CSRF-Token": token, "Content-Type": "application/json"},
                )
                return int(answer.status_code)

            setting_check, status = through(client, save)
            out["producer"]["setting"] = setting_check
        finally:
            client.close()
        editor_after = (
            _wait(lambda: (value := editor.input_value()) == str(NEW_VALUE) and value, EDITOR_WAIT_S)
            or editor.input_value()
        )
        out["setting"] = {
            "key": SETTING,
            "status": status,
            "editor_before": editor_before,
            "editor_after": editor_after,
            "settings_changed_frames": live_page.evaluate("window.__settingsChanged"),
        }

        # Which worker served the proxy requests, from each worker's own heartbeat counter (every 5 s).
        expected = {pid: count + (PRODUCED if pid == out["worker_a"] else 0) for pid, count in counts_before.items()}
        _wait(lambda: proxied() == expected, HEARTBEAT_WAIT_S, 0.5)
        counts_after = proxied()
        out["proxied_delta"] = {str(pid): counts_after.get(pid, 0) - count for pid, count in counts_before.items()}

        # The Overview tile, on its next stream-driven refresh (at most a minute after the first).
        out["kpi_tile_after"] = (
            _wait(
                lambda: (text := overview.locator(tile).inner_text().strip()) == str(PRODUCED) and text,
                TILE_WAIT_S,
                0.5,
            )
            or overview.locator(tile).inner_text().strip()
        )
        out["kpi_requests"] = overview.evaluate("window.__kpiRequests")
        out["kpi_card_loads_ms"] = overview.evaluate("window.__kpiCardLoads.map((t) => Math.round(t))")
        out["streams_at_end"] = sorted(holders().values())
    finally:
        out["browser_problems"] = problems[:20]
        for context in contexts:
            context.close()


def main() -> int:
    work, credentials = Path(sys.argv[1]), Path(sys.argv[2])
    ip = shutil.which("ip") or "/usr/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)  # a fresh namespace
    work.mkdir(parents=True, exist_ok=True)
    print(json.dumps(_driver(work, credentials)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
