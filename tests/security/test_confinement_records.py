"""The credential never lands in a record: logs at DEBUG, databases, captures, events, audit, exports, answers.

What this is
    Probes for plan 9.15, 19.5 items 11 and 12 and 19.7 ("inject secrets into requests and assert logs, captures,
    exports are clean"), run through the whole app with `ROXY_LOG_LEVEL=debug`, every served request captured and
    sampled. `test_credential_activity_leaves_no_trace` exercises everything Roxy itself does with the credential
    (probe, an allowlisted credential request, Roblox rotating the cookie, an admin replace, the guard
    self-test) plus ordinary caller traffic on all three egresses, then scans every byte the service wrote.
    `test_injected_credential_piece_is_scrubbed_everywhere` (strict xfail, finding F4) has a caller send a piece
    of the credential in places that are not request content (a path segment that is not id-shaped, the
    `Roblox-Id` header) and shows it surviving unredacted into metric dimensions and the Live feed.

Why it exists
    The credential has many ways to reach a record: a third-party library logging a request at DEBUG, a traceback,
    an event detail, an audit row for a secret change, a capture of a request that carried it, an alert. Plan 9.15
    makes the redaction filter and the field-level scrubbing the last line of defense, and only scanning what was
    actually written proves it holds.

How it works
    The lifespan's JSON log handler is pointed at an in-memory stream (`sys.stderr` is replaced before startup).
    After the traffic, the recorder is flushed and the app stopped; then the scan covers the log stream, the raw
    bytes of every SQLite file (including `-wal` files and free pages), every decoded capture, the Live ring, the
    answers of every parameterless GET route, `egress.stats()`, `credential.status()` and the settings export.
    `leak_scan` looks for the whole value or any 24 character run of its secret part, also percent-decoded.

What to read next
    `src/roxy/core/logging.py`, `src/roxy/core/redact.py`, `src/roxy/metrics/capture.py`,
    `src/roxy/metrics/live.py`, `src/roxy/metrics/templating.py`, and `tests/security/test_credential_suite.py`.
"""

from __future__ import annotations

import dataclasses
import io
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest
from confinement_harness import ADMIN, AppRun, leak_scan, running_app, secret_part
from starlette.routing import Route

from roxy.config.settings_service import SettingsService
from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX
from roxy.metrics.capture import decode_record

ECONOMY = "economy.roblox.com"
CURRENCY = "/v1/user/currency"


def database_bytes(state_dir: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in sorted(state_dir.iterdir())
        if path.name.endswith((".db", ".db-wal", ".db-shm"))
    }


async def answers_of_every_simple_get(run: AppRun) -> dict[str, bytes]:
    """The body of every GET route without path parameters (public pages, health, the admin surface's 401s)."""
    out: dict[str, bytes] = {}
    for route in run.app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", None) or set()
        if not isinstance(route, Route) or "{" in path or "GET" not in methods:
            continue
        response = await run.http.get(path)
        out[path] = response.content + json.dumps(dict(response.headers)).encode()
    return out


def captures(run: AppRun) -> list[dict[str, Any]]:
    rows = run.ctx.dbs.metrics.read_sync(lambda conn: conn.execute("SELECT compressed_blob FROM captures").fetchall())
    return [decode_record(row[0]) for row in rows if row[0] is not None]


def scan(blobs: dict[str, bytes | str], values: dict[str, str]) -> list[str]:
    return [
        f"{where}: {label}: {finding}"
        for where, blob in blobs.items()
        for label, value in values.items()
        for finding in leak_scan(blob, value)
    ]


async def capture_everything(run: AppRun) -> None:
    await run.settings(capture_sample_served_pct=100, request_sample_pct=100)


async def test_credential_activity_leaves_no_trace(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Roxy's own credential use, a cookie rotation, an admin replace and caller traffic on every egress, at DEBUG:
    no log line, database byte, capture, Live row, answer or export holds the credential or a 24+ piece of it."""
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)  # the lifespan's JSON log handler writes here
    debug_env = env.model_copy(update={"log_level": "debug"})
    rotated = TOKEN_PREFIX + "ROTATEDBYROBLOX" + "9F" * 150
    replacement = TOKEN_PREFIX + "REPLACEDBYADMIN" + "7C" * 150
    async with running_app(debug_env, credentials_dir, fake_secrets, monkeypatch) as run:
        assert logging.getLogger().getEffectiveLevel() == logging.DEBUG  # the service really logs at DEBUG
        fixture = run.fixture()
        await capture_everything(run)
        await run.activate_credential()
        run.mock.routes[CURRENCY] = fixture.MockResponse(
            body=b'{"robux": 5}',
            headers=[
                ("Content-Type", "application/json"),
                ("Set-Cookie", f".ROBLOSECURITY={rotated}; domain=.roblox.com; path=/; secure; HttpOnly"),
            ],
        )
        await run.rule("credential_allowlist", {"pattern": f"{ECONOMY}{CURRENCY}", "cache_private": True})
        await run.rule("rules_routing", {"pattern": "games.roblox.com/v1/rotated", "mode": "rotator_only"})
        caller_paths = [
            f"/{ECONOMY}{CURRENCY}",  # the credential path (allowlisted), and Roblox rotates the cookie
            "/games.roblox.com/v1/games?universeIds=1",  # direct
            "/games.roblox.com/v1/rotated?universeIds=2",  # rotator
            "/users.roblox.com/v1/users/404404",
            "/evil.example.com/x",  # refused
        ]
        for path in caller_paths:
            for method in ("GET", "HEAD", "POST"):
                run.clock.advance(5)
                kwargs: dict[str, Any] = {"content": b'{"ids":[1]}'} if method == "POST" else {}
                await run.request(method, path, **kwargs)
        assert any(r.header("Cookie") for r in run.mock.requests if r.path.startswith(CURRENCY))
        assert (await run.ctx.egress.self_test_leak_guard()).status in ("pass", "warn")
        # A bug that puts the cookie (or its bare secret part) in an exception message: the 500 path writes the
        # errors table, a log line with the traceback, an event and an alert; all of them must be scrubbed.
        serve = run.ctx.cache.serve
        bootstrap = fake_secrets["roblox_credential"]
        for message in (f"Cookie: .ROBLOSECURITY={bootstrap}", f"value {secret_part(bootstrap)[7:200]} end"):

            async def broken(req: Any, peek: Any, text: str = message) -> Any:
                raise RuntimeError(text)

            monkeypatch.setattr(run.ctx.cache, "serve", broken)
            run.clock.advance(5)
            assert (await run.get("/games.roblox.com/v1/games?universeIds=77")).status_code == 500
        monkeypatch.setattr(run.ctx.cache, "serve", serve)
        await run.ctx.egress.credential.replace(replacement, ADMIN, reason="confinement probe")
        await run.activate_credential()
        run.clock.advance(5)
        await run.get(f"/{ECONOMY}{CURRENCY}?after=replace")
        await run.ctx.recorder.flush()
        blobs: dict[str, bytes | str] = {}
        blobs["live ring"] = json.dumps(run.ctx.recorder.live.snapshot(limit=5000), default=str)
        blobs["captures"] = json.dumps(captures(run), default=str)
        blobs.update({f"GET {path}": body for path, body in (await answers_of_every_simple_get(run)).items()})
        blobs["egress.stats()"] = json.dumps(run.ctx.egress.stats(), default=str)
        blobs["credential.status()"] = json.dumps(dataclasses.asdict(run.ctx.egress.credential.status()), default=str)
        service = SettingsService(run.ctx.dbs.control, runtime=run.ctx.settings, clock=run.clock)
        blobs["settings export"] = json.dumps(await service.export_overrides(), default=str)
        assert len(captures(run)) >= 5  # captures were really written
        errors = run.ctx.dbs.metrics.read_sync(lambda conn: conn.execute("SELECT count(*) FROM errors").fetchone()[0])
        assert errors >= 1  # the errors table was really written
    blobs.update(database_bytes(env.state_dir))
    blobs["log stream"] = stream.getvalue()
    assert "credential_rotation" in stream.getvalue() or "worker_ready" in stream.getvalue()  # the stream is live
    values = {"bootstrap credential": fake_secrets["roblox_credential"], "rotated": rotated, "replacement": replacement}
    assert scan(blobs, values) == []


@pytest.mark.xfail(
    strict=True,
    reason=(
        "F4: a credential piece a caller puts in a non id-shaped path segment or in the Roblox-Id header is kept "
        "unredacted in metric dimensions (endpoint_template, place) and the Live feed's template and place fields"
    ),
)
async def test_injected_credential_piece_is_scrubbed_everywhere(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 19.7: inject the secret into requests, then every log, capture, Live row and metrics row is clean.
    (The guard refuses to send such a request, so this is about what Roxy RECORDS about it.)"""
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    piece = secret_part(fake_secrets["roblox_credential"])[30:70]
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        await capture_everything(run)
        injected = [
            ("GET", f"/games.roblox.com/v1/games?universeIds=1&k={piece}", {}, {}),
            ("POST", "/games.roblox.com/v1/games/list", {"X-Note": piece}, {"content": json.dumps({"k": piece})}),
            ("GET", f"/games.roblox.com/v1/x.{piece}", {}, {}),
            ("GET", "/games.roblox.com/v1/games?universeIds=3", {"Roblox-Id": piece}, {}),
            ("GET", "/games.roblox.com/v1/games?universeIds=4", {"User-Agent": f"Roblox/{piece}"}, {}),
        ]
        for method, path, headers, kwargs in injected:
            run.clock.advance(5)
            await run.request(method, path, headers=headers, **kwargs)
        await run.ctx.recorder.flush()
        live = json.dumps(run.ctx.recorder.live.snapshot(limit=5000), default=str)
        captured = json.dumps(captures(run), default=str)
    metrics = database_bytes(env.state_dir)
    found = scan(
        {"live ring": live, "captures": captured, "log stream": stream.getvalue(), **metrics},
        {"injected piece": TOKEN_PREFIX + piece},
    )
    assert run.ctx.egress.tripped(Egress.DIRECT)  # the guard did its job: nothing was sent
    assert found == []
