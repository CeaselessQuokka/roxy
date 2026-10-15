"""The credential-never-via-rotator suite (plan 19.5): the tests that must exist and must pass.

What this is
    One test per item of plan 19.5 that belongs to the egress layer: 1, 2, 2a, 2b, 2c, 2d, 3, 4, 5, 7, 8, 9 and
    12, plus the database and log part of 11 (`test_secret_replace_leaves_no_trace`). Item 6 (routing never picks
    the credential) belongs to the upstream package and item 10 (credential responses never served to another
    auth class) to the cache package.

Why it exists
    Plan C1 and C2 are the two rules a delivery may never break: exactly one credential, and the credential never
    travels through the rotator (or out of the direct path). Each defense layer is tested on its own here, so
    removing any one of them fails the build.

How it works
    Everything runs on loopback: `MockUpstream` stands in for Roblox, `RecordingProxy` for DataImpulse (plain
    forwarding, and a TLS-intercepting variant with a throwaway `trustme` CA). The development test override
    (`ROXY_TEST_UPSTREAM_BASE`, `ROXY_TEST_ROTATOR_PROXY`) points Roblox traffic at the mock. Recorded bytes are
    scanned for the credential, any 24 character piece of it, and its cookie name. The fake credential is
    generated at runtime by `tests/conftest.py`.

What to read next
    `src/roxy/egress/clients.py`, `src/roxy/egress/guard.py`, `src/roxy/egress/credential.py`.
"""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import io
import itertools
import json
import logging
import sqlite3
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.core.clock import SYSTEM_CLOCK
from roxy.core.logging import configure_logging
from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX, SecretRegistry
from roxy.egress import metering
from roxy.egress.clients import EgressClients, assert_no_proxy, make_credential_client
from roxy.egress.credential import CredentialSlot
from roxy.egress.errors import AuthSmugglingBlocked, CredentialLeakBlocked, EgressDisabled
from roxy.egress.guard import GuardTransport
from roxy.egress.models import OutboundRequest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "roxy"
ADMIN = Actor("admin", "owner", "127.0.0.1")
TIMEOUT = httpx.Timeout(5.0)
PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")


def _load_harness() -> ModuleType:
    name = "roxy_test_recording_proxy"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "tests" / "fixtures" / "recording_proxy.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


harness = _load_harness()


class Notifier:
    def __init__(self) -> None:
        self.alerts: list[Any] = []

    def send(self, alert: Any) -> None:
        self.alerts.append(alert)

    def critical(self) -> list[Any]:
        return [alert for alert in self.alerts if alert.severity == "critical"]


class Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, str, dict[str, Any]]] = []
        self.usage: list[Any] = []

    def record_event(self, kind: str, severity: str, reason: str, detail: dict[str, Any]) -> None:
        self.events.append((kind, severity, reason, detail))

    def record_egress_usage(self, item: Any) -> None:
        self.usage.append(item)


@pytest.fixture(autouse=True)
def _clean_state() -> Iterator[None]:
    SecretRegistry.clear()
    metering.reset_self_test()
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    pinned = {name: logging.getLogger(name).level for name in ("httpx", "httpcore", "h2", "hpack")}
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    for name, value in pinned.items():
        logging.getLogger(name).setLevel(value)
    logging.captureWarnings(False)
    SecretRegistry.clear()
    metering.reset_self_test()


@pytest.fixture
def settings() -> Any:
    return harness.FakeSettings()


@pytest.fixture
def secret(fake_secrets: dict[str, str]) -> str:
    return fake_secrets["roblox_credential"]


@pytest.fixture
def mock() -> Iterator[Any]:
    with harness.MockUpstream() as server:
        server.routes["/v1/users/authenticated"] = harness.MockResponse(body=b'{"id": 1, "name": "x"}')
        yield server


@pytest.fixture
async def make_egress(env: Any, dbs: Any, settings: Any) -> AsyncIterator[Callable[..., Awaitable[EgressClients]]]:
    built: list[EgressClients] = []

    async def factory(**options: Any) -> EgressClients:
        clients = EgressClients(
            env=options.pop("env", env),
            settings=options.pop("settings", settings),
            dbs=options.pop("dbs", dbs),
            clock=SYSTEM_CLOCK,
            worker_id=options.pop("worker_id", f"worker-{len(built)}"),
            environ=options.pop("environ", {}),
            **options,
        )
        built.append(clients)
        await clients.start()
        return clients

    yield factory
    for clients in built:
        await clients.aclose()


def out(url: str, method: str = "GET", **kwargs: Any) -> OutboundRequest:
    return OutboundRequest(method, url, kwargs.pop("headers", {}), kwargs.pop("content", None), TIMEOUT, **kwargs)


def forward_environ(mock: Any, proxy: Any) -> dict[str, str]:
    return {"ROXY_TEST_UPSTREAM_BASE": mock.base_url, "ROXY_TEST_ROTATOR_PROXY": proxy.url_with_auth("dpuser", "dppw1")}


def secret_part(value: str) -> str:
    return value.removeprefix(TOKEN_PREFIX)


# ------------------------------------------------------------------------------------------------ item 1


async def test_rotator_guard_blocks_cookie(make_egress: Any, mock: Any, secret: str) -> None:
    """19.5 item 1: the credential cookie on a RotatorClient raises CredentialLeakBlocked; nothing is sent."""
    notifier = Notifier()
    with harness.RecordingProxy(upstream=mock.address) as proxy:
        egress = await make_egress(environ=forward_environ(mock, proxy), alerts=lambda: notifier)
        lease = await egress.rotator.acquire(None)
        try:
            request = lease.client.http.build_request(
                "GET", "https://games.roblox.com/v1/games", headers={"Cookie": f".ROBLOSECURITY={secret}"}
            )
            with pytest.raises(CredentialLeakBlocked) as raised:
                await lease.client.send(request)
        finally:
            await egress.rotator.release(lease)
        proxy.wait_settled()
        assert proxy.exchanges == []
        assert mock.requests == []
    assert secret_part(secret)[:24] not in str(raised.value)
    assert not egress.is_enabled(Egress.ROTATOR)[0]
    assert egress.is_enabled(Egress.DIRECT)[0]
    assert [alert.subject for alert in notifier.critical()] == ["Roxy SECURITY: credential leak blocked"]


# ------------------------------------------------------------------------------------------------ item 2


def _leaky(where: str, piece: str) -> OutboundRequest:
    if where == "header":
        return out("https://games.roblox.com/v1/games", headers={"X-Debug": piece})
    if where == "query":
        return out(f"https://games.roblox.com/v1/games?trace={piece}")
    return out(
        "https://games.roblox.com/v1/x",
        "POST",
        content=b'{"note":"' + piece.encode() + b'"}',
        headers={"Content-Type": "application/json"},
    )


@pytest.mark.parametrize("where", ["header", "query", "body"])
@pytest.mark.parametrize("shape", ["full", "piece24", "piece40_lower", "tail"])
async def test_rotator_guard_blocks_header_query_body(
    make_egress: Any, mock: Any, secret: str, where: str, shape: str
) -> None:
    """19.5 item 2: the value or a 24+ character piece in any header, the query or the body is blocked."""
    part = secret_part(secret)
    piece = {
        "full": secret,
        "piece24": part[57:81],
        "piece40_lower": part[100:140].lower(),
        "tail": part[-24:],
    }[shape]
    with harness.RecordingProxy(upstream=mock.address) as proxy:
        egress = await make_egress(environ=forward_environ(mock, proxy))
        if shape == "full" and where != "body":
            # The full value starts with the public prefix; in a header or URL the leak check still runs first.
            pass
        with pytest.raises(CredentialLeakBlocked):
            await egress.send(Egress.ROTATOR, _leaky(where, piece))
        proxy.wait_settled()
        assert proxy.exchanges == []
        assert mock.requests == []
    assert egress.guard_stats[Egress.ROTATOR].leak_trips == 1


async def test_rotator_guard_inspects_the_whole_body_up_to_the_limit(
    make_egress: Any, mock: Any, secret: str, settings: Any
) -> None:
    """19.5 item 2: the piece sits at the end of a body just under `max_body_bytes`; a larger body is refused."""
    settings.set("max_body_bytes", 200_000)
    with harness.RecordingProxy(upstream=mock.address) as proxy:
        egress = await make_egress(environ=forward_environ(mock, proxy))
        body = b"a" * (200_000 - 30) + secret_part(secret)[200:230].encode()
        with pytest.raises(CredentialLeakBlocked):
            await egress.send(Egress.ROTATOR, out("https://games.roblox.com/v1/x", "POST", content=body))
        assert proxy.exchanges == []
    clean = await make_egress(environ=forward_environ(mock, proxy), worker_id="other")
    await clean.enable_egress(Egress.ROTATOR, ADMIN, reason="test")
    with pytest.raises(AuthSmugglingBlocked):
        await clean.send(Egress.ROTATOR, out("https://games.roblox.com/v1/x", "POST", content=b"b" * 200_001))


# ------------------------------------------------------------------------------------------------ item 2a


async def test_direct_guard_blocks_credential(make_egress: Any, mock: Any, secret: str, dbs: Any) -> None:
    """19.5 item 2a: the same on DirectClient; a trip disables the direct egress fleet-wide and alerts."""
    notifier = Notifier()
    environ = {"ROXY_TEST_UPSTREAM_BASE": mock.base_url}
    worker_a = await make_egress(environ=environ, alerts=lambda: notifier)
    worker_b = await make_egress(environ=environ, worker_id="worker-b")
    with pytest.raises(CredentialLeakBlocked):
        await worker_a.send(
            Egress.DIRECT, out("https://games.roblox.com/v1/x", headers={"X-A": secret_part(secret)[:30]})
        )
    assert mock.requests == []
    assert worker_a.is_enabled(Egress.DIRECT) == (False, "leak_guard_tripped")
    await worker_b.refresh()
    assert worker_b.is_enabled(Egress.DIRECT) == (False, "leak_guard_tripped")
    with pytest.raises(EgressDisabled):
        await worker_b.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))
    assert worker_b.is_enabled(Egress.ROTATOR)[1] != "leak_guard_tripped"  # only the tripping egress
    alert = notifier.critical()[0]
    assert alert.subject == "Roxy SECURITY: credential leak blocked"
    assert alert.always_send
    assert alert.fields["egress_disabled"] == "direct"
    assert secret_part(secret)[:24] not in json.dumps(alert.fields)
    rows = dbs.control.read_sync(lambda conn: [dict(r) for r in conn.execute("SELECT * FROM audit_log").fetchall()])
    trip = [row for row in rows if row["action"] == "egress.leak_guard_trip"]
    assert trip
    assert trip[0]["target"] == "egress:direct"
    assert secret_part(secret)[:24] not in json.dumps(rows)
    assert await worker_b.enable_egress(Egress.DIRECT, ADMIN, reason="investigated")
    await worker_a.refresh()
    assert worker_a.is_enabled(Egress.DIRECT) == (True, "")
    assert (await worker_a.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))).status == 200


# ------------------------------------------------------------------------------------------------ item 2b


@pytest.mark.parametrize(
    ("headers", "content"),
    [
        ({}, b"note=" + TOKEN_PREFIX.encode()),
        ({"X-Note": ".ROBLOSECURITY"}, None),
        ({}, b'{"cookie": ".roblosecurity=abc"}'),
    ],
)
async def test_public_markers_do_not_disable_egress(
    make_egress: Any, mock: Any, headers: dict[str, str], content: bytes | None
) -> None:
    """19.5 item 2b (egress half): a public marker reaching the guard is refused as smuggling, counted, and no
    egress is disabled and no critical alert is sent. The ingress half (400 at `abuse/checks/auth_smuggling.py`)
    is tested by the abuse package."""
    notifier = Notifier()
    recorder = Recorder()
    with harness.RecordingProxy(upstream=mock.address) as proxy:
        egress = await make_egress(
            environ=forward_environ(mock, proxy), alerts=lambda: notifier, recorder=lambda: recorder
        )
        method = "POST" if content else "GET"
        for egress_kind in (Egress.DIRECT, Egress.ROTATOR):
            with pytest.raises(AuthSmugglingBlocked):
                await egress.send(
                    egress_kind, out("https://games.roblox.com/v1/x", method, headers=headers, content=content)
                )
            assert egress.is_enabled(egress_kind) == (True, "")
        assert proxy.exchanges == []
        assert mock.requests == []
    assert notifier.critical() == []
    assert [event[0] for event in recorder.events] == ["auth_smuggling_blocked"] * 2
    assert egress.guard_stats[Egress.DIRECT].smuggling_refusals == 1
    assert (await egress.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))).status == 200


# ------------------------------------------------------------------------------------------------ item 2c


async def test_guard_is_a_transport(make_egress: Any, mock: Any, secret: str) -> None:
    """19.5 item 2c: clearing `event_hooks` cannot remove the guard, and a hook that adds the credential after
    the fact is still caught, because the guard sees the final request."""
    egress = await make_egress(environ={"ROXY_TEST_UPSTREAM_BASE": mock.base_url})
    client = egress.direct_client
    client.http.event_hooks = {"request": [], "response": []}
    assert isinstance(client.transport, GuardTransport)
    assert client.http._transport is client.transport

    async def sneaky(request: httpx.Request) -> None:
        request.headers["Cookie"] = f".ROBLOSECURITY={secret}"

    client.http.event_hooks = {"request": [sneaky], "response": []}
    with pytest.raises(CredentialLeakBlocked):
        await egress.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))
    assert mock.requests == []


# ------------------------------------------------------------------------------------------------ item 2d


async def test_credential_client_ignores_set_cookie(make_egress: Any, mock: Any, secret: str, dbs: Any) -> None:
    """19.5 item 2d: `Set-Cookie: .ROBLOSECURITY=...` changes nothing in the slot or other workers and raises the
    rotation alert."""
    notifier = Notifier()
    environ = {"ROXY_TEST_UPSTREAM_BASE": mock.base_url}
    worker_a = await make_egress(environ=environ, alerts=lambda: notifier)
    worker_b = await make_egress(environ=environ, worker_id="worker-b")
    assert (await worker_a.credential.probe("admin_check")).ok

    def state() -> tuple[Any, ...]:
        def read(conn: sqlite3.Connection) -> tuple[Any, ...]:
            return (
                conn.execute("SELECT count(*) FROM credential_store").fetchone()[0],
                conn.execute("SELECT fingerprint FROM credential_meta").fetchone()[0],
                conn.execute("SELECT value_json FROM service_state WHERE key = 'credential_version'").fetchone()[0],
            )

        return dbs.control.read_sync(read)

    before = state()
    rotated = "ROTATEDBYROBLOX" + "C3" * 150
    mock.routes["/v1/users/authenticated"] = harness.MockResponse(
        body=b'{"id": 1}', headers=[("Set-Cookie", f".ROBLOSECURITY={rotated}; domain=.roblox.com; secure; HttpOnly")]
    )
    response = await worker_a.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/authenticated"))
    assert "set-cookie" not in response.headers
    assert rotated not in response.body.decode()
    assert state() == before
    await worker_b.refresh()
    for worker in (worker_a, worker_b):
        assert worker.credential.status().fingerprint == worker.credential.fingerprint_of(secret)
    assert [alert.subject for alert in notifier.alerts] == ["Roxy: Roblox sent a new credential cookie"]
    await worker_a.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/authenticated"))
    assert mock.requests[-1].header("Cookie") == f".ROBLOSECURITY={secret}"  # still the slot value, never the new one


# ------------------------------------------------------------------------------------------------ item 3


async def test_clients_ignore_env_proxies(make_egress: Any, mock: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """19.5 item 3: with every proxy variable pointing at a recording proxy, direct and credential traffic never
    reaches it."""
    with harness.RecordingProxy(upstream=mock.address) as trap:
        for name in PROXY_VARS:
            monkeypatch.setenv(name, trap.url)
        monkeypatch.setenv("NO_PROXY", "")
        egress = await make_egress(environ={"ROXY_TEST_UPSTREAM_BASE": mock.base_url})
        assert (await egress.credential.probe("admin_check")).ok
        await egress.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))
        await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/authenticated"))
        trap.wait_settled()
        assert trap.exchanges == []
        assert len(mock.requests) == 3
        check = egress.self_test_env_proxy()
        assert check.status == "warn"
        assert "HTTPS_PROXY" in check.value


# ------------------------------------------------------------------------------------------------ item 4


async def _rotator_battery(egress: EgressClients, secret: str, *, url_base: str) -> None:
    for index in range(3):
        response = await egress.send(Egress.ROTATOR, out(f"{url_base}/v1/games?universeIds={index}"))
        assert response.status == 200
    await egress.send(
        Egress.ROTATOR,
        out(f"{url_base}/v1/x", "POST", content=b'{"ids":[1,2]}', headers={"Content-Type": "application/json"}),
    )
    probe = await egress.rotator.exit_ip_probe()
    assert probe.exit_ip, probe
    with pytest.raises(CredentialLeakBlocked):
        await egress.send(Egress.ROTATOR, out(f"{url_base}/v1/x", headers={"X-Oops": secret_part(secret)[10:40]}))
    assert (await egress.self_test_leak_guard()).status == "pass"


@pytest.mark.parametrize("variant", ["forward", "tls_intercept"])
async def test_end_to_end_recording_proxy(
    make_egress: Any, mock: Any, secret: str, env: Any, settings: Any, variant: str, fake_secrets: dict[str, str]
) -> None:
    """19.5 item 4: rotator, credential and direct traffic plus the health self-tests run with the rotator
    pointed at a recording forward proxy (plain HTTP for inspection, and a TLS-intercepting variant with a test
    CA); the recorded bytes never contain the credential, a piece of it, or its cookie name.

    The caller-facing proxy pipeline (`proxy/router.py`) is built by another package; when it lands, the
    integration suite runs it with this same override and proxy."""
    echo_env = env.model_copy(update={"rotator_ip_echo_url": f"{mock.base_url}/ip"})
    if variant == "forward":
        proxy = harness.RecordingProxy(upstream=mock.address)
        environ_extra: dict[str, str] = {"ROXY_TEST_UPSTREAM_BASE": mock.base_url}
        tls_verify: Any = True
    else:
        ca = harness.make_ca()
        proxy = harness.RecordingProxy(upstream=mock.address, intercept_context=harness.server_ssl_context(ca))
        environ_extra = {}
        tls_verify = harness.client_ssl_context(ca)
    with proxy:
        environ = {**environ_extra, "ROXY_TEST_ROTATOR_PROXY": proxy.url_with_auth("dpuser", "dppw1")}
        settings.set("rotator_session_username_template", "{user}-sessid-{session}")
        egress = await make_egress(environ=environ, env=echo_env, tls_verify=tls_verify)
        await _rotator_battery(egress, secret, url_base="https://games.roblox.com")
        if variant == "forward":
            # The credential and direct paths share the run (they reach the mock directly, never the proxy).
            assert (await egress.credential.probe("admin_check")).ok
            await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/authenticated"))
            await egress.send(Egress.DIRECT, out("https://games.roblox.com/v1/games?universeIds=9"))
            assert any(r.header("Cookie") for r in mock.requests)  # the credential did go out, but not this way
        assert egress.self_test_env_proxy({}).status == "pass"
        await egress.aclose()
        proxy.wait_settled()
        recorded = proxy.all_recorded()
    assert harness.leak_findings(recorded, secret) == []
    assert fake_secrets["rotator_url"].encode() not in recorded
    relayed = sum(ex.requests for ex in proxy.exchanges)
    assert relayed >= 5  # 3 GETs, 1 POST, 1 exit IP probe
    if variant == "tls_intercept":
        plaintext = b"".join(bytes(ex.plaintext) for ex in proxy.exchanges)
        assert b"GET /v1/games?universeIds=0 HTTP/1.1" in plaintext  # interception really saw the plaintext
        assert any(ex.kind == "intercept" for ex in proxy.exchanges)


# ------------------------------------------------------------------------------------------------ item 5


@pytest.mark.parametrize(
    ("env_proxies", "override", "http2", "rotator"),
    list(itertools.product([False, True], [False, True], [False, True], [False, True])),
)
async def test_credential_path_has_no_proxy(
    make_egress: Any,
    mock: Any,
    env: Any,
    monkeypatch: pytest.MonkeyPatch,
    env_proxies: bool,
    override: bool,
    http2: bool,
    rotator: bool,
) -> None:
    """19.5 item 5: the credential client has no proxy mount after construction under every permutation."""
    if env_proxies:
        for name in PROXY_VARS:
            monkeypatch.setenv(name, "http://127.0.0.1:9")
    if not rotator:
        (env.credentials_dir / "rotator_url").unlink()
    environ = (
        {"ROXY_TEST_UPSTREAM_BASE": mock.base_url, "ROXY_TEST_ROTATOR_PROXY": "http://127.0.0.1:9"} if override else {}
    )
    standalone = make_credential_client(http2=http2)
    egress = await make_egress(environ=environ)
    try:
        for client in (standalone, egress.credential_client):
            assert_no_proxy(client)
            assert client.http._mounts == {}
            assert client.http.trust_env is False
            assert not client.metering.proxy_configured
            assert not client.metering.pool_is_proxy()
            assert type(client.metering._pool).__name__ == "AsyncConnectionPool"
            assert not isinstance(client.transport, GuardTransport)  # no guard: but also no proxy, ever
    finally:
        await standalone.aclose()


# ------------------------------------------------------------------------------------------------ item 7


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


# Names unique to the credential module: its loader, the slot's reveal method, and the slot type.
FORBIDDEN_NAMES = frozenset({"_read_bootstrap_file", "_reveal_credential", "CredentialSlot"})
# Its other module constants may not be imported elsewhere either (a generic name such as STORE_AAD may exist in
# another module with another meaning, so these are checked as imports from credential.py).
FORBIDDEN_IMPORTS = frozenset({"_read_bootstrap_file", "BOOTSTRAP_FILE_NAME", "STORE_AAD", "CredentialSlot"})


def credential_reader_offenders(source: Path, owner: Path, allowed_constant_owners: set[Path]) -> tuple[list[str], int]:
    """Every place under `source` (except `owner`) that could read the credential, and how many files were read."""
    offenders: list[str] = []
    checked = 0
    for path in sorted(source.rglob("*.py")):
        if path == owner:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = _docstring_nodes(tree)
        checked += 1
        label = path.relative_to(source).as_posix()
        for node in ast.walk(tree):
            name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None
            if name in FORBIDDEN_NAMES:
                offenders.append(f"{label}:{node.lineno} uses {name}")
            if isinstance(node, ast.ImportFrom) and node.module == "roxy.egress.credential":
                for alias in node.names:
                    if alias.name in FORBIDDEN_IMPORTS or alias.name == "*":
                        offenders.append(f"{label} imports {alias.name} from the credential module")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                if node.value == "roblox_credential" and path not in allowed_constant_owners:
                    offenders.append(f"{label}:{node.lineno} names the credential file")
                if "credential_store" in node.value:
                    offenders.append(f"{label}:{node.lineno} touches credential_store")
    return offenders, checked


def test_ast_scan_catches_a_second_reader(tmp_path: Path) -> None:
    """The scan is not vacuous: each kind of violation in a fake tree is reported."""
    package = tmp_path / "roxy"
    (package / "egress").mkdir(parents=True)
    owner = package / "egress" / "credential.py"
    owner.write_text('def _read_bootstrap_file(d):\n    return open(d / "roblox_credential").read()\n')
    (package / "sneaky.py").write_text(
        '"""Docstrings may say roblox_credential and credential_store."""\n'
        "from roxy.egress.credential import BOOTSTRAP_FILE_NAME\n"
        'PATH = "roblox_credential"\n'
        'SQL = "SELECT ciphertext FROM credential_store"\n'
        "def leak(manager):\n    return manager._slot._reveal_credential()\n"
    )
    offenders, checked = credential_reader_offenders(package, owner, set())
    assert checked == 1
    assert len(offenders) == 4
    assert all("sneaky.py" in item for item in offenders)


def test_only_credential_module_reads_secret() -> None:
    """19.5 item 7: an AST scan of src/ shows that only `egress/credential.py` references the credential loader,
    the bootstrap file name, the credential table, or the slot's reveal method."""
    owner = SOURCE / "egress" / "credential.py"
    # Two documented exceptions for the file NAME only (never the loader, never credential_store):
    #   * `core/redact.py` names the log-scrubbing registry entry "roblox_credential" (no file is read);
    #   * `migration/secrets_out.py` is the offline v1 migrator (plan 18.3) that WRITES the bootstrap file from
    #     v1's token file (first line only, C1); the running service never imports it.
    allowed_constant_owners = {SOURCE / "core" / "redact.py", SOURCE / "migration" / "secrets_out.py"}
    offenders, checked = credential_reader_offenders(SOURCE, owner, allowed_constant_owners)
    assert checked > 50
    assert offenders == []
    # And the owner really is the one that reads it.
    owner_tree = ast.parse(owner.read_text(encoding="utf-8"))
    assert any(isinstance(n, ast.FunctionDef) and n.name == "_read_bootstrap_file" for n in ast.walk(owner_tree))
    assert any(isinstance(n, ast.FunctionDef) and n.name == "_reveal_credential" for n in ast.walk(owner_tree))
    redact = (SOURCE / "core" / "redact.py").read_text(encoding="utf-8")
    assert "open(" not in redact
    assert "read_text" not in redact
    # The service itself never imports the offline migrator, so its file name constant cannot load anything.
    for path in sorted(SOURCE.rglob("*.py")):
        if "migration" in path.relative_to(SOURCE).parts or path.name in ("cli.py",):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("roxy.migration.secrets_out"):
                offenders.append(f"{path.relative_to(ROOT)} imports the migrator's secret writer")
    assert offenders == []


# ------------------------------------------------------------------------------------------------ item 8


async def test_single_credential_slot(make_egress: Any, mock: Any, dbs: Any, secret: str) -> None:
    """19.5 item 8 (C1): setting a second value replaces, never appends, and no API accepts a list."""
    slot = CredentialSlot()
    slot.set("A" * 40, source="ui", value_fingerprint="f1")
    slot.set("B" * 40, source="ui", value_fingerprint="f2")
    assert slot.fingerprint == "f2"
    assert "B" * 40 not in repr(slot)
    with pytest.raises(TypeError):
        slot.set(["A" * 40, "B" * 40], source="ui", value_fingerprint="x")  # type: ignore[arg-type]
    assert not any(hasattr(slot, name) for name in ("append", "add", "extend", "values", "items", "__iter__"))
    egress = await make_egress(environ={"ROXY_TEST_UPSTREAM_BASE": mock.base_url})
    first = TOKEN_PREFIX + "FIRSTUI" + "11" * 100
    second = TOKEN_PREFIX + "SECONDUI" + "22" * 100
    await egress.credential.replace(first, ADMIN)
    await egress.credential.replace(second, ADMIN)
    for value in ([first, second], (first,), {"value": first}):
        with pytest.raises(TypeError):
            await egress.credential.replace(value, ADMIN)  # type: ignore[arg-type]
    rows = dbs.control.read_sync(lambda conn: conn.execute("SELECT count(*) FROM credential_store").fetchone()[0])
    assert rows == 1
    with pytest.raises(sqlite3.IntegrityError):
        dbs.control.write_sync(
            lambda conn: conn.execute(
                "INSERT INTO credential_store (id, ciphertext, nonce, set_at, set_by) VALUES (2, x'00', x'00', 0, 'x')"
            )
        )
    assert (await egress.credential.probe("admin_check")).ok
    await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/authenticated"))
    assert mock.requests[-1].header("Cookie") == f".ROBLOSECURITY={second}"


# ------------------------------------------------------------------------------------------------ item 9


async def test_superseded_bootstrap_never_reused(make_egress: Any, mock: Any, dbs: Any, secret: str) -> None:
    """19.5 item 9: after a UI replace, a restart with the old bootstrap file does not use it, even if the UI
    value disappears without the audited delete action (a restored or hand-edited database)."""
    environ = {"ROXY_TEST_UPSTREAM_BASE": mock.base_url}
    first = await make_egress(environ=environ)
    replacement = TOKEN_PREFIX + "UIVALUE" + "33" * 100
    await first.credential.replace(replacement, ADMIN)
    await first.aclose()
    restarted = await make_egress(environ=environ, worker_id="restarted")
    status = restarted.credential.status()
    assert status.source == "ui"
    assert status.bootstrap_superseded
    dbs.control.write_sync(lambda conn: conn.execute("DELETE FROM credential_store"))  # not the audited action
    again = await make_egress(environ=environ, worker_id="restarted-again")
    status = again.credential.status()
    assert not status.present
    assert status.problem == "bootstrap_superseded"
    assert status.status == "unavailable"
    assert (await again.credential.probe("admin_check")).outcome == "bootstrap_superseded"
    count = len(mock.requests)
    with pytest.raises(EgressDisabled):
        await again.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/authenticated"))
    assert len(mock.requests) == count
    assert again.credential.leak_matcher().matches(secret.encode())  # still guarded against leaks


# ------------------------------------------------------------------------------------------------ item 11 (part)


def _database_bytes(env: Any) -> bytes:
    blobs = []
    for path in env.state_dir.iterdir():
        if path.name.endswith((".db", ".db-wal", ".db-shm")):
            blobs.append(path.read_bytes())
    return b"".join(blobs)


async def test_secret_replace_leaves_no_trace(make_egress: Any, mock: Any, env: Any, dbs: Any) -> None:
    """19.5 item 11, egress part: a credential replace and a rotator URL replace leave the values in no database
    file and no log line. (Captures and the LLM export are scanned by their own packages' tests.)"""
    stream = io.StringIO()
    configure_logging("debug", stream=stream)
    recorder = Recorder()
    egress = await make_egress(environ={"ROXY_TEST_UPSTREAM_BASE": mock.base_url}, recorder=lambda: recorder)
    new_credential = TOKEN_PREFIX + "NOTRACEVALUE" + "4D" * 150
    new_url = "http://dpuser:NoTracePassword77@127.0.0.1:19"
    await egress.credential.replace(new_credential, ADMIN, reason="no trace")
    await egress.rotator.replace_url(new_url, ADMIN, reason="no trace")
    assert (await egress.credential.probe("admin_check")).ok
    await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/authenticated"))
    logging.getLogger("roxy.test").info("event", extra={"fields": {"url": new_url, "value": new_credential}})
    await egress.aclose()
    dbs.close_all_sync()
    stored = _database_bytes(env)
    assert harness.leak_findings(stored, new_credential) == []
    assert b"NoTracePassword77" not in stored
    logs = stream.getvalue().encode()
    assert harness.leak_findings(logs, new_credential) == []
    assert b"NoTracePassword77" not in logs
    assert json.dumps([e[3] for e in recorder.events]).find("NoTrace") == -1


# ------------------------------------------------------------------------------------------------ item 12


async def test_debug_logging_never_leaks(
    make_egress: Any, mock: Any, secret: str, fake_secrets: dict[str, str], env: Any, settings: Any
) -> None:
    """19.5 item 12 (9.15): at DEBUG, credential and rotator requests (and a guard trip and a cookie rotation)
    leave no secret in the log output."""
    stream = io.StringIO()
    configure_logging("debug", stream=stream)
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING
    settings.set("rotator_session_username_template", "{user}-sessid-{session}")
    echo_env = env.model_copy(update={"rotator_ip_echo_url": f"{mock.base_url}/ip"})
    with harness.RecordingProxy(upstream=mock.address) as proxy:
        egress = await make_egress(environ=forward_environ(mock, proxy), env=echo_env)
        assert (await egress.credential.probe("admin_check")).ok
        mock.routes["/v1/users/1"] = harness.MockResponse(
            body=b"{}", headers=[("Set-Cookie", ".ROBLOSECURITY=" + "E5" * 120 + "; path=/")]
        )
        await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/1"))
        await egress.send(Egress.ROTATOR, out("https://games.roblox.com/v1/games?universeIds=1"))
        await egress.rotator.exit_ip_probe()
        with pytest.raises(CredentialLeakBlocked):
            await egress.send(Egress.ROTATOR, out("https://games.roblox.com/v1/x?k=" + secret_part(secret)[:40]))
        logging.getLogger("httpx").debug("request headers %s", {"Cookie": f".ROBLOSECURITY={secret}"})
        logging.getLogger("roxy.test").debug("dump %r", {"cookie": secret, "proxy": fake_secrets["rotator_url"]})
        await egress.aclose()
    output = stream.getvalue()
    assert output  # something was logged at all
    assert harness.leak_findings(output.encode(), secret) == []
    assert "E5E5E5E5E5E5E5E5E5E5E5E5" not in output
    password = fake_secrets["rotator_url"].split(":")[2].split("@")[0]
    assert password not in output
    assert "dppw1" not in output


# ------------------------------------------------------------------------------------------------ guard self-test


async def test_h_cred_guard_self_test_never_sends(make_egress: Any, mock: Any) -> None:
    """13.2 H-CRED-GUARD: the self-test blocks every synthetic credential-bearing rotator request in-process."""
    egress = await make_egress(environ={"ROXY_TEST_UPSTREAM_BASE": mock.base_url})
    result = await egress.self_test_leak_guard()
    assert result.status == "pass"
    assert result.facts["reached_network"] == 0
    assert mock.requests == []
    assert egress.is_enabled(Egress.ROTATOR)[1] != "leak_guard_tripped"  # a self-test never trips the egress
    await asyncio.sleep(0)


def test_suite_uses_only_fake_values(fake_secrets: dict[str, str]) -> None:
    """The secrets here are generated per run and point at loopback port 9 (plan 19.12, C4)."""
    assert "FAKETESTCREDENTIAL" in fake_secrets["roblox_credential"]
    assert "@127.0.0.1:9" in fake_secrets["rotator_url"]
    assert SimpleNamespace  # imported for symmetry with the unit tests; keeps the import list stable
