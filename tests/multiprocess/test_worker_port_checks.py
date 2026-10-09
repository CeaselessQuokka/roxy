"""The gunicorn hooks that make a taken port fail loudly with `reuse_port` (findings mp-3 and mp-4), unit level.

What this is
    Tests of `deploy/gunicorn.conf.py`'s `port_problem`, `check_ports_free` (run by `on_starting`), `pre_fork` and
    `resolve_bind`, with real loopback sockets and a stand-in for gunicorn's arbiter (`cfg.address` and `log`).
    tests/multiprocess/test_rr_mp_reuse_port.py runs the same hooks inside real gunicorn masters.

Why it exists
    With `reuse_port` every worker binds its own SO_REUSEPORT listener after the fork and the master binds nothing,
    so without these hooks a second master on a served port shares it silently, and a port another program holds
    leaves a READY master whose workers fail to bind forever. The hooks must refuse exactly those cases and never
    the master's own listeners.

How it works
    The config is executed the way gunicorn reads it (module-level settings from ROXY_* variables). Each test opens
    its listeners on an ephemeral loopback port and closes them at the end.

What to read next
    deploy/gunicorn.conf.py (module docstring, `on_starting`, `pre_fork`), tests/multiprocess/test_rr_mp_reuse_port.py.
"""

from __future__ import annotations

import errno
import importlib.util
import os
import socket
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(not hasattr(socket, "SO_REUSEPORT"), reason="needs SO_REUSEPORT (Linux)")


def _load_conf(monkeypatch: pytest.MonkeyPatch, **env: str) -> ModuleType:
    for name in list(os.environ):
        if name.startswith("ROXY_"):
            monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    name = f"worker_port_conf_{abs(hash(tuple(env.items())))}"
    spec = importlib.util.spec_from_file_location(name, REPO / "deploy" / "gunicorn.conf.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conf(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    return _load_conf(monkeypatch, ROXY_COLOR="blue", ROXY_BIND="127.0.0.1:8001")


class _Log:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str, *args: Any) -> None:
        self.errors.append(message % args)


def _server(port: int, *, master_pid: int = 0) -> Any:
    """What the hooks use of gunicorn's arbiter: the parsed `bind` (a TCP address and a Unix path) and the log."""
    config = SimpleNamespace(address=[("127.0.0.1", port), "/run/x.sock"])
    return SimpleNamespace(cfg=config, log=_Log(), master_pid=master_pid)


def _listener(*, reuse_port: bool, port: int = 0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if reuse_port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(8)
    return sock


@pytest.fixture
def opened() -> Iterator[list[socket.socket]]:
    sockets: list[socket.socket] = []
    yield sockets
    for sock in sockets:
        sock.close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_a_free_port_passes_both_checks(conf: ModuleType) -> None:
    port = _free_port()
    assert conf.port_problem("127.0.0.1", port, shared=False) is None
    assert conf.port_problem("127.0.0.1", port, shared=True) is None


def test_any_listener_refuses_the_startup_check(conf: ModuleType, opened: list[socket.socket]) -> None:
    """The start check sets no SO_REUSEPORT, so another master's SO_REUSEPORT workers refuse it too (mp-3)."""
    for reuse_port in (False, True):
        sock = _listener(reuse_port=reuse_port)
        opened.append(sock)
        port = int(sock.getsockname()[1])
        problem = conf.port_problem("127.0.0.1", port, shared=False)
        assert problem is not None
        assert problem.errno == errno.EADDRINUSE


def test_the_worker_check_accepts_the_masters_own_listeners_only(conf: ModuleType, opened: list[socket.socket]) -> None:
    own = _listener(reuse_port=True)
    opened.append(own)
    assert conf.port_problem("127.0.0.1", int(own.getsockname()[1]), shared=True) is None
    foreign = _listener(reuse_port=False)
    opened.append(foreign)
    problem = conf.port_problem("127.0.0.1", int(foreign.getsockname()[1]), shared=True)
    assert problem is not None
    assert problem.errno == errno.EADDRINUSE


def test_on_starting_check_exits_1_on_a_taken_port(conf: ModuleType, opened: list[socket.socket]) -> None:
    sock = _listener(reuse_port=True)  # another master's worker
    opened.append(sock)
    server = _server(int(sock.getsockname()[1]))
    with pytest.raises(SystemExit) as stopped:
        conf.check_ports_free(server, attempts=2, delay_s=0.01)
    assert stopped.value.code == 1
    assert len(server.log.errors) == 1
    assert server.log.errors[0].startswith("Connection in use: 127.0.0.1:")


def test_on_starting_check_passes_a_free_port(conf: ModuleType) -> None:
    server = _server(_free_port())
    conf.check_ports_free(server, attempts=1)
    assert server.log.errors == []


def test_a_port_freed_during_the_retries_is_used(
    conf: ModuleType, opened: list[socket.socket], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A master of this color that is still stopping may hold the port for a moment: the check retries."""
    sock = _listener(reuse_port=False)
    port = int(sock.getsockname()[1])
    monkeypatch.setattr(conf.time, "sleep", lambda _s: sock.close())
    conf.check_ports_free(_server(port), attempts=3, delay_s=0.0)


def test_pre_fork_halts_the_master_on_a_foreign_listener(conf: ModuleType, opened: list[socket.socket]) -> None:
    from gunicorn.errors import HaltServer

    own = _listener(reuse_port=True)
    opened.append(own)
    conf.pre_fork(_server(int(own.getsockname()[1])), object())  # the master's own workers: fine
    foreign = _listener(reuse_port=False)
    opened.append(foreign)
    with pytest.raises(HaltServer) as halted:
        conf.pre_fork(_server(int(foreign.getsockname()[1])), object())
    assert halted.value.exit_status == 1


def test_on_starting_skips_the_check_for_a_reexecuted_master(conf: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """A master started by USR2 inherits the port from its parent, which still serves it."""
    checked: list[Any] = []
    monkeypatch.setattr(conf, "check_ports_free", checked.append)
    monkeypatch.setattr(conf, "internal_listener", lambda server: "unix-listener")
    reexecuted = _server(1, master_pid=4242)
    conf.on_starting(reexecuted)
    assert checked == []
    assert reexecuted.LISTENERS == ["unix-listener"]
    fresh = _server(1)
    conf.on_starting(fresh)
    assert checked == [fresh]


@pytest.mark.parametrize(
    ("color", "expected"), [("blue", "127.0.0.1:8001"), ("green", "127.0.0.1:8002"), ("dev", "127.0.0.1:8001")]
)
def test_each_color_defaults_to_its_own_port(monkeypatch: pytest.MonkeyPatch, color: str, expected: str) -> None:
    conf = _load_conf(monkeypatch, ROXY_COLOR=color)
    assert conf.bind == [expected]
    assert conf.default_bind(color) == expected


def test_the_color_ports_match_the_nginx_upstreams(conf: ModuleType) -> None:
    for color, port in conf.COLOR_PORTS.items():
        upstream = (REPO / "deploy" / "nginx" / f"roxy-upstream-{color}.conf").read_text()
        assert f"server 127.0.0.1:{port};" in upstream


def test_hooks_never_import_roxy() -> None:
    """The master must start even when the app cannot be imported (module docstring of the config)."""
    source = (REPO / "deploy" / "gunicorn.conf.py").read_text()
    assert "import roxy" not in source
    assert "from roxy" not in source
