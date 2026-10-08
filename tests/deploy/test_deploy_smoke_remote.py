"""scripts/smoke_remote.py and scripts/build_static.py: the deploy's post-start smoke test and its static files.

What this is
    smoke_remote runs against a fake color (a loopback HTTP server and a Unix socket HTTP server) whose answers
    each test bends to make one check fail; the nginx HSTS check runs against a local TLS server with a trustme
    certificate. build_static runs against temporary static trees and against the app's real static directory, and
    its names are compared with what the app's `AssetHasher` serves.

Why it exists
    The smoke test is the last gate before nginx switches to a new color (plan 17.4 step 5), so each check must
    really fail when its condition breaks; a check that always passes is worse than none. build_static produces
    the file names nginx serves with a one-year immutable cache, so they must match the names in the pages
    byte for byte.

How it works
    `run_checks` takes a `Target` and returns PASS, FAIL or SKIP per check. The fake servers run in threads on
    127.0.0.1 and in the test's temporary directory; nothing leaves the machine.

What to read next
    scripts/smoke_remote.py, scripts/build_static.py, src/roxy/core/templating.py.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from deploy_sandbox import REPO, load_script

pytestmark = [pytest.mark.deploy]

HOST = "roxy.example.test"
SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture(scope="module")
def smoke() -> ModuleType:
    return load_script(REPO / "scripts" / "smoke_remote.py", "smoke_remote_for_tests")


@pytest.fixture(scope="module")
def build_static() -> ModuleType:
    return load_script(REPO / "scripts" / "build_static.py", "build_static_for_tests")


class FakeColor:
    """What a healthy color answers; tests change `answers` to break one thing."""

    def __init__(self) -> None:
        self.answers: dict[str, tuple[int, dict[str, str], bytes]] = {
            "/": (200, {"Content-Type": "text/html; charset=utf-8"}, b"<html>home</html>"),
            "/health": (200, {"Content-Type": "application/json"}, b'{"Status":"ok"}'),
            "/admin": (200, {"Content-Type": "text/html; charset=utf-8"}, b"<html>login</html>"),
            "/internal/version": (404, {}, b"Not Found"),
            "/static/css/app.0123456789.css": (200, {"Content-Type": "text/css"}, b"body{}"),
        }
        self.proxy_states = ["MISS", "HIT"]
        self.version = SHA
        self.color = "green"
        self.seen_hosts: list[str] = []


def make_handler(fake: FakeColor, *, internal: bool) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if not internal:
                fake.seen_hosts.append(self.headers.get("Host", ""))
            if internal:
                body = json.dumps({"Version": fake.version, "Color": fake.color}).encode()
                self.reply(200, {"Content-Type": "application/json"}, body)
            elif self.path.startswith("/users.roblox.com/"):
                state = fake.proxy_states.pop(0) if fake.proxy_states else "HIT"
                headers = {"Content-Type": "application/json"}
                if state:
                    headers["Roxy-Cache"] = state
                self.reply(200, headers, b'{"id":1}')
            else:
                self.reply(*fake.answers.get(self.path, (404, {}, b"Not Found")))

        def reply(self, status: int, headers: dict[str, str], body: bytes) -> None:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            return

    return Handler


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self) -> Any:
        request, _ = super().get_request()
        return request, ("local", 0)


@pytest.fixture
def color(tmp_path: Path) -> Iterator[tuple[FakeColor, Any]]:
    fake = FakeColor()
    tcp = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(fake, internal=False))
    sock_path = tmp_path / "internal.sock"
    uds = UnixHTTPServer(str(sock_path), make_handler(fake, internal=True))
    for server in (tcp, uds):
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    target = {"base_url": f"http://127.0.0.1:{tcp.server_address[1]}", "socket": str(sock_path)}
    try:
        yield fake, target
    finally:
        for server in (tcp, uds):
            server.shutdown()
            server.server_close()


@pytest.fixture
def release(tmp_path: Path) -> Path:
    root = tmp_path / "release"
    (root / "build" / "public").mkdir(parents=True)
    (root / "build" / "public" / "static-manifest.json").write_text(
        json.dumps({"css/app.css": "/static/css/app.0123456789.css"})
    )
    return root


def results(smoke: ModuleType, target: dict[str, str], release: Path, **kwargs: Any) -> dict[str, tuple[str, str]]:
    tgt = smoke.Target("green", target["base_url"], target["socket"], HOST, kwargs.pop("expect", SHA))
    found = smoke.run_checks(
        tgt,
        proxy_path=kwargs.pop("proxy_path", "/users.roblox.com/v1/users/1"),
        strict_cache=kwargs.pop("strict_cache", False),
        nginx=kwargs.pop("nginx", None),
        release_root=release,
        **kwargs,
    )
    return {r.name: (r.status, r.detail) for r in found}


def test_healthy_color_passes(smoke: ModuleType, color: Any, release: Path) -> None:
    fake, target = color
    found = results(smoke, target, release, strict_cache=True)
    assert {name: status for name, (status, _) in found.items()} == {
        "internal_version": "PASS",
        "home": "PASS",
        "health": "PASS",
        "admin_login": "PASS",
        "internal_hidden": "PASS",
        "proxy": "PASS",
        "static": "PASS",
    }
    assert set(fake.seen_hosts) == {HOST}, "requests carry the site's Host header"


@pytest.mark.parametrize(
    ("break_it", "check"),
    [
        (lambda f: f.answers.update({"/internal/version": (200, {}, b"{}")}), "internal_hidden"),
        (lambda f: setattr(f, "version", "f" * 40), "internal_version"),
        (lambda f: setattr(f, "color", "blue"), "internal_version"),
        (lambda f: f.answers.update({"/": (500, {}, b"")}), "home"),
        (lambda f: f.answers.update({"/": (200, {"Content-Type": "application/json"}, b"{}")}), "home"),
        (lambda f: f.answers.update({"/admin": (404, {}, b"")}), "admin_login"),
        (lambda f: f.answers.update({"/health": (503, {}, b"")}), "health"),
        (lambda f: setattr(f, "proxy_states", ["", ""]), "proxy"),
        (lambda f: f.answers.pop("/static/css/app.0123456789.css"), "static"),
    ],
)
def test_each_check_fails_when_its_condition_breaks(
    smoke: ModuleType, color: Any, release: Path, break_it: Any, check: str
) -> None:
    fake, target = color
    break_it(fake)
    found = results(smoke, target, release)
    assert found[check][0] == "FAIL", found
    assert [name for name, (status, _) in found.items() if status == "FAIL"] == [check]


def test_strict_cache_needs_a_hit(smoke: ModuleType, color: Any, release: Path) -> None:
    fake, target = color
    fake.proxy_states = ["MISS", "MISS"]
    assert results(smoke, target, release)["proxy"][0] == "PASS"
    fake.proxy_states = ["MISS", "MISS"]
    assert results(smoke, target, release, strict_cache=True)["proxy"][0] == "FAIL"


def test_skips(smoke: ModuleType, color: Any, tmp_path: Path) -> None:
    _, target = color
    found = results(smoke, target, tmp_path / "no-release", proxy_path=None)
    assert found["proxy"][0] == "SKIP"
    assert found["static"][0] == "SKIP"


def test_unreachable_socket_fails(smoke: ModuleType, color: Any, release: Path, tmp_path: Path) -> None:
    _, target = color
    target = {**target, "socket": str(tmp_path / "missing.sock")}
    assert results(smoke, target, release)["internal_version"][0] == "FAIL"


def test_nginx_hsts_check(smoke: ModuleType, color: Any, release: Path, tmp_path: Path) -> None:
    import trustme

    ca = trustme.CA()
    cert = ca.issue_cert(HOST)
    for with_hsts in (True, False):

        class TLSHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                if with_hsts:  # noqa: B023 (read at request time, inside this loop iteration)
                    self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: Any) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TLSHandler)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        cert.configure_cert(context)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        bundle = tmp_path / "ca.pem"
        ca.cert_pem.write_to_path(str(bundle))
        try:
            _, target = color
            found = results(
                smoke,
                target,
                release,
                nginx=f"127.0.0.1:{server.server_address[1]}",
                verify=ssl.create_default_context(cafile=str(bundle)),
            )
        finally:
            server.shutdown()
            server.server_close()
        assert found["static"][0] == ("PASS" if with_hsts else "FAIL"), found["static"]


def test_command_line_reads_the_env_files(smoke: ModuleType, color: Any, tmp_path: Path, capsys: Any) -> None:
    _, target = color
    env_dir = tmp_path / "etc"
    env_dir.mkdir()
    (env_dir / "roxy.env").write_text(f"ROXY_SITE_ORIGIN=https://{HOST}\n")
    (env_dir / "green.env").write_text(
        f"ROXY_BIND={target['base_url'].removeprefix('http://')}\nROXY_INTERNAL_SOCKET={target['socket']}\n"
    )
    code = smoke.main(["--color", "green", "--expect-version", SHA, "--env-dir", str(env_dir), "--skip-proxy"])
    output = capsys.readouterr().out
    assert code == 0, output
    assert "checks passed on green" in output


# ------------------------------------------------------------------------------------------- build_static


def test_build_static_names_match_the_app(build_static: ModuleType, tmp_path: Path) -> None:
    from roxy.core.templating import AssetHasher

    static = tmp_path / "static"
    (static / "css").mkdir(parents=True)
    (static / "css" / "app.css").write_text("body { color: black }")
    (static / "js").mkdir()
    (static / "js" / "app.min.js").write_text("console.log(1)")
    (static / ".DS_Store").write_text("junk")
    (static / "link.css").symlink_to(static / "css" / "app.css")
    out = tmp_path / "public"
    manifest = build_static.build(static, out)
    hasher = AssetHasher(static)
    assert manifest == {"css/app.css": hasher.url("css/app.css"), "js/app.min.js": hasher.url("js/app.min.js")}
    for logical, url in manifest.items():
        built = out / url.lstrip("/")
        assert built.read_bytes() == (static / logical).read_bytes()
        assert built.stat().st_mode & 0o777 == 0o644
        assert hasher.resolve(url.removeprefix("/static/")) == (logical, True), "the app maps the name back"
    assert json.loads((out / "static-manifest.json").read_text()) == manifest
    (static / "css" / "app.css").write_text("body { color: white }")
    second = build_static.build(static, out)
    assert second["css/app.css"] != manifest["css/app.css"]
    assert not (out / manifest["css/app.css"].lstrip("/")).exists(), "a rebuild leaves no stale names"


def test_build_static_without_a_static_directory(build_static: ModuleType, tmp_path: Path) -> None:
    assert build_static.build(tmp_path / "missing", tmp_path / "public") == {}
    assert (tmp_path / "public" / "static").is_dir()


def test_build_static_on_the_real_static_directory(build_static: ModuleType, tmp_path: Path) -> None:
    from roxy.core.templating import STATIC_DIR, AssetHasher

    if not STATIC_DIR.is_dir():
        pytest.skip("the app has no static directory yet")
    manifest = build_static.build(STATIC_DIR, tmp_path / "public")
    hasher = AssetHasher(STATIC_DIR)
    for logical, url in manifest.items():
        assert url == hasher.url(logical)
        assert (tmp_path / "public" / url.lstrip("/")).is_file()
