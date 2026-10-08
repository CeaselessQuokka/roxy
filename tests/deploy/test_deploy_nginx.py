"""nginx config: the site template renders for nginx 1.18, 1.24 and 1.25.1 or later, and `nginx -t` accepts it.

What this is
    Tests for deploy/nginx/ (plan 17.2): rendering rules of deploy/tools/roxy-nginx-apply (`render_site`,
    `site_values`), the required directives (security header snippet in every location with its own add_header,
    /internal 404, gzip off on /admin, unbuffered SSE, limit_req zones and a limit on every location that reaches
    the app, upstream keepalive below the app's, no log of the kill-switch path), the rule that every directive is
    commented, `nginx -t` against real nginx binaries when they are available, and a running nginx 1.24 that is
    flooded (tests/deploy/nginx_live_driver.py) to show which requests reach the app and what reaches the logs.

Why it exists
    v1's nginx config used `http2 on`, which the distro nginx on Ubuntu 22.04 and 24.04 rejects (v1 notes 12.1), so
    it could only ever have been tested on another machine. The plan targets nginx 1.18 and 1.24 (17.2, 19.10 row
    17); the template keeps both correct, and this suite proves it with the real binaries.

How it works
    Binaries come from $ROXY_TEST_NGINX_118, $ROXY_TEST_NGINX, $ROXY_TEST_NGINX_NEW, or the no-root unpack locations
    (~/.local/nginx118root, ~/.local/nginxroot, ~/.local/nginxnewroot: `apt-get download` plus `dpkg -x`). A test
    whose binary is missing is skipped with the reason. `nginx -t` runs with `-p <prefix>` and a copy of Ubuntu's
    own /etc/nginx/nginx.conf (the http-level directives there are exactly what can collide with a site file),
    certificates from trustme. nginx -t binds the listen sockets, so it runs inside a private user and network
    namespace (`unshare -rn`) where ports 80 and 443 may be bound; where namespaces are not allowed the listen
    ports are moved above 1024 instead.

What to read next
    deploy/nginx/roxy.conf.template, then deploy/tools/roxy-nginx-apply.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from deploy_sandbox import (
    DEPLOY,
    build_prefix,
    can_unshare,
    high_ports,
    load_script,
    nginx_binaries,
    nginx_command,
    ubuntu_nginx_conf,
)

pytestmark = [pytest.mark.deploy]

TEMPLATE = (DEPLOY / "nginx" / "roxy.conf.template").read_text(encoding="utf-8")
HOST = "roxy.example.test"
HOME = Path.home()


@pytest.fixture(scope="module")
def nginx_apply() -> ModuleType:
    return load_script(DEPLOY / "tools" / "roxy-nginx-apply", "roxy_nginx_apply_for_nginx_tests")


def render(module: ModuleType, version: tuple[int, int, int], root: Path = Path("/srv/test")) -> str:
    layout = module.Layout(
        nginx_dir=root / "nginx", log_dir=root / "logs", cert_root=root / "certs", releases_dir=root / "releases"
    )
    values = module.site_values({"ROXY_SITE_ORIGIN": f"https://{HOST}"}, layout)
    return str(module.render_site(TEMPLATE, version=version, values=values))


# --------------------------------------------------------------------------------- a tiny nginx parser


def parse(text: str) -> list[Any]:
    """Parse nginx config into nested [name, args, children] lists (enough for structural assertions)."""
    tokens = re.findall(r"#[^\n]*|'[^']*'|\"[^\"]*\"|[{};]|[^\s{};]+", text)
    stack: list[list[Any]] = [[]]
    current: list[str] = []
    for token in tokens:
        if token.startswith("#"):
            continue
        if token == ";":
            stack[-1].append([current[0], current[1:], []])
            current = []
        elif token == "{":
            block: list[Any] = [current[0], current[1:], []]
            stack[-1].append(block)
            stack.append(block[2])
            current = []
        elif token == "}":
            stack.pop()
        else:
            current.append(token)
    assert len(stack) == 1, "unbalanced config"
    assert not current, "unbalanced config"
    return stack[0]


def find(nodes: list[Any], name: str) -> list[Any]:
    return [node for node in nodes if node[0] == name]


def directive(nodes: list[Any], name: str) -> list[str] | None:
    found = find(nodes, name)
    return found[0][1] if found else None


def main_server(nodes: list[Any]) -> list[Any]:
    """The HTTPS server for our names (the one with locations)."""
    servers = [node for node in find(nodes, "server") if find(node[2], "location")]
    https = next(s for s in servers if any("443" in " ".join(lst[1]) for lst in find(s[2], "listen")))
    return list(https[2])


def locations(server: list[Any]) -> dict[str, list[Any]]:
    return {" ".join(node[1]): node[2] for node in find(server, "location")}


# ------------------------------------------------------------------------------------------- rendering

VERSIONS = [(1, 18, 0), (1, 24, 0), (1, 25, 1), (1, 30, 5)]


@pytest.mark.parametrize("version", VERSIONS, ids=lambda v: ".".join(map(str, v)))
def test_render_leaves_no_template_syntax(nginx_apply: ModuleType, version: tuple[int, int, int]) -> None:
    text = render(nginx_apply, version)
    assert "{{" not in text
    assert "}}" not in text
    assert not [line for line in text.splitlines() if line.lstrip().startswith("#@")]
    parse(text)  # balanced braces


def test_render_http2_and_default_server_by_version(nginx_apply: ModuleType) -> None:
    old = render(nginx_apply, (1, 18, 0))
    assert "listen 443 ssl http2;" in old
    assert "http2 on;" not in old
    assert "ssl_reject_handshake" not in old
    assert "return 444;" in old
    distro = render(nginx_apply, (1, 24, 0))
    assert "listen 443 ssl http2;" in distro
    assert "http2 on;" not in distro
    assert "ssl_reject_handshake on;" in distro
    new = render(nginx_apply, (1, 25, 1))
    assert "http2 on;" in new
    assert "ssl http2" not in new
    assert "ssl_reject_handshake on;" in new


def test_render_names_and_fixed_redirect(nginx_apply: ModuleType) -> None:
    text = render(nginx_apply, (1, 24, 0))
    assert f"server_name {HOST} www.{HOST};" in text
    assert f"return 301 https://{HOST}$request_uri;" in text
    assert "$host$request_uri" not in text, "never redirect to the attacker-supplied Host (v1 bug)"
    assert f"ssl_certificate /srv/test/certs/{HOST}/fullchain.pem;" in text


@pytest.mark.parametrize(
    "origin",
    [
        "http://roxy.example.test",
        "https://roxy.example.test:8443",
        "https://roxy.example.test/x",
        "https://evil.test;include /etc/shadow",
        "https://-bad.test",
        "https://localhost",
    ],
)
def test_site_values_refuse_unsafe_origins(nginx_apply: ModuleType, origin: str) -> None:
    with pytest.raises(nginx_apply.ApplyError):
        nginx_apply.site_values({"ROXY_SITE_ORIGIN": origin}, nginx_apply.Layout())


def test_site_values_refuse_unsafe_server_names(nginx_apply: ModuleType) -> None:
    env = {"ROXY_SITE_ORIGIN": f"https://{HOST}", "ROXY_NGINX_SERVER_NAMES": f"{HOST} evil;"}
    with pytest.raises(nginx_apply.ApplyError):
        nginx_apply.site_values(env, nginx_apply.Layout())


def test_site_values_refuse_unsafe_paths(nginx_apply: ModuleType) -> None:
    layout = nginx_apply.Layout(log_dir=Path("/var/log/nginx; access_log /etc/cron.d/x"))
    with pytest.raises(nginx_apply.ApplyError):
        nginx_apply.site_values({"ROXY_SITE_ORIGIN": f"https://{HOST}"}, layout)


@pytest.mark.parametrize(
    "template",
    [
        "#@if nginx >= 1.0.0\n#@if nginx >= 1.0.0\n#@endif\n#@endif\n",
        "#@else\n",
        "#@endif\n",
        "#@if nginx >= 1.0.0\n",
        "x {{UNKNOWN}};\n",
        "#@include something\n",
        "x {{lower}};\n",
    ],
)
def test_render_rejects_bad_templates(nginx_apply: ModuleType, template: str) -> None:
    with pytest.raises(nginx_apply.ApplyError):
        nginx_apply.render_site(template, version=(1, 24, 0), values={})


# ------------------------------------------------------------------------------------ required directives


@pytest.fixture(scope="module")
def config(nginx_apply: ModuleType) -> list[Any]:
    return parse(render(nginx_apply, (1, 24, 0)))


def test_every_location_with_add_header_includes_the_security_snippet(config: list[Any]) -> None:
    """nginx drops inherited add_header in a location that has its own, so HSTS must be re-included (plan 17.2)."""
    server = main_server(config)
    assert any("roxy-security-headers.conf" in " ".join(n[1]) for n in find(server, "include"))
    for name, body in locations(server).items():
        if find(body, "add_header"):
            includes = " ".join(" ".join(n[1]) for n in find(body, "include"))
            assert "snippets/roxy-security-headers.conf" in includes, f"location {name} would lose HSTS"
    snippet = (DEPLOY / "nginx" / "snippets" / "roxy-security-headers.conf").read_text()
    assert 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;' in snippet
    directives = [line for line in snippet.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    assert directives, "no preload (D21)"
    assert all("preload" not in line for line in directives), "no preload (D21)"


def test_internal_is_404_and_never_proxied(config: list[Any]) -> None:
    locs = locations(main_server(config))
    for name in ("^~ /internal/", "= /internal"):
        assert directive(locs[name], "return") == ["404"]
        assert directive(locs[name], "proxy_pass") is None


def test_admin_locations(config: list[Any]) -> None:
    locs = locations(main_server(config))
    admin = [name for name in locs if "/admin" in name]
    assert set(admin) == {
        "= /admin",
        "^~ /admin/api/v1/auth/",
        "^~ /admin/invalidate/",
        "= /admin/api/v1/stream",
        "^~ /admin/",
    }
    for name in admin:
        assert directive(locs[name], "gzip") == ["off"], f"{name}: gzip must be off (BREACH, plan 9.6)"
    assert directive(locs["= /admin/api/v1/stream"], "proxy_buffering") == ["off"]
    assert directive(locs["= /admin/api/v1/stream"], "limit_req") is None
    assert directive(locs["^~ /admin/invalidate/"], "access_log") == ["off"], "the kill-switch token stays off disk"
    assert directive(locs["= /admin"], "limit_req") == ["zone=adminauth", "burst=10", "nodelay"]
    assert directive(locs["^~ /admin/api/v1/auth/"], "limit_req") == ["zone=adminauth", "burst=10", "nodelay"]
    assert directive(locs["^~ /admin/"], "limit_req") == ["zone=admin", "burst=120", "nodelay"]
    for name in ("= /admin", "^~ /admin/api/v1/auth/", "^~ /admin/", "= /admin/api/v1/stream"):
        log = directive(locs[name], "access_log") or []
        assert log, f"{name}: no query strings in the admin access log"
        assert log[-1] == "roxy_json_noquery", f"{name}: no query strings in the admin access log"


def test_public_locations(config: list[Any]) -> None:
    locs = locations(main_server(config))
    assert directive(locs["/"], "limit_req") == ["zone=perip", "burst=100", "nodelay"]
    assert directive(locs["= /csp-report"], "limit_req") == ["zone=cspreport", "burst=5"]
    assert directive(locs["= /health"], "access_log") == ["off"]
    static = locs["^~ /static/"]
    root = (directive(static, "root") or [""])[0]
    assert root.endswith("/current-$roxy_active_color/build/public"), "static files come from the active release"
    assert directive(static, "expires") == ["1y"]
    assert ["Cache-Control", '"public, immutable"'] in [n[1] for n in find(static, "add_header")]
    assert directive(static, "try_files") == ["$uri", "@roxy_static_fallback"]
    assert directive(locs["@roxy_static_fallback"], "proxy_pass") == ["http://roxy_app"]


def test_every_location_that_reaches_the_app_is_rate_limited(config: list[Any]) -> None:
    """Plan 17.2: floods are dropped before Python runs. That holds for every location that proxies to the app,
    not only `/`: /health reads the databases on every call and has no limiter in the app, and a missing static
    asset falls back to the app. The one exception is the SSE stream (one long-lived request per dashboard)."""
    locs = locations(main_server(config))
    unlimited = sorted(
        name for name, body in locs.items() if directive(body, "proxy_pass") and directive(body, "limit_req") is None
    )
    assert unlimited == ["= /admin/api/v1/stream"]
    for name in ("= /health", "@roxy_static_fallback"):
        assert directive(locs[name], "limit_req") == ["zone=perip", "burst=100", "nodelay"], name


def test_kill_switch_token_is_never_logged(config: list[Any]) -> None:
    """The one-time token is in the path of /admin/invalidate/<token>; plan 17.2 says it must never be written to
    disk. A refused (rate limited) request or an upstream error quotes the request line in the error log, so that
    location has its own error_log, which goes nowhere, as well as no access log."""
    location = locations(main_server(config))["^~ /admin/invalidate/"]
    assert directive(location, "access_log") == ["off"]
    assert directive(location, "error_log") == ["/dev/null"]


def test_zones_limits_and_timeouts(config: list[Any]) -> None:
    zones = {args[1].split(":")[0].removeprefix("zone="): args[2] for _, args, _ in find(config, "limit_req_zone")}
    assert zones == {"perip": "rate=20r/s", "adminauth": "rate=2r/s", "admin": "rate=30r/s", "cspreport": "rate=1r/s"}
    server = main_server(config)
    assert directive(server, "limit_conn") == ["connperip", "50"]
    assert directive(server, "limit_req_status") == ["429"]
    assert directive(server, "limit_conn_status") == ["429"]
    assert directive(server, "client_max_body_size") == ["2m"]
    assert directive(server, "ssl_protocols") == ["TLSv1.2", "TLSv1.3"]
    assert directive(server, "ssl_session_tickets") == ["off"]
    assert directive(server, "large_client_header_buffers") == ["4", "8k"]
    read_timeout = int((directive(server, "proxy_read_timeout") or ["0s"])[0].removesuffix("s"))
    assert read_timeout >= 60 + 10, "nginx must outlive the app's request deadline (plan 5.2)"
    assert directive(server, "proxy_http_version") == ["1.1"]
    assert directive(server, "proxy_set_header") is not None
    for server_block in find(config, "server"):
        assert directive(server_block[2], "server_tokens") == ["off"]


def test_upstream_keepalive_is_shorter_than_the_apps() -> None:
    """nginx's upstream idle timeout must stay below uvicorn's keep-alive, or callers see 502s (plan 5.2, 17.2)."""
    from roxy.worker import RoxyUvicornWorker

    app_keepalive = RoxyUvicornWorker.CONFIG_KWARGS["timeout_keep_alive"]
    for color, port in (("blue", "8001"), ("green", "8002")):
        nodes = parse((DEPLOY / "nginx" / f"roxy-upstream-{color}.conf").read_text())
        upstream = find(nodes, "upstream")[0]
        assert upstream[1] == ["roxy_app"]
        assert directive(upstream[2], "server") == [f"127.0.0.1:{port}"]
        assert directive(upstream[2], "keepalive") == ["64"]
        nginx_keepalive = int((directive(upstream[2], "keepalive_timeout") or ["0s"])[0].removesuffix("s"))
        assert nginx_keepalive < app_keepalive
        color_map = find(nodes, "map")[0]
        assert color_map[1] == ["$host", "$roxy_active_color"]
        assert directive(color_map[2], "default") == [color]
    env_blue = (DEPLOY / "env" / "blue.env.example").read_text()
    env_green = (DEPLOY / "env" / "green.env.example").read_text()
    assert "ROXY_BIND=127.0.0.1:8001" in env_blue
    assert "ROXY_BIND=127.0.0.1:8002" in env_green


@pytest.mark.parametrize(
    "path",
    [
        "roxy.conf.template",
        "roxy-upstream-blue.conf",
        "roxy-upstream-green.conf",
        "snippets/roxy-security-headers.conf",
    ],
)
def test_every_directive_is_commented(path: str) -> None:
    """Plan 17.2 and 18.1 item 8: each directive line has a comment on it or on the line above."""
    lines = (DEPLOY / "nginx" / path).read_text().splitlines()
    previous = ""
    missing = []
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            previous = line
            continue
        is_directive = not line.startswith("}") and not line.startswith("'")
        if is_directive and "#" not in line and not previous.startswith("#") and not previous.endswith(("'", "{")):
            missing.append(f"{number}: {line}")
        previous = line
    assert missing == []


# ------------------------------------------------------------------------------------------ nginx -t


@pytest.mark.parametrize("binary_info", [pytest.param(info, id=f"nginx-{info[0]}") for info in nginx_binaries()])
def test_nginx_t_accepts_the_rendered_site(nginx_apply: ModuleType, tmp_path: Path, binary_info: Any) -> None:
    label, binary, base, libs = binary_info
    if binary is None:
        pytest.skip(f"no nginx {label} binary (apt-get download + dpkg -x into ~/.local, see tests/deploy docs)")
    env = dict(os.environ, LD_LIBRARY_PATH=libs)
    version = nginx_apply.parse_nginx_version(
        subprocess.run([binary, "-v"], capture_output=True, text=True, env=env, check=False).stderr
    )
    prefix = tmp_path / "nginx"
    namespaced = can_unshare()
    build_prefix(prefix, ubuntu_nginx_conf(base), namespaced=namespaced)
    layout = nginx_apply.Layout(
        nginx_dir=prefix, log_dir=prefix / "logs", cert_root=prefix / "certs", releases_dir=prefix / "releases"
    )
    values = nginx_apply.site_values({"ROXY_SITE_ORIGIN": f"https://{HOST}"}, layout)
    rendered = nginx_apply.render_site(TEMPLATE, version=version, values=values)
    (prefix / "sites-enabled" / "roxy-v2.conf").write_text(rendered if namespaced else high_ports(rendered))
    for color in ("blue", "green"):  # both upstream files must load (the switch selects either)
        link = prefix / "roxy-active-upstream.conf"
        link.unlink()
        link.symlink_to(prefix / f"roxy-upstream-{color}.conf")
        result = subprocess.run(
            [*nginx_command(binary, prefix, version, unshare=namespaced), "-t"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        output = result.stderr + result.stdout
        assert result.returncode == 0, output
        assert "test is successful" in output
        problems = [line for line in output.splitlines() if "[warn]" in line or "[emerg]" in line]
        assert problems == [], problems


# ------------------------------------------------------------------------------------- a running nginx


@pytest.fixture(scope="module")
def live(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """tests/deploy/nginx_live_driver.py against the Ubuntu 24.04 nginx (1.24), inside `unshare -rn`."""
    if sys.platform != "linux" or not can_unshare() or not (shutil.which("ip") or Path("/usr/sbin/ip").exists()):
        pytest.skip("a running nginx needs unprivileged user and network namespaces (unshare -rn) and ip")
    found = [(binary, libs) for label, binary, _base, libs in nginx_binaries() if label == "1.24" and binary]
    if not found:
        pytest.skip("no nginx 1.24 binary (apt-get download + dpkg -x into ~/.local/nginxroot)")
    binary, libs = found[0]
    work = tmp_path_factory.mktemp("nginx-live")
    result = subprocess.run(
        [
            "unshare",
            "-rn",
            sys.executable,
            str(Path(__file__).parent / "nginx_live_driver.py"),
            binary,
            libs,
            str(work),
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    return dict(json.loads(result.stdout.strip().splitlines()[-1]))


@pytest.mark.parametrize(
    ("key", "path"), [("health", "/health"), ("static_missing", "/static/css/missing.ffffffffffff.css")]
)
def test_live_floods_never_reach_the_app_unlimited(live: dict[str, Any], key: str, path: str) -> None:
    """A real nginx refuses most of a 250-request flood of /health and of a missing static asset with 429; only
    what the perip zone allows (20 r/s plus the burst of 100) reaches the app."""
    statuses = live[key]["statuses"]
    assert statuses.get("429", 0) > 0, live[key]
    assert live["backend_hits"].get(path, 0) == statuses.get("200", 0)
    assert live["backend_hits"].get(path, 0) < live[key]["sent"]


def test_live_kill_switch_token_never_reaches_a_log_file(live: dict[str, Any]) -> None:
    assert live["kill_switch"]["statuses"].get("429", 0) > 0, "the flood was limited, which nginx logs"
    assert live["limit_lines"] > 0, "limited requests elsewhere are logged, so the log files were written"
    assert live["token_in_logs"] == [], live["log_files"]


def test_nginx_t_skips_cleanly_without_a_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The binary discovery never fails the suite: a missing nginx means a skipped test, not an error."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ROXY_TEST_NGINX", str(tmp_path / "missing"))
    found = nginx_binaries()
    assert [label for label, *_ in found] == ["1.18", "1.24", "new"]
    assert all(binary is None or Path(binary).is_file() for _, binary, _, _ in found)
