"""Post-start smoke test of one Roxy color, run by the deploy before nginx switches to it (plan 17.4 step 5).

What this is
    `python scripts/smoke_remote.py --color green --expect-version <sha>` checks a freshly started color on the
    server it runs on, before any caller reaches it:
      internal_version  the internal Unix socket answers /internal/version with the expected commit and color
      home              GET / on the color's TCP port is 200 HTML
      health            GET /health is 200
      admin_login       GET /admin (the login page) is 200 HTML
      internal_hidden   GET /internal/version on the TCP port is an immediate 404 from the app itself (internal
                        endpoints exist only on the socket; the path never reaches the proxy pipeline)
      proxy             a proxy request goes through the whole pipeline twice; the second answer carries a
                        Roxy-Cache header (with --strict-cache it must be a cache hit). On a color that is paused
                        or in throttle-all (an owner's choice, or a pause carried over from v1), Roxy's own pause
                        (503) or throttle-all (429) refusal is the right answer: the check verifies it is that
                        refusal and says so
      static            a content-hashed asset from the release's static manifest is 200 on the TCP port and, when
                        --nginx is given, 200 through nginx with Strict-Transport-Security
    Each check prints one PASS, FAIL or SKIP line; the exit status is 1 when any check failed. A check fails
    through `require` (an `if`, never an `assert`): `python -O` and PYTHONOPTIMIZE remove asserts, and a gate
    that passes everything under them is worse than none (finding sec-7).

Why it exists
    The health gate (/internal/ready) proves the workers started and the databases answer, but not that pages
    render, the proxy route is mounted, or the internal endpoints are really absent from the public port (plan
    5.8). Those are the mistakes that turn a "successful" deploy into an outage the moment nginx switches, so
    deploy.sh runs this before the switch and rolls back when it fails.

How it works
    The color's address and socket come from /etc/roxy/roxy.env and /etc/roxy/<color>.env (the deploy user can
    read them: 0640 root:roxy) unless --bind and --socket are given. httpx talks to the TCP port with the site's
    Host header, and to the Unix socket through `httpx.HTTPTransport(uds=...)`. Clients use `trust_env=False`, so
    no proxy variable in the deploy shell can redirect a check. The nginx check connects to the local nginx and
    sends the real host name in TLS SNI, so it works without hairpin routing to the public address.

What to read next
    `src/roxy/internal_app.py` (the socket endpoints), `deploy/deploy.sh` (steps 5 and 7), then
    `scripts/build_static.py` (where the static manifest comes from).
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

CACHE_HITS = frozenset({"HIT", "REVALIDATING", "COALESCED", "STALE"})
DEFAULT_PROXY_PATH = "/users.roblox.com/v1/users/1"
TIMEOUT = httpx.Timeout(20.0, connect=5.0)
INTERNAL_HIDDEN_TIMEOUT = httpx.Timeout(5.0)
"""The public app answers /internal at once; the probe tarpit (if the path ever reached the proxy) holds 8 s or more."""
RELEASE_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Result:
    name: str
    status: str  # PASS, FAIL or SKIP
    detail: str


def read_env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE lines (no shell expansion); a missing or unreadable file is empty."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


@dataclass
class Target:
    """Where the color listens, and how the site is named."""

    color: str
    base_url: str
    socket: str
    host: str
    expect_version: str | None


def resolve_target(args: argparse.Namespace) -> Target:
    env: dict[str, str] = {}
    if args.env_dir:
        env.update(read_env_file(Path(args.env_dir) / "roxy.env"))
        env.update(read_env_file(Path(args.env_dir) / f"{args.color}.env"))
    bind = args.bind or env.get("ROXY_BIND") or ("127.0.0.1:8001" if args.color == "blue" else "127.0.0.1:8002")
    socket_path = args.socket or env.get("ROXY_INTERNAL_SOCKET") or f"/run/roxy-{args.color}/internal.sock"
    origin = args.site_origin or env.get("ROXY_SITE_ORIGIN") or "https://roxytheproxy.com"
    host = urlsplit(origin).hostname or "localhost"
    return Target(args.color, f"http://{bind}", socket_path, host, args.expect_version)


class CheckFailed(Exception):
    """The color failed a check (raised by `require`)."""


def require(condition: bool, message: str) -> None:
    """Fail the running check with `message` unless `condition` holds.

    A plain `if`, never an `assert`: `python -O` and PYTHONOPTIMIZE strip asserts, and every check would then pass
    a color answering 500 everywhere, so deploy.sh would switch traffic to it (finding sec-7).
    """
    if not condition:
        raise CheckFailed(message)


def check(name: str, fn: Callable[[], str]) -> Result:
    """Run one check: a returned string is the PASS detail; CheckFailed is FAIL; SkipCheck is SKIP."""
    try:
        return Result(name, "PASS", fn())
    except SkipCheck as exc:
        return Result(name, "SKIP", str(exc))
    except CheckFailed as exc:
        return Result(name, "FAIL", str(exc) or "check failed")
    except httpx.HTTPError as exc:
        return Result(name, "FAIL", f"{type(exc).__name__}: {exc}")
    except ValueError as exc:  # a body that should be JSON is not (json.JSONDecodeError is a ValueError)
        return Result(name, "FAIL", f"{type(exc).__name__}: {exc}")


class SkipCheck(Exception):
    """The check does not apply here (for example no static files yet)."""


SWITCH_REFUSALS = {
    # Roxy-Refusal value: (status, the header only that refusal carries, the /health key that reports the switch)
    "paused": (503, "roxy-paused", "Paused"),
    "throttle_all": (429, "roxy-global-throttled", "ThrottleAll"),
}
"""Roxy's own answers while an owner's switch is on (abuse/checks/pause.py and throttle_all.py)."""


def switch_refusal(response: httpx.Response) -> str | None:
    """`paused` or `throttle_all` when `response` is exactly Roxy's own refusal for that switch, else None."""
    reason = (response.headers.get("roxy-refusal") or "").strip().lower()
    expected = SWITCH_REFUSALS.get(reason)
    if expected is None:
        return None
    status, marker, _ = expected
    if response.status_code != status or (response.headers.get(marker) or "").strip().lower() != "true":
        return None
    return reason


def static_asset(release_root: Path) -> str | None:
    """The URL of one hashed asset from the release's manifest, or None when there is none."""
    try:
        manifest = json.loads((release_root / "build" / "public" / "static-manifest.json").read_text("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(manifest, Mapping) or not manifest:
        return None
    return str(manifest[sorted(manifest)[0]])


def run_checks(
    target: Target,
    *,
    proxy_path: str | None,
    strict_cache: bool,
    nginx: str | None,
    release_root: Path = RELEASE_ROOT,
    verify: bool | ssl.SSLContext = True,
) -> list[Result]:
    headers = {"Host": target.host, "User-Agent": "roxy-smoke-remote"}
    tcp = httpx.Client(base_url=target.base_url, headers=headers, timeout=TIMEOUT, trust_env=False)
    internal = httpx.Client(
        transport=httpx.HTTPTransport(uds=target.socket), base_url="http://internal", timeout=TIMEOUT, trust_env=False
    )
    results: list[Result] = []
    try:

        def internal_version() -> str:
            body = internal.get("/internal/version").raise_for_status().json()
            require(isinstance(body, dict), "/internal/version did not answer a JSON object")
            version = body.get("Version")
            if target.expect_version is not None:
                require(version == target.expect_version, f"version {version!r}, expected {target.expect_version!r}")
            color = body.get("Color")
            require(color in (target.color, None), f"color {color!r}, expected {target.color!r}")
            return f"version {version}, color {color}"

        def home() -> str:
            response = tcp.get("/")
            require(response.status_code == 200, f"status {response.status_code}")
            content_type = response.headers.get("content-type", "")
            require(content_type.startswith("text/html"), f"content-type {content_type!r}")
            return "200 text/html"

        def health() -> str:
            response = tcp.get("/health")
            require(response.status_code == 200, f"status {response.status_code}")
            return "200"

        def admin_login() -> str:
            response = tcp.get("/admin")
            require(response.status_code == 200, f"status {response.status_code}")
            require(response.headers.get("content-type", "").startswith("text/html"), "not HTML")
            return "200 text/html"

        def internal_hidden() -> str:
            # A timeout here (httpx.ReadTimeout, a FAIL) or a Roxy-Refusal header means /internal reached the proxy
            # pipeline and its tarpit instead of the public app's own 404 (src/roxy/internal_app.py).
            response = tcp.get("/internal/version", timeout=INTERNAL_HIDDEN_TIMEOUT)
            require(
                response.status_code == 404, f"status {response.status_code}; internal endpoints must be 404 on TCP"
            )
            refusal = response.headers.get("roxy-refusal")
            require(refusal is None, f"refused by the proxy pipeline ({refusal}); /internal must never reach it")
            return "404 on the TCP port"

        def health_switches() -> dict[str, object]:
            """The color's /health document (Paused, and ThrottleAll when this release reports it), or {}."""
            try:
                body = tcp.get("/health").json()
            except (httpx.HTTPError, ValueError):
                return {}
            return body if isinstance(body, dict) else {}

        def switch_answer(second: httpx.Response, before: dict[str, object]) -> str | None:
            """The PASS detail when the answer is Roxy's own refusal for an owner's switch the color reports as on.

            A paused color answers every proxy request with its own 503 pause refusal and a color in throttle-all
            refuses the second request of an address with its own 429 (lead decision 1: an owner may pause on
            purpose, and a v1 paused at copy time makes v2 start paused). Either one still proves the request went
            through the proxy route and the abuse pipeline. /health must agree (read before and after the requests,
            so a switch flipped in between still counts); it reports Paused, and ThrottleAll where the release has
            it; without that key the refusal's own headers (Roxy-Refusal: throttle_all with
            Roxy-Global-Throttled: True) are the evidence.
            """
            reason = switch_refusal(second)
            if reason is None:
                return None
            _, marker, key = SWITCH_REFUSALS[reason]
            readings = [before, health_switches()]
            reported = [reading[key] for reading in readings if key in reading]
            if key == "Paused" or reported:
                require(
                    any(value is True for value in reported),
                    f"Roxy refused the proxy request as {reason} (status {second.status_code}), but /health does not "
                    f"say {key}",
                )
                evidence = f"/health says {key}"
            else:
                evidence = f"{marker}: True (/health does not report throttle-all)"
            what = "paused" if reason == "paused" else "in throttle-all"
            return (
                f"the color is {what} ({evidence}): Roxy's own {reason} refusal, status {second.status_code} with "
                f"Roxy-Refusal: {reason}; the proxy route is mounted"
            )

        def proxy() -> str:
            if not proxy_path:
                raise SkipCheck("--skip-proxy")
            before = health_switches()
            first = tcp.get(proxy_path)
            second = tcp.get(proxy_path)
            switched = switch_answer(second, before)
            if switched is not None:
                return switched
            state = second.headers.get("roxy-cache")
            require(
                state is not None, f"no Roxy-Cache header (status {second.status_code}); the proxy route is missing"
            )
            internal_error = second.status_code == 500 and "roxy-upstream-status" not in second.headers
            require(not internal_error, "status 500 from Roxy itself (no upstream status)")
            if strict_cache:
                require(str(state).upper() in CACHE_HITS, f"second request was {state}, expected a cache hit")
            return f"first {first.status_code} {first.headers.get('roxy-cache')}, second {second.status_code} {state}"

        def static() -> str:
            url = static_asset(release_root)
            if url is None:
                raise SkipCheck("no static files in this release")
            response = tcp.get(url)
            require(response.status_code == 200, f"{url}: status {response.status_code} on the TCP port")
            detail = f"{url} 200"
            if nginx:
                with httpx.Client(timeout=TIMEOUT, trust_env=False, verify=verify) as client:
                    via = client.get(
                        f"https://{nginx}{url}",
                        headers={"Host": target.host},
                        extensions={"sni_hostname": target.host},
                    )
                require(via.status_code == 200, f"{url}: status {via.status_code} through nginx")
                hsts = via.headers.get("strict-transport-security", "")
                require("max-age=" in hsts, f"{url}: no Strict-Transport-Security through nginx")
                detail += f"; through nginx 200 with HSTS ({hsts})"
            return detail

        for name, fn in (
            ("internal_version", internal_version),
            ("home", home),
            ("health", health),
            ("admin_login", admin_login),
            ("internal_hidden", internal_hidden),
            ("proxy", proxy),
            ("static", static),
        ):
            results.append(check(name, fn))
    finally:
        tcp.close()
        internal.close()
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke test one Roxy color before the deploy switches to it.")
    parser.add_argument("--color", required=True, choices=("blue", "green", "dev"))
    parser.add_argument("--expect-version", help="the commit /internal/version must report")
    parser.add_argument("--env-dir", default="/etc/roxy", help="where roxy.env and <color>.env are")
    parser.add_argument("--bind", help="host:port of the color (default: ROXY_BIND from the env files)")
    parser.add_argument("--socket", help="internal socket path (default: ROXY_INTERNAL_SOCKET)")
    parser.add_argument("--site-origin", help="public origin (default: ROXY_SITE_ORIGIN)")
    parser.add_argument("--proxy-path", default=DEFAULT_PROXY_PATH, help="a cacheable proxy path to request twice")
    parser.add_argument("--skip-proxy", action="store_true", help="skip the proxy check")
    parser.add_argument("--strict-cache", action="store_true", help="require a cache hit on the second request")
    parser.add_argument("--nginx", help="host:port of the local nginx to check HSTS on a static asset (TLS)")
    args = parser.parse_args(argv)
    target = resolve_target(args)
    results = run_checks(
        target,
        proxy_path=None if args.skip_proxy else args.proxy_path,
        strict_cache=args.strict_cache,
        nginx=args.nginx,
    )
    for result in results:
        print(f"{result.status:4}  {result.name:16}  {result.detail}")
    failed = [result.name for result in results if result.status == "FAIL"]
    print(f"smoke_remote: {len(results) - len(failed)} of {len(results)} checks passed on {target.color}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
