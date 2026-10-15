"""Egress targets: the last host check before a request leaves, and the test-only upstream override.

What this is
    `check_roblox_target(url, ...)` validates an outgoing URL the way plan 9.10 validates incoming ones (https only,
    port 443, no userinfo, a `*.roblox.com` host, and the `allowed_roblox_hosts` list when strict), returning the
    parsed `httpx.URL` or raising `TargetNotAllowed`. `check_echo_target` admits exactly one non-Roblox URL, the
    rotator's IP echo service (plan 8.1). `UpstreamTestOverride` is the development-only switch that sends every
    Roblox request to a local mock server for multi-process tests (documented in `clients.py`).

Why it exists
    The ingress validator (`proxy/validate.py`) already refuses bad URLs, but the egress is where a mistake would
    actually send bytes somewhere. Checking again here, on the final URL and on every redirect hop, is defense in
    depth for SSRF and for the credential (which may only go over https to an allowed Roblox host, C2 item 7).

How it works
    Hosts are lowercased, one trailing dot is stripped, and the result must `fullmatch` the Roblox host pattern
    (never `match` with `$`, which also matches before a trailing newline). IP literals, other ports and any
    userinfo are refused. The override reads two environment variables once at startup; in production either one
    is a startup error, and its base must be a loopback address, so even a mistake can only reach this machine.

What to read next
    `roxy/egress/clients.py` (where these checks run on every hop), then `roxy/egress/credential.py`
    (`authorize`, which repeats the credential rules right before the cookie is attached).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass

import httpx

from roxy.core.reasons import Egress
from roxy.egress.errors import EgressConfigError, TargetNotAllowed

ROBLOX_HOST_PATTERN = re.compile(r"(?:[a-z0-9-]+\.)*roblox\.com")
"""Every Roblox API host. Used with `fullmatch` only."""

HTTPS_PORT = 443

TEST_UPSTREAM_ENV = "ROXY_TEST_UPSTREAM_BASE"
"""Development only: send every Roblox request of the direct and credential clients (and the rotator's targets)
to this loopback base URL instead, for example `http://127.0.0.1:18080`."""

TEST_ROTATOR_PROXY_ENV = "ROXY_TEST_ROTATOR_PROXY"
"""Development only: the rotator's proxy URL (a local recording proxy) instead of the configured DataImpulse URL."""

TEST_HOST_HEADER = "X-Roxy-Test-Host"
"""Header naming the original Roblox host when the test override rewrote the URL."""

_LOOPBACK_NAMES = frozenset({"localhost"})


def normalize_host(raw: str) -> str | None:
    """Lowercase, strip exactly one trailing dot; None when the rest is empty, not ASCII, or has control chars."""
    host = raw.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or not host.isascii() or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in host):
        return None
    return host


def is_roblox_host(host: str, *, allowed_hosts: Collection[str], strict: bool) -> bool:
    """True when `host` (already normalized) is a Roblox host Roxy may call (plan 9.10)."""
    if ROBLOX_HOST_PATTERN.fullmatch(host) is None:
        return False
    return not strict or host in allowed_hosts


def _parse(url: str | httpx.URL, egress: Egress) -> httpx.URL:
    if isinstance(url, httpx.URL):
        return url
    if any(ch in url for ch in "\r\n\t\x00"):
        raise TargetNotAllowed(egress, "control character in URL")
    try:
        return httpx.URL(url)
    except (httpx.InvalidURL, ValueError, TypeError) as exc:
        raise TargetNotAllowed(egress, f"unparsable URL ({type(exc).__name__})") from exc


def check_roblox_target(
    url: str | httpx.URL,
    *,
    egress: Egress,
    allowed_hosts: Collection[str],
    strict: bool,
    require_listed: bool = False,
) -> httpx.URL:
    """Return the parsed URL if Roxy may send `egress` traffic there, else raise `TargetNotAllowed`.

    `require_listed=True` (the credential client) demands membership in `allowed_roblox_hosts` even when the strict
    switch is off: the account cookie only ever goes to hosts the owner listed.
    """
    parsed = _parse(url, egress)
    if parsed.scheme != "https":
        raise TargetNotAllowed(egress, "only https targets are allowed")
    if parsed.userinfo:
        raise TargetNotAllowed(egress, "userinfo in URL")
    if parsed.port not in (None, HTTPS_PORT):
        raise TargetNotAllowed(egress, "only port 443 is allowed")
    host = normalize_host(parsed.raw_host.decode("ascii", "replace"))
    if host is None:
        raise TargetNotAllowed(egress, "bad host")
    if not is_roblox_host(host, allowed_hosts=allowed_hosts, strict=strict or require_listed):
        raise TargetNotAllowed(egress, "host is not an allowed Roblox host")
    if host != parsed.host:
        parsed = parsed.copy_with(host=host)
    return parsed


def check_echo_target(url: str | httpx.URL, *, egress: Egress, echo_url: str) -> httpx.URL:
    """Return the parsed URL if it is exactly the configured IP echo service (same scheme, host, port and path)."""
    parsed = _parse(url, egress)
    expected = _parse(echo_url, egress)
    same = (
        parsed.scheme == expected.scheme
        and parsed.host == expected.host
        and parsed.port == expected.port
        and parsed.path == expected.path
        and not parsed.userinfo
    )
    if not same:
        raise TargetNotAllowed(egress, "only the configured IP echo service is allowed besides Roblox")
    return parsed


def endpoint_label(url: httpx.URL) -> str:
    """`host/path` with no query string: safe to put in an alert or an event (queries can carry anything)."""
    return f"{url.host}{url.path}"[:200]


def is_loopback_host(host: str) -> bool:
    """True for loopback IP literals and `localhost`."""
    name = host.strip("[]").lower()
    if name in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class UpstreamTestOverride:
    """Development-only redirection of Roblox traffic to local mock servers (see `clients.py` for the rules).

    `base` is the loopback mock upstream (None when only the rotator proxy is overridden); `rotator_proxy` is the
    loopback proxy URL the rotator uses instead of the configured DataImpulse URL.
    """

    __test__ = False  # not a pytest test class, whatever its name suggests

    base: httpx.URL | None
    rotator_proxy: str | None

    @classmethod
    def from_environ(cls, env_name: str, environ: Mapping[str, str]) -> UpstreamTestOverride | None:
        """Read the two variables. None when neither is set; `EgressConfigError` when set outside development."""
        base_raw = (environ.get(TEST_UPSTREAM_ENV) or "").strip()
        proxy_raw = (environ.get(TEST_ROTATOR_PROXY_ENV) or "").strip()
        if not base_raw and not proxy_raw:
            return None
        names = [name for name, value in ((TEST_UPSTREAM_ENV, base_raw), (TEST_ROTATOR_PROXY_ENV, proxy_raw)) if value]
        if env_name != "development":
            # Names only: a value could be anything. This stops the worker before it serves a single request.
            raise EgressConfigError(
                f"{', '.join(names)} is a test-only setting and is refused when ROXY_ENV={env_name}"
            )
        base = cls._loopback_url(TEST_UPSTREAM_ENV, base_raw, allow_https=True) if base_raw else None
        if base is not None and (base.path not in ("", "/") or base.query or base.userinfo):
            raise EgressConfigError(f"{TEST_UPSTREAM_ENV} must be a bare origin such as http://127.0.0.1:18080")
        proxy = str(cls._loopback_url(TEST_ROTATOR_PROXY_ENV, proxy_raw, allow_https=False)) if proxy_raw else None
        return cls(base=base, rotator_proxy=proxy)

    @staticmethod
    def _loopback_url(name: str, raw: str, *, allow_https: bool) -> httpx.URL:
        try:
            url = httpx.URL(raw)
        except (httpx.InvalidURL, ValueError) as exc:
            raise EgressConfigError(f"{name} is not a valid URL") from exc
        schemes = ("http", "https") if allow_https else ("http",)
        if url.scheme not in schemes or not url.host or url.port is None:
            raise EgressConfigError(f"{name} must look like http://127.0.0.1:<port>")
        if not is_loopback_host(url.host):
            raise EgressConfigError(f"{name} must point at a loopback address (tests never leave this machine)")
        return url

    def rewrite(self, url: httpx.URL) -> tuple[httpx.URL, dict[str, str]]:
        """The URL to actually connect to and the extra headers, for a validated Roblox `url`."""
        if self.base is None:
            return url, {}
        target = self.base.copy_with(raw_path=url.raw_path)
        return target, {"Host": url.host, TEST_HOST_HEADER: url.host}

    def owns(self, url: httpx.URL) -> bool:
        """True when `url` points at the override base (same scheme, host and port)."""
        base = self.base
        return base is not None and (url.scheme, url.host, url.port) == (base.scheme, base.host, base.port)


__all__ = [
    "ROBLOX_HOST_PATTERN",
    "TEST_HOST_HEADER",
    "TEST_ROTATOR_PROXY_ENV",
    "TEST_UPSTREAM_ENV",
    "UpstreamTestOverride",
    "check_echo_target",
    "check_roblox_target",
    "endpoint_label",
    "is_loopback_host",
    "is_roblox_host",
    "normalize_host",
]
