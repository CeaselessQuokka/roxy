r"""Target validation: turn the raw request path into a safe Roblox URL, or say exactly why it is not one.

What this is
    `parse_target(raw_path, query_string, method)` reads the path a caller sent to the catch-all proxy route
    (`/games.roblox.com/v1/games?universeIds=1`) and returns a `TargetParse`: the lowercased host, the normalized
    path, the query pairs in caller order (with `prettyprint` taken out), and `problem`, which is None for a good
    target or one of the reason codes `unsafe_url`, `not_roblox` or `host_not_allowed`. It never raises.
    `build_upstream_url(host, path, query)` is the one way to turn a valid parse back into the https URL Roblox
    receives. `parse_upstream_url(url)` and `parse_redirect(current_url, location)` apply the same checks to an
    absolute URL (a redirect target the upstream layer is about to follow, a probe URL).

Why it exists
    This is Roxy's server-side request forgery (SSRF) defense (plan 9.10): an attacker who can make Roxy call any
    host could reach internal services or use Roxy to attack others. v1 checked the decoded path with
    `re.match(r"^[a-z]+\.roblox\.com/")` and HTML-escaped the URL (bugs B3, B4 and B17 in the v1 notes): a
    percent-encoded `?` split the upstream URL, `..` segments let a request evade a block while fetching the
    blocked path, and legitimate characters were refused. v2 parses the URL once, and the path every rule matches
    is exactly the path Roblox receives.

How it works
    The RAW path (still percent-encoded, as the caller sent it) is used, never the server's decoded copy, because
    decoding first would hide encoded slashes. Steps, in order:
    1. Length: path plus query longer than `max_url_length` is unsafe (the middleware's 414 normally answers
       first; this is defense in depth).
    2. v1 probe characters: if the decoded target contains `<`, `>`, `"`, a backtick or a backslash, the target is
       `unsafe_url` (v1 answered these with "Invalid URL" too). `&` and `'` are allowed now: they are ordinary
       path characters (RFC 3986 sub-delims) that v1 refused by mistake (B17).
    3. Host (the first segment), plan 9.10 exactly, with one extra guard: a host containing `%` (encoded dots or
       slashes) or any non-ASCII byte is refused BEFORE lowercasing, because `str.lower()` turns some non-ASCII
       letters into ASCII ones (the Kelvin sign becomes `k`). Then lowercase, strip exactly one trailing dot,
       refuse empty, control characters or more than 253 characters, require
       `re.fullmatch(r"(?:[a-z0-9-]+\.)*roblox\.com", host)` (fullmatch, because `re.match` with `$` also matches
       before a trailing newline), and, while `strict_host_allowlist` is on, membership in
       `allowed_roblox_hosts`. Any failure is `not_roblox`, except a roblox.com host missing from the allowlist,
       which is `host_not_allowed`; callers get 404 "Not a Roblox URL" for both. There must be a `/` after the
       host (v1 parity: `/games.roblox.com` alone is not a Roblox URL). Scheme https and port 443 are implied:
       a port, user name or IP literal in the host fails the fullmatch.
    4. Path: split the raw path on `/` FIRST, then percent-decode each segment, so `%2F` can be seen and refused
       (an encoded slash changes meaning). Each decoded segment must be valid UTF-8 and free of control
       characters (CR and LF included), `%` (double encoding), `?` and `#` (they would split the URL, v1 B3).
       `.` and `..` segments are refused (v1 B4). Empty segments are dropped, so `//v1` becomes `/v1` (a block on
       `/v1/x` cannot be dodged with a double slash); a trailing slash is kept.
    5. Query: `parse_qsl` with blank values kept, in caller order (`ids=1&ids=2` stays two pairs, plan row 2).
       Every `prettyprint` pair is removed (exact, case-sensitive name, as v1); pretty printing is on when the
       LAST one equals `true` ignoring case. NUL, CR and LF inside a name or value make the target unsafe.
    The decoded path cannot contain `%`, `?` or `#`, so encoding it again (`build_upstream_url`) is lossless and
    unambiguous: one decoded form for the rules and the cache, one encoded form for Roblox.

What to read next
    `roxy/proxy/router.py` (where the parse becomes a `ProxyRequest`), then `roxy/proxy/scrub.py` (which caller
    headers may go upstream) and `tests/security/test_ssrf.py` (the attack corpus).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote_to_bytes, urlencode, urljoin, urlsplit

from roxy.config.settings.routing import DEFAULT_ALLOWED_ROBLOX_HOSTS
from roxy.core.reasons import ReasonCode

HOST_PATTERN = re.compile(r"(?:[a-z0-9-]+\.)*roblox\.com")
"""Plan 9.10: one or more labels of lowercase letters, digits and hyphens, ending in roblox.com. Use fullmatch."""

UNSAFE_CHARACTERS = frozenset('<>"`\\')
"""Characters that never appear in a real Roblox API URL and mark HTML or path-traversal probes (v1 step 7)."""

PATH_FORBIDDEN = frozenset("%?#")
"""Decoded path characters that would change the URL's meaning if sent on (double encoding, query, fragment)."""

QUERY_FORBIDDEN = frozenset("\x00\r\n")
"""Decoded query characters refused outright: NUL, CR and LF have no use in a Roblox API call."""

PRETTYPRINT_PARAM = "prettyprint"
MAX_HOST_LENGTH = 253
MAX_QUERY_FIELDS = 1000
DEFAULT_MAX_URL_LENGTH = 4096
MAX_LOGGED_TARGET = 300
"""The decoded target kept for logs and probe records is cut to this many characters."""
MAX_RAW_TARGET = 8192
"""Upper bound of `raw_target` (the longest URL the `max_url_length` setting allows)."""

PATH_SAFE_CHARACTERS = "/!$&'()*+,;=:@"
"""Characters `quote` leaves as they are in a path (RFC 3986 pchar plus `/`); letters, digits and `-._~` always."""

DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset(DEFAULT_ALLOWED_ROBLOX_HOSTS)


@dataclass(frozen=True, slots=True)
class TargetParse:
    """The result of `parse_target`. For a target with a problem, host and path are best effort (for logs only)."""

    method: str
    host: str
    """Lowercased, one trailing dot removed; for example `games.roblox.com`."""
    path: str
    """Decoded and normalized, always starting with `/`; for example `/v1/games`."""
    query: tuple[tuple[str, str], ...]
    """Decoded (name, value) pairs in caller order, every `prettyprint` pair removed."""
    prettyprint: bool
    target: str
    """What rules match: `host` plus `path` without the leading slash (v1's `dst`). For a target with a problem,
    the decoded text after the first `/` as received (so ignored paths such as `favicon.ico` still match)."""
    raw_query: str
    problem: ReasonCode | None
    detail: str
    """Why the target is refused, in plain words, for logs and the probe record ("" when valid)."""
    raw_target: str = ""
    """The percent-decoded path after the first `/` exactly as received, before normalization (v1's `dst`): what
    ignored paths and probe signatures look at."""

    @property
    def ok(self) -> bool:
        return self.problem is None

    @property
    def upstream_url(self) -> str:
        """The https URL Roblox receives (only meaningful when `ok`)."""
        return build_upstream_url(self.host, self.path, self.query)


def quote_path(path: str) -> str:
    """Percent-encode a decoded, validated path for the wire (UTF-8, RFC 3986 path characters kept)."""
    return quote(path, safe=PATH_SAFE_CHARACTERS)


def encode_query(pairs: Iterable[tuple[str, str]]) -> str:
    """Form-encode query pairs in order, the way v1's `requests` sent them (a space becomes `+`)."""
    return urlencode(list(pairs))


def build_upstream_url(host: str, path: str, query: Iterable[tuple[str, str]] = ()) -> str:
    """`https://<host><encoded path>[?<encoded query>]`. Port 443 and the https scheme are never configurable."""
    encoded_query = encode_query(query)
    return f"https://{host}{quote_path(path or '/')}" + (f"?{encoded_query}" if encoded_query else "")


def _as_bytes(value: bytes | bytearray | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes | bytearray):
        return bytes(value)
    return value.encode("utf-8", "surrogateescape")


def _has_control(text: str) -> bool:
    """True when `text` holds an ASCII control character (including CR, LF, TAB, NUL and DEL)."""
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text)


@dataclass(slots=True)
class _Parts:
    """Working state of one parse, so each step can stop with a problem."""

    method: str
    raw_query: str
    target: str = ""
    host: str = ""
    path: str = "/"
    query: tuple[tuple[str, str], ...] = ()
    prettyprint: bool = False
    raw_target: str = ""

    def result(self, problem: ReasonCode | None = None, detail: str = "") -> TargetParse:
        return TargetParse(
            method=self.method,
            host=self.host,
            path=self.path,
            query=self.query,
            prettyprint=self.prettyprint,
            target=self.target,
            raw_query=self.raw_query,
            problem=problem,
            detail=detail,
            raw_target=self.raw_target,
        )


def parse_query(query_text: str) -> tuple[tuple[tuple[str, str], ...], bool, str | None]:
    """Split a raw query string into (pairs without prettyprint, prettyprint flag, problem detail or None)."""
    try:
        pairs = parse_qsl(query_text, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS, errors="replace")
    except ValueError:
        return (), False, f"more than {MAX_QUERY_FIELDS} query parameters"
    kept: list[tuple[str, str]] = []
    pretty_values: list[str] = []
    for name, value in pairs:
        if QUERY_FORBIDDEN.intersection(name) or QUERY_FORBIDDEN.intersection(value):
            return (), False, "control character in the query string"
        if name == PRETTYPRINT_PARAM:  # exact and case-sensitive, as v1 (`PrettyPrint` is an ordinary parameter)
            pretty_values.append(value)
        else:
            kept.append((name, value))
    pretty = bool(pretty_values) and pretty_values[-1].lower() == "true"  # the LAST value wins (v1)
    return tuple(kept), pretty, None


def check_host(host_raw: bytes, allowed_hosts: Collection[str], strict: bool) -> tuple[str, ReasonCode | None, str]:
    """Plan 9.10 host check on the raw first path segment. Returns (host, problem, detail)."""
    best_effort = host_raw.decode("utf-8", "replace").lower()[:MAX_HOST_LENGTH]
    if b"%" in host_raw:
        return best_effort, ReasonCode.NOT_ROBLOX, "percent-encoded characters in the host"
    try:
        # ASCII is checked BEFORE lowercasing: str.lower() maps some non-ASCII letters to ASCII ones.
        host = host_raw.decode("ascii")
    except UnicodeDecodeError:
        return best_effort, ReasonCode.NOT_ROBLOX, "non-ASCII host"
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]  # exactly one trailing dot (a fully qualified name); `..` stays invalid
    if not host:
        return host, ReasonCode.NOT_ROBLOX, "empty host"
    if _has_control(host) or " " in host:
        return host[:MAX_HOST_LENGTH], ReasonCode.NOT_ROBLOX, "control character in the host"
    if len(host) > MAX_HOST_LENGTH:
        return host[:MAX_HOST_LENGTH], ReasonCode.NOT_ROBLOX, "host longer than 253 characters"
    if HOST_PATTERN.fullmatch(host) is None:
        return host, ReasonCode.NOT_ROBLOX, "host is not a roblox.com name"
    if strict and host not in allowed_hosts:
        return host, ReasonCode.HOST_NOT_ALLOWED, "host is not in allowed_roblox_hosts"
    return host, None, ""


def normalize_path(raw_segments: list[bytes]) -> tuple[str, str | None]:
    """Decode and normalize the path segments after the host. Returns (path, problem detail or None)."""
    kept: list[str] = []
    for raw in raw_segments:
        decoded = unquote_to_bytes(raw)
        if b"/" in decoded:
            return "/", "encoded slash in the path"
        try:
            segment = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return "/", "path is not valid UTF-8"
        if _has_control(segment):
            return "/", "control character in the path"
        if PATH_FORBIDDEN.intersection(segment):
            return "/", "encoded %, ? or # in the path"
        if segment in (".", ".."):
            return "/", "dot segment in the path"
        if segment:
            kept.append(segment)  # empty segments (`//`) are dropped
    trailing = len(raw_segments) > 1 and raw_segments[-1] == b"" and bool(kept)
    return "/" + "/".join(kept) + ("/" if trailing else ""), None


def parse_target(
    raw_path: bytes | str,
    query_string: bytes | str | None,
    method: str,
    *,
    allowed_hosts: Collection[str] | None = None,
    strict_host_allowlist: bool = True,
    max_url_length: int = DEFAULT_MAX_URL_LENGTH,
) -> TargetParse:
    """Parse the raw request path and query of a proxy request (plan 9.10). Never raises.

    `raw_path` is `scope["raw_path"]` (percent-encoded, as received; a query after `?` is split off when present),
    `query_string` is `scope["query_string"]`. `allowed_hosts` defaults to the shipped allowlist.
    """
    path_bytes = _as_bytes(raw_path)
    query_bytes = _as_bytes(query_string)
    if b"?" in path_bytes:  # some servers (and httpx's test transport) include the query in raw_path
        path_bytes, _, embedded = path_bytes.partition(b"?")
        query_bytes = query_bytes or embedded
    raw_query = query_bytes.decode("utf-8", "replace")
    parts = _Parts(method=(method or "GET").upper(), raw_query=raw_query)
    try:
        return _parse(path_bytes, query_bytes, parts, allowed_hosts, strict_host_allowlist, max_url_length)
    except Exception:  # never raise: anything unexpected is simply not a URL Roxy will fetch
        return parts.result(ReasonCode.UNSAFE_URL, "unparsable URL")


def _parse(
    path_bytes: bytes,
    query_bytes: bytes,
    parts: _Parts,
    allowed_hosts: Collection[str] | None,
    strict: bool,
    max_url_length: int,
) -> TargetParse:
    target_bytes = path_bytes[1:] if path_bytes.startswith(b"/") else path_bytes
    decoded_target = unquote_to_bytes(target_bytes).decode("utf-8", "replace")
    parts.target = decoded_target[:MAX_LOGGED_TARGET]
    parts.raw_target = decoded_target[:MAX_RAW_TARGET]
    first, _, rest = decoded_target.partition("/")
    parts.host = first.lower()[:MAX_HOST_LENGTH]
    parts.path = "/" + rest[:MAX_LOGGED_TARGET]

    url_length = len(path_bytes) + (1 + len(query_bytes) if query_bytes else 0)
    if url_length > max_url_length:
        return parts.result(ReasonCode.UNSAFE_URL, f"URL longer than {max_url_length} characters")
    if UNSAFE_CHARACTERS.intersection(decoded_target):
        return parts.result(ReasonCode.UNSAFE_URL, "unsafe characters")

    raw_segments = target_bytes.split(b"/")
    hosts = DEFAULT_ALLOWED_HOSTS if allowed_hosts is None else allowed_hosts
    host, problem, detail = check_host(raw_segments[0], hosts, strict)
    parts.host = host
    if problem is not None:
        return parts.result(problem, detail)
    if len(raw_segments) < 2:
        return parts.result(ReasonCode.NOT_ROBLOX, "no path after the host")

    path, path_problem = normalize_path(raw_segments[1:])
    if path_problem is not None:
        return parts.result(ReasonCode.UNSAFE_URL, path_problem)
    parts.path = path
    parts.target = host + path

    query, pretty, query_problem = parse_query(query_bytes.decode("utf-8", "replace"))
    if query_problem is not None:
        return parts.result(ReasonCode.UNSAFE_URL, query_problem)
    parts.query = query
    parts.prettyprint = pretty
    return parts.result()


def parse_upstream_url(
    url: str,
    method: str = "GET",
    *,
    allowed_hosts: Collection[str] | None = None,
    strict_host_allowlist: bool = True,
    max_url_length: int = DEFAULT_MAX_URL_LENGTH,
) -> TargetParse:
    """Check an absolute URL Roxy is about to call (a redirect target, a probe URL) with the same rules.

    Plan 9.10: the scheme must be https, the port absent or 443, no user name or password, then exactly the host,
    path and query checks of `parse_target`. A URL that fails any of them is never fetched.
    """
    parts = _Parts(method=(method or "GET").upper(), raw_query="", target=url[:MAX_LOGGED_TARGET])
    if _has_control(url) or " " in url:
        # urlsplit silently deletes TAB, CR and LF, which could join a split host back into an allowed one.
        return parts.result(ReasonCode.UNSAFE_URL, "control character or space in the URL")
    try:
        split = urlsplit(url)
        port = split.port  # raises ValueError for a port that is not a number in range
    except ValueError:
        return parts.result(ReasonCode.UNSAFE_URL, "unparsable URL")
    if split.scheme.lower() != "https":
        return parts.result(ReasonCode.NOT_ROBLOX, "scheme is not https")
    if "@" in split.netloc:
        return parts.result(ReasonCode.NOT_ROBLOX, "user name or password in the URL")
    if port is not None and port != 443:
        return parts.result(ReasonCode.NOT_ROBLOX, "port is not 443")
    host = split.netloc.rsplit(":", 1)[0] if port is not None else split.netloc
    if host.startswith("["):
        return parts.result(ReasonCode.NOT_ROBLOX, "IP literal host")
    raw_path = "/" + host + (split.path or "/")
    return parse_target(
        raw_path.encode("utf-8", "surrogateescape"),
        split.query.encode("utf-8", "surrogateescape"),
        method,
        allowed_hosts=allowed_hosts,
        strict_host_allowlist=strict_host_allowlist,
        max_url_length=max_url_length,
    )


def parse_redirect(
    current_url: str,
    location: str,
    method: str = "GET",
    *,
    allowed_hosts: Collection[str] | None = None,
    strict_host_allowlist: bool = True,
    max_url_length: int = DEFAULT_MAX_URL_LENGTH,
) -> TargetParse:
    """Re-validate a redirect (plan 7.9 and 9.10): resolve `location` against the current URL, then check it.

    A relative `Location` stays on the current host; `//evil.example/x` resolves to another host and is refused.
    Like every function here it never raises: `urljoin` raises `ValueError` for a Location that does not even parse
    (`//[`, an unclosed IPv6 bracket), and that is the `unsafe_url` problem "unparsable URL". The upstream layer
    follows every 3xx hop through this function, with the live `max_url_length` (review findings cred-3 and the
    ingress review's unguarded `urljoin`).
    """
    try:
        joined = urljoin(current_url, location.strip())
    except ValueError:
        parts = _Parts(method=(method or "GET").upper(), raw_query="", target=location.strip()[:MAX_LOGGED_TARGET])
        return parts.result(ReasonCode.UNSAFE_URL, "unparsable URL")
    return parse_upstream_url(
        joined,
        method,
        allowed_hosts=allowed_hosts,
        strict_host_allowlist=strict_host_allowlist,
        max_url_length=max_url_length,
    )
