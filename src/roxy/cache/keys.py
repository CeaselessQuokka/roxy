"""Cache keys: the readable key text, the 24 hex character entry id, and the rules that shape both.

What this is
    `build_key(method, host, path, query, body, rule, ...)` turns one proxied request into a `CacheKey`: the
    readable key text (`GET games.roblox.com/v1/games/votes?universeIds=1`), the entry id (the first 24 hex
    characters of the text's SHA-256, the v1 format), the auth class, and what the cache needs later (the
    parameters a refresh resends, the ignored names that were dropped). It also holds the vary list: the caller
    headers Roxy forwards upstream, every one of which must be part of the key (plan 9.13).

Why it exists
    The key decides which callers share an answer. Two requests may share a key only when Roblox would answer
    them the same way, so the key must be a one-to-one function of everything that reaches Roblox. v1 joined the
    decoded names and values with `&` and `=`, so `?universeIds=1%26universeIds%3D2` (one odd value) and
    `?universeIds=1&universeIds=2` (two values) shared a key while sending different URLs upstream: a caller
    could make Roblox's answer to the odd request be served for the normal one (cache poisoning, v1 bug B12).

How it works
    - The v1 layout is kept: `METHOD host/path?name=value&...`. The method is uppercased (HEAD becomes GET,
      because HEAD runs as GET), the host is lowercased, the path keeps its case (Roblox paths are case
      sensitive). Exactly one leading slash of the path is dropped.
    - Names and values are percent-encoded (LEAD_NOTES decision 9): unreserved characters (letters, digits and
      `-._~`) stay, everything else becomes `%XX`, so an `&`, `=`, `%` or space inside a value can never look
      like structure. Plain values (digits, letters) keep their v1 ids. The path is encoded the same way except
      that `/` and the other characters that are legal in a URL path stay; `?`, `#`, `%` and spaces are encoded.
    - Parameters are sorted by name with a stable sort, so repeated values keep their arrival order
      (`ids=1&ids=2` differs from `ids=2&ids=1`). Names in the ignored set (exact, case sensitive, v1) are left
      out of the key and of the resend list, and remembered in `stripped` so a later change to the ignored set
      can purge exactly the entries it affects (parity row 54).
    - A cache rule can add normalization flags: `sort_csv:<param>` sorts a comma separated id list (only for
      endpoints whose answer does not depend on the order, plan 15.5) and `casefold_path` lowercases the path.
    - A request body adds ` #` and the body's full SHA-256. v1 kept only 12 hex characters (48 bits): an attacker
      can grind a second body with the same 12 characters in hours of GPU time and poison another caller's batch
      lookup, so v2 keeps all 64 (only POST keys change; recorded as a deviation).
    - Forwarded caller headers (`VARY_HEADERS`) are appended as ` ^name=value`, and a credential request as
      ` @cred`, so a credential answer can never share an id with an anonymous one (plan 6.9).
    - Every separator begins with a space and no encoded part contains a space, so the text parses back
      unambiguously: that is the property that makes the key one-to-one.

What to read next
    `roxy/cache/policy.py` (which requests get a key, and how long answers live), then `roxy/cache/service.py`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import quote

from roxy.core.reasons import AuthClass

VARY_HEADERS: Final[tuple[str, ...]] = ("accept", "content-type", "content-length")
"""Every caller header that may reach Roblox (plan 9.13), lowercase. The key includes each one a request carries.

It must equal `roxy/proxy/scrub.py: FORWARDED_REQUEST_HEADERS`; `assert_forward_list` checks that, and the cache
service runs the check when it starts. Content-Length is derived from the body (already hashed into the key), so
including it changes nothing about which requests share an entry; it is listed so the two lists stay identical.
"""

KEY_ID_LENGTH: Final = 24
"""Hex characters of SHA-256 kept as the entry id (v1 format, 96 bits)."""

MARKER_SUFFIX: Final = " !429"
"""Appended to a key's text to name its per-key Roblox 429 marker (plan 7.7), a separate row from the entry."""

CRED_SUFFIX: Final = " @cred"
"""Appended to the key text of a request that uses the credential path (plan 6.9)."""

SORT_CSV_FLAG: Final = "sort_csv:"
CASEFOLD_PATH_FLAG: Final = "casefold_path"

_PATH_SAFE: Final = "/!$&'()*+,;=:@"
"""Characters kept as they are in the key's path: `/` plus the RFC 3986 path characters that are never key
structure. `?` and `#` are deliberately absent (encoded), so the first `?` in a key always starts the query."""


class VaryMismatchError(AssertionError):
    """A header is forwarded upstream but is not part of the cache key (or the other way round).

    Raised explicitly (never with `assert`), so it also fires under `python -O`. Subclassing AssertionError
    says what it is: a broken invariant in the code, not a bad request.
    """


class NormalizingRule(Protocol):
    """What `build_key` needs from a cache rule (`rules/models.py: CacheRuleRow` fits)."""

    @property
    def id(self) -> int: ...

    @property
    def normalize_flags(self) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class CacheKey:
    """One request's cache identity (DESIGN 7 `CacheKey(text, id, auth_class)` plus what the cache needs later)."""

    text: str
    """The readable key, shown in the cache browser."""
    id: str
    """`sha256(text)[:24]`, the `entries.id` primary key."""
    auth_class: AuthClass
    method: str
    """Uppercase; HEAD is GET."""
    host: str
    """Lowercase."""
    path: str
    """The path as requested (without the leading slash), before any normalization flag."""
    params: tuple[tuple[str, str], ...]
    """Kept (not ignored) parameters in caller order: what a refresh resends."""
    stripped: tuple[str, ...]
    """Ignored parameter names that this request carried (dropped from the key)."""
    body_hash: str | None
    vary: tuple[tuple[str, str], ...]
    rule_id: int | None

    @property
    def target(self) -> str:
        """`host/path`, the form rules are matched against."""
        return f"{self.host}/{self.path}" if self.path else self.host

    @property
    def flight_key(self) -> str:
        """The single-flight key: entry id plus auth class (plan 6.9)."""
        return f"{self.id}:{self.auth_class.value}"

    @property
    def marker_id(self) -> str:
        """The id of this key's Roblox 429 marker row."""
        return key_id(self.text + MARKER_SUFFIX)


def key_id(text: str) -> str:
    """The entry id of a key text: the first 24 hex characters of its SHA-256 (v1 `key_id`)."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:KEY_ID_LENGTH]


def encode_component(value: str) -> str:
    """Percent-encode a query name or value: keep unreserved characters, encode everything else (UTF-8 bytes).

    `quote(..., safe="")` always keeps letters, digits and `-._~` (RFC 3986 unreserved) and encodes the rest,
    including `%` itself, so two different strings never encode to the same text.
    """
    return quote(value, safe="")


def encode_path(path: str) -> str:
    """Percent-encode a path for the key: `/` and path-legal characters stay; `?`, `#`, `%` and spaces do not."""
    return quote(path, safe=_PATH_SAFE)


def canonical_method(method: str | None) -> str:
    """Uppercase method, GET when empty; HEAD runs as GET, so it shares GET's entries."""
    verb = (method or "GET").upper()
    return "GET" if verb == "HEAD" else verb


def _csv_order(part: str) -> tuple[int, int, str]:
    """Sort key for one id in a comma separated list: numbers in numeric order first, then text.

    Numeric order without `int()`: Python refuses to convert digit strings longer than 4300 characters, and a
    caller controls this value. Comparing (length without leading zeros, text) orders plain numbers correctly.
    """
    if part.isascii() and part.isdigit():
        trimmed = part.lstrip("0")
        return (0, len(trimmed), trimmed)
    return (1, 0, part)


def sort_csv(value: str) -> str:
    """Sort the items of a comma separated id list (`3,1,2` -> `1,2,3`); duplicates are kept."""
    if "," not in value:
        return value
    return ",".join(sorted(value.split(","), key=_csv_order))


def normalize_vary(vary: Mapping[str, str | None] | Iterable[tuple[str, str]] | None) -> tuple[tuple[str, str], ...]:
    """Forwarded header values as sorted `(lowercase name, value)` pairs; refuses a name outside `VARY_HEADERS`."""
    if not vary:
        return ()
    items = vary.items() if isinstance(vary, Mapping) else vary
    pairs: dict[str, str] = {}
    for raw_name, value in items:
        name = str(raw_name).lower()
        if name not in VARY_HEADERS:
            raise VaryMismatchError(
                f"header {name!r} is forwarded upstream but is not in the cache key's vary list (plan 9.13)"
            )
        if value is None:
            continue
        pairs.setdefault(name, str(value))
    return tuple(sorted(pairs.items()))


def assert_forward_list(forwarded: Iterable[str]) -> None:
    """Raise `VaryMismatchError` unless the forwarded caller headers are exactly the key's vary list (plan 9.13)."""
    names = {name.lower() for name in forwarded}
    if names != set(VARY_HEADERS):
        missing = sorted(names - set(VARY_HEADERS))
        extra = sorted(set(VARY_HEADERS) - names)
        raise VaryMismatchError(
            f"forwarded headers and the cache key's vary list differ: forwarded but not in the key {missing}, "
            f"in the key but not forwarded {extra}"
        )


def canonical_query(
    query: Iterable[tuple[str, str]],
    ignored: frozenset[str] | set[str],
    sort_params: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, tuple[tuple[str, str], ...], tuple[str, ...]]:
    """The key's query text plus the kept pairs (caller order) and the stripped (ignored) names.

    v1 `canonical_query`: names sorted with Python's plain string order (case sensitive code points, so `B`
    sorts before `_` and `a`), repeated values in arrival order; then each part is percent-encoded.
    """
    kept: list[tuple[str, str]] = []
    stripped: list[str] = []
    for name, value in query:
        if name in ignored:
            if name not in stripped:
                stripped.append(name)
            continue
        kept.append((name, value))
    parts: list[str] = []
    for name, value in sorted(kept, key=lambda pair: pair[0]):  # sorted() is stable: repeated values keep order
        text = sort_csv(value) if name in sort_params else value
        parts.append(f"{encode_component(name)}={encode_component(text)}")
    return "&".join(parts), tuple(kept), tuple(stripped)


def build_key(
    method: str,
    host: str,
    path: str,
    query: Iterable[tuple[str, str]],
    body: bytes | None,
    rule: NormalizingRule | None = None,
    *,
    ignored: frozenset[str] | set[str] = frozenset(),
    auth_class: AuthClass = AuthClass.ANON,
    vary: Mapping[str, str | None] | Iterable[tuple[str, str]] | None = None,
) -> CacheKey:
    """The cache key of one request (module docstring has the layout).

    `path` is the decoded path as it will be requested (with or without its leading slash); `query` is the
    caller's `(name, value)` pairs in caller order with `prettyprint` already removed; `body` is hashed only for
    methods other than GET; `vary` holds the caller header values Roxy forwards (`scrub.cache_vary_items`).
    """
    verb = canonical_method(method)
    host_text = (host or "").lower()
    raw_path = path[1:] if path.startswith("/") else path  # exactly one slash: `//x` and `/x` stay distinct
    flags: tuple[str, ...] = tuple(rule.normalize_flags) if rule is not None else ()
    sort_params = frozenset(flag[len(SORT_CSV_FLAG) :] for flag in flags if flag.startswith(SORT_CSV_FLAG))
    key_path = raw_path.lower() if CASEFOLD_PATH_FLAG in flags else raw_path
    text = f"{verb} {host_text}/{encode_path(key_path)}" if key_path else f"{verb} {host_text}"
    query_text, kept, stripped = canonical_query(query, ignored, sort_params)
    if query_text:
        text += "?" + query_text
    body_hash: str | None = None
    if body and verb != "GET":
        body_hash = hashlib.sha256(body).hexdigest()
        text += " #" + body_hash
    vary_pairs = normalize_vary(vary)
    for name, value in vary_pairs:
        text += f" ^{name}={encode_component(value)}"
    if auth_class == AuthClass.CRED:
        text += CRED_SUFFIX
    return CacheKey(
        text=text,
        id=key_id(text),
        auth_class=AuthClass(auth_class),
        method=verb,
        host=host_text,
        path=raw_path,
        params=kept,
        stripped=stripped,
        body_hash=body_hash,
        vary=vary_pairs,
        rule_id=rule.id if rule is not None else None,
    )


def split_target(dst: str) -> tuple[str, str]:
    """Split a v1 style target `Host.roblox.com/path` into `(host, path)` (used for v1 worked examples)."""
    host, _, rest = (dst or "").partition("/")
    return host, rest


def pairs_from_mapping(params: Mapping[str, Sequence[str] | str]) -> list[tuple[str, str]]:
    """v1 style `{name: [values]}` (or `{name: value}`) as `(name, value)` pairs in mapping order."""
    pairs: list[tuple[str, str]] = []
    for name, values in params.items():
        if isinstance(values, str):
            pairs.append((name, values))
        else:
            pairs.extend((name, str(value)) for value in values)
    return pairs


__all__ = [
    "CASEFOLD_PATH_FLAG",
    "CRED_SUFFIX",
    "KEY_ID_LENGTH",
    "MARKER_SUFFIX",
    "SORT_CSV_FLAG",
    "VARY_HEADERS",
    "CacheKey",
    "NormalizingRule",
    "VaryMismatchError",
    "assert_forward_list",
    "build_key",
    "canonical_method",
    "canonical_query",
    "encode_component",
    "encode_path",
    "key_id",
    "normalize_vary",
    "pairs_from_mapping",
    "sort_csv",
    "split_target",
]
