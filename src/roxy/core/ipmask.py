"""Client addresses in free text: find every IPv4 and IPv6 address and replace it with `ip:<keyed hash>`.

What this is
    `mask_ip_text(text, hasher, *, keep_versions=False)`: `text` with every address replaced by `ip:` plus
    `hasher(address)` (an `ip:` already in front stays one), and `is_user_agent_field(name)`. The one masker of
    every file built to leave the server: the admin API's table downloads (`admin/api/common.py mask_ip_text`,
    `mask_ip_value`) and the LLM export (`insights/llm_export.py mask_ips`).

Why it exists
    Plan 9.15 and 12.3: while `export_include_ips` is off, an export holds no client address, not in an IP column
    and not in free text either (spam subjects, ban previews, event details, recommendation subjects). Roxy writes
    an IPv6 client as its /64 limit key after a word and a colon (`ip:2001:db8:1:2::/64`, `bypass:<network>`), so a
    masker that refuses to start right after a colon, or that strips the trailing `::` of a network, leaves exactly
    those raw (review round 4, findings secfix-2 and secfix-3). Two copies of the rules had drifted apart; this
    module is the only copy now.

How it works
    1. IPv6 first: every maximal run of hex digits, colons and dots with at least two colons is a candidate. The run
       is tried as it is, then without one leading `word:` (the `ip:`, `ban:` or `bypass:` in front of a client;
       a run glued to a word, such as the `:2001:...` of `ip:2001:...` or the `e::f` of `Type::fmt`, is only tried
       after its first colon), each also without one trailing `.` or `:` (the end of a sentence; never the `::`
       that ends a network), and the first form `ipaddress` accepts is replaced (`::` alone is a separator, never
       a client). A `/64` after a network stays as text, as `/24` does after an IPv4 network (the address part is
       what identifies the client). Times (`12:30:45`), MAC addresses and `a::b::c` never parse, so they stay.
    2. IPv4 next: a dotted quad that is not part of a longer dotted number (`v1.2.3.4.5`) and parses. A version
       after a product name (`Chrome/120.0.0.0`) is kept only with `keep_versions` (User-Agent fields, see
       `is_user_agent_field`); anywhere else `<letter>/<quad>` is a path such as `/lookup/198.51.100.7` and is
       masked (privacy first).
    The hash is of the address's normal form, so it equals the hash an IP column gets for the same client. Text
    without a dot or a colon returns at once.

What to read next
    `roxy/core/iphash.py` (the keyed hash), `roxy/admin/api/common.py` (`ExportBuilder`, `export_ip_policy`),
    `roxy/insights/llm_export.py` (`UntrustedPool`).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Final

IpHasher = Callable[[str], str]

IP_TEXT_PREFIX: Final = "ip:"
"""How an address in free text is replaced: `ip:<keyed hash>` (the LLM export's form, DESIGN 14.5)."""

MAX_ADDRESS_CHARS: Final = 45
"""The longest textual IPv6 address (eight groups with an embedded IPv4 tail); longer candidates are not parsed."""

_RUN_RE: Final = re.compile(r"[0-9A-Fa-f.:]{2,}")
"""A maximal run of the characters an address is written with (IPv6 candidates need two colons in it)."""
_IPV4_RE: Final = re.compile(r"(?<![0-9])(?<![0-9]\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])(?!\.[0-9])")
"""A dotted quad, not part of a longer dotted number (`1.2.3.4.5`)."""
_VERSION_BEFORE_RE: Final = re.compile(r"[A-Za-z]/\Z")
"""What stands right before a product version (`Chrome/`), kept only in User-Agent fields."""


def is_user_agent_field(name: str) -> bool:
    """Whether a column or object key holds User-Agent text (`user_agent`, `top_user_agents`, `ua`): the one place a
    `Chrome/120.0.0.0` is a version, never an address."""
    lowered = name.lower()
    return "user_agent" in lowered or lowered in ("ua", "user-agent", "useragent")


def _v6_span(run: str, *, glued: bool) -> tuple[int, int] | None:
    """`(start, end)` of the IPv6 address inside `run` (see the module docstring, step 1), or None.

    `glued`: the run follows a letter, digit or underscore. The run's first characters then continue that word up
    to its first colon (`ip:`, `ban:`, and also `Type::fmt`, whose `e::f` would parse), so the address can only
    start after it."""
    starts = [] if glued else [0]
    first_colon = run.find(":")
    if 0 <= first_colon < len(run) - 1:
        starts.append(first_colon + 1)  # one leading `word:` (or the colon of `ip:` that joined the run)
    ends = [len(run)]
    if run[-1] == "." or (run[-1] == ":" and not run.endswith("::")):
        ends.append(len(run) - 1)  # the end of a sentence, never the `::` that ends a network
    for start in starts:
        for end in ends:
            candidate = run[start:end]
            if candidate.count(":") < 2 or len(candidate) > MAX_ADDRESS_CHARS:
                continue
            try:
                address = ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            if address.is_unspecified:
                continue  # `::` alone is a separator in text (`a :: b`), never a client
            return start, end
    return None


def mask_ip_text(text: str, hasher: IpHasher, *, keep_versions: bool = False) -> str:
    """`text` with every IPv4 and IPv6 address replaced by `ip:<hasher(normal form)>`; an `ip:` already in front of
    the address stays one. `keep_versions` keeps a dotted quad right after `<letter>/` (a User-Agent's product
    version); without it such a quad is masked like any other."""
    if "." not in text and ":" not in text:
        return text

    def replace(source: str, start: int, address: str) -> str:
        hashed = hasher(address)
        tagged = source[max(0, start - len(IP_TEXT_PREFIX)) : start] == IP_TEXT_PREFIX
        return hashed if tagged else IP_TEXT_PREFIX + hashed

    def v6(match: re.Match[str]) -> str:
        run = match.group(0)
        if run.count(":") < 2:
            return run
        before = match.string[match.start() - 1 : match.start()]
        span = _v6_span(run, glued=before.isalnum() or before == "_")
        if span is None:
            return run
        start, end = span
        address = str(ipaddress.IPv6Address(run[start:end]))
        return run[:start] + replace(match.string, match.start() + start, address) + run[end:]

    def v4(match: re.Match[str]) -> str:
        candidate = match.group(0)
        start = match.start()
        if keep_versions and _VERSION_BEFORE_RE.search(match.string[max(0, start - 2) : start]):
            return candidate  # `Chrome/120.0.0.0` in a User-Agent: a version, not an address
        try:
            address = str(ipaddress.IPv4Address(candidate))
        except ValueError:
            return candidate
        return replace(match.string, start, address)

    if text.count(":") >= 2:
        text = _RUN_RE.sub(v6, text)
    if "." in text:
        text = _IPV4_RE.sub(v4, text)
    return text


__all__ = ["IP_TEXT_PREFIX", "MAX_ADDRESS_CHARS", "IpHasher", "is_user_agent_field", "mask_ip_text"]
