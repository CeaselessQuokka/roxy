"""Identifiers: request ids and record ids that sort by time.

What this is
    `new_request_id()` returns a 26 character ULID (Universally Unique Lexicographically Sortable Identifier),
    and `new_id(prefix)` returns the same with a short type prefix, for example `rec_01JABCXYZ...` for a
    recommendation.

Why it exists
    Every request gets a `Roxy-Request-Id` header, and every event, capture and trace refers to it. A ULID is
    random enough to be unguessable in practice and starts with the timestamp, so sorting ids sorts by time,
    which makes logs and tables easy to read without an extra column.

How it works
    48 bits of milliseconds since the epoch followed by 80 random bits from the operating system's secure random
    source (`secrets`), encoded in Crockford base32 (no I, L, O or U, so ids are easy to read aloud and copy).

What to read next
    `roxy/core/clock.py` for where the time comes from.
"""

from __future__ import annotations

import secrets

from roxy.core.clock import SYSTEM_CLOCK, Clock

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode(value: int, length: int) -> str:
    """Encode a non-negative integer as `length` Crockford base32 characters (most significant first)."""
    chars = []
    for _ in range(length):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_request_id(clock: Clock | None = None) -> str:
    """Return a new 26 character ULID: 10 characters of time, 16 of randomness."""
    ms = (clock or SYSTEM_CLOCK).now_ms() & ((1 << 48) - 1)
    rand = secrets.randbits(80)
    return _encode(ms, 10) + _encode(rand, 16)


def new_id(prefix: str, clock: Clock | None = None) -> str:
    """Return `<prefix>_<ulid>`, for example `rec_01J9Z3...`. The prefix names the record type."""
    return f"{prefix}_{new_request_id(clock)}"
