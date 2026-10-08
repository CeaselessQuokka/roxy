"""Real client IP behind nginx: the only code in Roxy that reads `X-Forwarded-For`.

What this is
    `resolve_client_ip(peer, xff, trusted_cidrs, hops)` returns the caller's IP address, and
    `limit_key(ip, ipv6_prefix)` returns the key per-IP limits count against (IPv6 grouped by prefix).

Why it exists
    nginx connects to the app from 127.0.0.1, so the socket peer is always nginx. The caller's address is in the
    `X-Forwarded-For` header, but that header is a list anyone can start: nginx APPENDS the address it saw
    (`$proxy_add_x_forwarded_for`), so `X-Forwarded-For: 1.2.3.4` sent by an attacker arrives as
    `1.2.3.4, <real attacker IP>`. Taking the leftmost entry (v1 once did, via `access_route[0]`) lets anyone pick
    their own IP and dodge every per-IP limit. Plan 9.11: trust the header only when the peer is a trusted proxy,
    and walk it from the RIGHT, one trusted hop at a time.

How it works
    1. Normalize the peer address. If it is not inside `ROXY_TRUSTED_PROXY_CIDRS`, the header is ignored and the
       peer is the client (a direct connection cannot vouch for anything).
    2. Otherwise take entries from the right end of the header, up to `ROXY_TRUSTED_PROXY_HOPS` of them. Each
       entry is the address the previous trusted hop saw. Stop early when an entry is NOT itself a trusted proxy:
       that entry is the client, and anything left of it was written by the client.
       With one hop (nginx only) this is exactly v1's ProxyFix(x_for=1): the rightmost entry. With two hops (a
       CDN in front of nginx) it returns the entry the CDN appended, but only if the rightmost entry really is a
       CDN address listed in the trusted ranges; a request that bypassed the CDN cannot spoof its way in.
    3. Addresses are normalized: IPv4-mapped IPv6 (`::ffff:1.2.3.4`) becomes `1.2.3.4`, IPv6 is compressed, zone
       ids and ports are dropped. Unparsable entries stop the walk (the last good address is returned).
    The middleware (`core/middleware.py`) calls this once per request and stores the result for everyone else.

What to read next
    `roxy/core/middleware.py` (`ClientIPMiddleware`), then `roxy/abuse/throttle.py` (the main user of `limit_key`).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

UNKNOWN_IP = "unknown"
"""Returned when no address is available (for example a request on the internal Unix socket)."""

_MAX_XFF_ENTRIES = 64  # a longer header is garbage or an attack; only the right end matters anyway


def parse_ip(text: str | None) -> IPAddress | None:
    """Parse one address as written in a header or socket tuple, or None when it is not an IP address.

    Accepts `1.2.3.4`, `1.2.3.4:5678`, `::1`, `[::1]`, `[::1]:443`, `fe80::1%eth0`, and IPv4-mapped IPv6.
    """
    if not text:
        return None
    value = text.strip().strip('"')
    if not value:
        return None
    if value.startswith("["):  # "[v6]" or "[v6]:port"
        end = value.find("]")
        if end == -1:
            return None
        value = value[1:end]
    elif value.count(":") == 1:  # "v4:port"; a bare IPv6 address has at least two colons
        value = value.split(":", 1)[0]
    value = value.split("%", 1)[0]  # drop an IPv6 zone id
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def normalize_ip(text: str | None) -> str | None:
    """Canonical text form of an address (`::FFFF:1.2.3.4` -> `1.2.3.4`), or None when it is not one."""
    address = parse_ip(text)
    return None if address is None else str(address)


def parse_cidrs(text: str | Iterable[str]) -> tuple[IPNetwork, ...]:
    """Parse `127.0.0.1/32,::1/128` (or a list of entries) into networks. Raises ValueError on a bad entry.

    Host bits are allowed (`10.0.0.1/8` means `10.0.0.0/8`), and a bare address means a single host.
    """
    items = text.split(",") if isinstance(text, str) else list(text)
    networks: list[IPNetwork] = []
    for item in items:
        entry = item.strip()
        if entry:
            networks.append(ipaddress.ip_network(entry, strict=False))
    return tuple(networks)


def is_trusted(address: IPAddress, trusted_cidrs: Sequence[IPNetwork]) -> bool:
    """True when `address` is inside one of the trusted proxy networks."""
    return any(address.version == net.version and address in net for net in trusted_cidrs)


def resolve_client_ip(
    peer: str | None,
    xff: str | None,
    trusted_cidrs: Sequence[IPNetwork],
    hops: int,
) -> str:
    """Return the caller's IP: the rightmost trusted hop of `X-Forwarded-For`, or the peer (plan 9.11).

    `peer` is the socket peer address, `xff` the raw `X-Forwarded-For` value (several header lines joined with
    commas, in order), `trusted_cidrs` the proxies whose header is believed, `hops` how many of them sit in front.
    """
    peer_address = parse_ip(peer)
    if peer_address is None:
        return UNKNOWN_IP if not peer else peer.strip() or UNKNOWN_IP
    current = peer_address
    if hops <= 0 or not xff or not is_trusted(peer_address, trusted_cidrs):
        return str(current)
    entries = xff.split(",")[-_MAX_XFF_ENTRIES:]
    for _ in range(hops):
        if not entries:
            break
        candidate = parse_ip(entries.pop())
        if candidate is None:
            break  # garbage where an address should be: keep the last address a trusted hop vouched for
        current = candidate
        if not is_trusted(candidate, trusted_cidrs):
            break  # an untrusted address is the client; anything further left was written by the client
    return str(current)


def limit_key(ip: str, ipv6_prefix: int = 64) -> str:
    """The key per-IP limits count against: the IPv4 address itself, or the IPv6 network of `ipv6_prefix` bits.

    One IPv6 customer usually gets a whole /64 (2^64 addresses), so limiting single IPv6 addresses would let one
    caller rotate through billions of "different" clients. `ipv6_limit_prefix` (default 64) groups them; 128 turns
    grouping off. Anything that is not an IP address is returned unchanged.
    """
    address = parse_ip(ip)
    if address is None:
        return ip
    if isinstance(address, ipaddress.IPv4Address):
        return str(address)
    prefix = min(max(int(ipv6_prefix), 0), 128)
    if prefix == 128:
        return str(address)
    network = ipaddress.IPv6Network((address, prefix), strict=False)
    return str(network)
