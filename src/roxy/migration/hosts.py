"""The `allowed_roblox_hosts` union: the shipped list plus every roblox.com host seen in the v1 statistics.

What this is
    `collect_hosts(diagnostics)` finds every host in the v1 endpoint records, cache records, request failures and
    internal calls, with the evidence for each (where it was seen, how many requests, whether any answer
    succeeded). `plan_hosts(current, evidence)` returns the new list and what was added or left out.

Why it exists
    Plan 9.10 and 18.3. v2 forwards only to hosts on `allowed_roblox_hosts` (the SSRF control), while v1 accepted
    any `<letters>.roblox.com`. If a game used a host that is not on the shipped list, it would get 404 "Not a
    Roblox URL" after cutover. So the migrator adds every roblox.com host seen in v1 data and reports each
    addition with its evidence, so the owner can remove one that only a scanner ever asked for.

How it works
    Hosts are taken from the part before the first `/` of each recorded endpoint (v1 stored `host/path` without
    the scheme; a scheme is stripped when present), lowercased, one trailing dot removed, and accepted only when
    the whole name matches `<label>.roblox.com` (ASCII letters, digits and hyphens). Additions go after the
    current list, busiest first, up to the setting's 200 item limit; the rest are reported as not added.

What to read next
    `roxy/config/settings/routing.py` (the setting and its default list) and REMAKE_PLAN.md section 9.10.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.config import catalog

HOST_KEY: Final = "allowed_roblox_hosts"
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+roblox\.com")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


@dataclass(slots=True)
class HostEvidence:
    """Why a host is believed to be in use: where it was seen, how often, and whether it ever answered."""

    host: str
    seen_in: set[str] = field(default_factory=set)
    requests: int = 0
    successful: bool = False

    def as_report(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "seen_in": sorted(self.seen_in),
            "requests": self.requests,
            "successful": self.successful,
        }


def host_of(endpoint: Any) -> str | None:
    """The roblox.com host of a v1 endpoint string (`games.roblox.com/v1/...`), or None when it has none."""
    if not isinstance(endpoint, str):
        return None
    text = _SCHEME.sub("", endpoint.strip()).lstrip("/")
    host = text.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].lower()
    if host.endswith("."):
        host = host[:-1]
    if not host.isascii() or not _HOST.fullmatch(host):
        return None
    return host


def _count(record: Any, *names: str) -> int:
    if not isinstance(record, Mapping):
        return 0
    total = 0
    for name in names:
        value = record.get(name)
        if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
            total += int(value)
    return total


def collect_hosts(diagnostics: Mapping[str, Any]) -> dict[str, HostEvidence]:
    """Every roblox.com host found in the v1 statistics (endpoint records, failures, internal calls)."""
    found: dict[str, HostEvidence] = {}

    def note(endpoint: Any, source: str, requests: int, successful: bool) -> None:
        host = host_of(endpoint)
        if host is None:
            return
        evidence = found.setdefault(host, HostEvidence(host))
        evidence.seen_in.add(source)
        evidence.requests += max(0, requests)
        evidence.successful = evidence.successful or successful

    endpoints = diagnostics.get("endpoints")
    if isinstance(endpoints, Mapping):
        for template, record in endpoints.items():
            outcome = record.get("LastOutcome") if isinstance(record, Mapping) else None
            status = str(record.get("LastStatus", "")) if isinstance(record, Mapping) else ""
            note(template, "endpoints", _count(record, "Count"), outcome == "served" or status.startswith("2"))
    cache_endpoints = diagnostics.get("cache_endpoints")
    if isinstance(cache_endpoints, Mapping):
        for template, record in cache_endpoints.items():
            note(template, "cache", _count(record, "Count"), _count(record, "Hits", "Stores") > 0)
    failures = diagnostics.get("request_failures")
    if isinstance(failures, Mapping):
        for record in failures.values():
            if isinstance(record, Mapping):
                note(record.get("LastEndpoint"), "request_failures", _count(record, "Count"), False)
    internal = diagnostics.get("internal_requests")
    if isinstance(internal, Mapping):
        for record in internal.values():
            if isinstance(record, Mapping):
                ok = _count(record, "Count") > _count(record, "Failed")
                note(record.get("LastEndpoint"), "internal_requests", _count(record, "Count"), ok)
    return found


@dataclass(slots=True)
class HostPlan:
    """The new list (None when nothing changes), the additions and the hosts left out by the size limit."""

    new_list: list[str] | None
    added: list[HostEvidence]
    not_added: list[str]
    seen: int


def plan_hosts(current: Sequence[str], evidence: Mapping[str, HostEvidence]) -> HostPlan:
    """Union `current` (the effective setting value) with the hosts in `evidence`, busiest first."""
    spec = catalog.CATALOG[HOST_KEY]
    limit = int(spec.max_length or catalog.DEFAULT_LIST_MAX_ITEMS)
    present = [str(host).lower().removesuffix(".") for host in current]
    known = set(present)
    candidates = sorted(
        (item for host, item in evidence.items() if host not in known),
        key=lambda item: (not item.successful, -item.requests, item.host),
    )
    room = max(0, limit - len(present))
    added = candidates[:room]
    not_added = [item.host for item in candidates[room:]]
    new_list = present + [item.host for item in added] if added else None
    return HostPlan(new_list, added, not_added, len(evidence))


def default_hosts() -> list[str]:
    """The shipped list (plan 9.10), as full host names."""
    return [str(host) for host in catalog.DEFAULTS[HOST_KEY]]


def as_list(value: Any) -> list[str]:
    """A stored setting value as a list of host names (the shipped list when it is not a list)."""
    if isinstance(value, list | tuple):
        return [str(item) for item in value]
    return default_hosts()


__all__ = ["HOST_KEY", "HostEvidence", "HostPlan", "as_list", "collect_hosts", "default_hosts", "host_of", "plan_hosts"]
