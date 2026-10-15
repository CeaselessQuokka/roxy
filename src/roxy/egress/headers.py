"""Header profiles: the request headers Roxy presents to Roblox on each egress path (plan 7.11 and 9.13).

What this is
    `HeaderProfiles.api_headers(egress, identity)` returns the base headers for one upstream call: an API-shaped
    `Accept`, a fixed `Accept-Language`, and a `User-Agent` that is stable per egress identity. `ROTATOR_PROFILES`
    are complete, internally consistent browser identities, one of which a rotator session keeps for its whole
    life. `FORWARDED_CALLER_HEADERS` names the inbound allowlist (the only caller headers that may reach Roblox;
    `proxy/scrub.py forwarded_request_headers` applies it, the one implementation the cache key and the upstream
    call share since finding pipe-1), and `merge_outbound` combines the profile with the upstream layer's extra
    headers.

Why it exists
    v1 sent a Chrome page-navigation header set (`Sec-Fetch-Mode: navigate`, `Upgrade-Insecure-Requests`) to JSON
    APIs, and on the rotator swapped in a random User-Agent per request while keeping Chrome-only hints, which is
    an incoherent fingerprint (plan R9, v1 notes B23). Caller headers passed through a denylist, so localized
    `Accept-Language` values could mix into the shared cache. v2 sends what an API client sends, the same identity
    for the life of a session, and nothing from the caller except a short allowlist.

How it works
    Direct and credential calls use the `direct_user_agent` setting (decision D23). While the User-Agent
    experiment runs, direct calls are split between that and `ua_experiment_alt_user_agent` by a hash of the
    request's identity (its cache key id), so one key always gets the same arm. It runs `ua_experiment_days` from
    the newest stored change of `UA_EXPERIMENT_KEYS` (switching it on, or changing either User-Agent; plan 11.5
    "splits direct traffic ... for ua_experiment_days"), then every direct call goes back to `direct_user_agent`
    while the switch stays on (review finding brain-7). A rotator session picks one of
    `ROTATOR_PROFILES` by a hash of its session id: same session, same profile. Chromium profiles carry the three
    low-entropy client hints Chromium sends by default; Firefox and Safari send none, so their profiles have none.
    `Accept-Encoding` is left to httpx, which advertises only encodings it can decode (gzip, deflate, br).
    Any header ever added to `FORWARDED_CALLER_HEADERS` must be added to the cache key's vary list in the same
    change (`cache/keys.py` asserts the two are equal).

What to read next
    `roxy/egress/clients.py` (where these headers are applied), then `roxy/egress/rotator.py` (sessions).
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from roxy.core.reasons import Egress

API_ACCEPT = "application/json, text/plain, */*"
ACCEPT_LANGUAGE = "en-US,en;q=0.9"
"""Fixed by Roxy (plan 7.11, 9.13): caller values are never forwarded, so the shared cache holds one language."""

FORWARDED_CALLER_HEADERS: tuple[str, ...] = ("content-type", "accept")
"""The only caller headers that may reach Roblox (plan 9.13). The cache key's vary list must equal this."""

FORBIDDEN_OUTBOUND = frozenset(
    {
        "cookie",
        "cookie2",
        "authorization",
        "proxy-authorization",
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "content-length",
        "x-roblox-token",
    }
)
"""Never taken from `OutboundRequest.headers`: cookies come only from `egress/credential.py`, `Host` and lengths
from httpx, and hop-by-hop headers belong to one connection, not to the request."""

SITE_ORIGIN_PLACEHOLDER = "{site_origin}"

DAY_S = 86_400
UA_EXPERIMENT_KEYS: tuple[str, ...] = ("ua_experiment_enabled", "direct_user_agent", "ua_experiment_alt_user_agent")
"""A stored change of any of these starts a new run of the User-Agent experiment (the insights rule reads the same
keys, `insights/providers_rules_upstream.py`)."""


def experiment_started_at(settings: Any) -> float | None:
    """When the running User-Agent experiment started: the newest `updated_at` of `UA_EXPERIMENT_KEYS` among the
    stored overrides (`SettingsSnapshot.meta`), or None when `settings` carries no such record (a plain mapping).
    While the switch is on it is an override (its default is 0), so its own switch-on time is always there."""
    snapshot = getattr(settings, "snapshot", None)
    meta = getattr(snapshot() if callable(snapshot) else settings, "meta", None)
    if not isinstance(meta, Mapping):
        return None
    times = [float(meta[key][0]) for key in UA_EXPERIMENT_KEYS if key in meta]
    return max(times) if times else None


@dataclass(frozen=True, slots=True)
class BrowserProfile:
    """One coherent browser identity: a User-Agent plus exactly the extra headers that browser sends to an API."""

    name: str
    user_agent: str
    extra: tuple[tuple[str, str], ...] = ()


def _chromium_hints(brand: str, platform: str) -> tuple[tuple[str, str], ...]:
    return (
        ("sec-ch-ua", f'"{brand}";v="141", "Not?A_Brand";v="8", "Chromium";v="141"'),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", f'"{platform}"'),
    )


ROTATOR_PROFILES: tuple[BrowserProfile, ...] = (
    BrowserProfile(
        "chrome-windows",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 "
        "Safari/537.36",
        _chromium_hints("Google Chrome", "Windows"),
    ),
    BrowserProfile(
        "chrome-macos",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 "
        "Safari/537.36",
        _chromium_hints("Google Chrome", "macOS"),
    ),
    BrowserProfile(
        "edge-windows",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 "
        "Safari/537.36 Edg/141.0.0.0",
        _chromium_hints("Microsoft Edge", "Windows"),
    ),
    BrowserProfile(
        "firefox-windows",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
    ),
    BrowserProfile(
        "firefox-macos",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
    ),
    BrowserProfile(
        "safari-macos",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 "
        "Safari/605.1.15",
    ),
)


def _bucket(text: str, modulo: int) -> int:
    digest = hashlib.sha256(text.encode("utf-8", "replace")).digest()
    return int.from_bytes(digest[:4], "big") % modulo


def profile_for_session(session_id: str) -> BrowserProfile:
    """The profile a rotator session keeps for its lifetime (deterministic in the session id)."""
    return ROTATOR_PROFILES[_bucket(session_id, len(ROTATOR_PROFILES))]


class HeaderProfiles:
    """Builds base headers per egress identity from live settings (`ctx.egress.headers`)."""

    def __init__(self, settings: Any, site_origin: str, clock: Callable[[], float] = time.time) -> None:
        self._settings = settings
        self._site_origin = site_origin
        self._clock = clock

    def _setting(self, key: str, default: Any) -> Any:
        try:
            return self._settings.get(key)
        except (KeyError, LookupError, AttributeError):
            return default

    def ua_variant(self, egress: Egress, identity: str | None) -> str:
        """`primary` or `alt`: which arm of the User-Agent experiment a direct call with `identity` is in (the
        assignment alone; `experiment_running` says whether the split still applies to a call made now)."""
        if egress is not Egress.DIRECT or not identity or not self._setting("ua_experiment_enabled", 0):
            return "primary"
        return "alt" if _bucket(identity, 2) == 1 else "primary"

    def experiment_running(self) -> bool:
        """Whether direct calls are split right now: the switch is on and fewer than `ua_experiment_days` days
        passed since the run started (`experiment_started_at`). Without a start record the switch alone decides."""
        if not self._setting("ua_experiment_enabled", 0):
            return False
        started = experiment_started_at(self._settings)
        if started is None:
            return True
        days = float(self._setting("ua_experiment_days", 7))
        return self._clock() < started + days * DAY_S

    def user_agent(self, egress: Egress, identity: str | None = None) -> str:
        """The User-Agent for one call (see the module docstring for who gets which)."""
        if egress is Egress.ROTATOR:
            return profile_for_session(identity or "").user_agent
        if self.ua_variant(egress, identity) == "alt" and self.experiment_running():
            alt = str(self._setting("ua_experiment_alt_user_agent", ""))
            if alt:
                return alt.replace(SITE_ORIGIN_PLACEHOLDER, self._site_origin)
        return str(self._setting("direct_user_agent", "")).replace(SITE_ORIGIN_PLACEHOLDER, self._site_origin)

    def api_headers(self, egress: Egress, identity: str | None = None) -> dict[str, str]:
        """Base headers for one call. `identity` is the rotator session id, or the direct call's experiment key."""
        headers = {"Accept": API_ACCEPT, "Accept-Language": ACCEPT_LANGUAGE}
        user_agent = self.user_agent(egress, identity)
        if user_agent:
            headers["User-Agent"] = user_agent
        if egress is Egress.ROTATOR:
            headers.update(profile_for_session(identity or "").extra)
        return headers


def merge_outbound(base: Mapping[str, str], extra: Mapping[str, str]) -> dict[str, str]:
    """`base` overlaid with `extra`, case-insensitively, minus every `FORBIDDEN_OUTBOUND` header."""
    merged: dict[str, tuple[str, str]] = {}
    for source in (base, extra):
        for name, value in source.items():
            key = name.lower()
            if key in FORBIDDEN_OUTBOUND:
                continue
            merged[key] = (name, value)
    return dict(merged.values())


__all__ = [
    "ACCEPT_LANGUAGE",
    "API_ACCEPT",
    "DAY_S",
    "FORBIDDEN_OUTBOUND",
    "FORWARDED_CALLER_HEADERS",
    "ROTATOR_PROFILES",
    "UA_EXPERIMENT_KEYS",
    "BrowserProfile",
    "HeaderProfiles",
    "experiment_started_at",
    "merge_outbound",
    "profile_for_session",
]
