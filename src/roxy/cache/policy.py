"""Cache policy: which requests get a cache key, which answers are stored, and for how long.

What this is
    Pure functions and small frozen records, no I/O. `CacheSettings.read(settings)` takes one consistent copy of
    every cache setting (plan 15.3 D). `request_policy(...)` decides, before anything is looked up, whether a
    request is cacheable at all, under which rule, with which auth class and lifetimes. `store_decision(...)`
    decides, after an upstream answer, whether to store it as an entry, as a negative (error) entry, as a per-key
    429 marker, or not at all, and why.

Why it exists
    v1 spread these rules over `cache.py` and `index.py` and had two notable bugs: a matching cache rule decided
    the lifetime before the status was checked, so any non-200 answer (201, 401, 422...) under a rule was cached
    (v1 bug B3), and only HTTP 200 counted as success (B4). Keeping the whole policy in one pure module makes it
    testable row by row against plan 7.6, 7.7 and 15.3 D.

How it works
    - Methods (parity row 57): GET (and HEAD, which runs as GET) always; POST per `cache_post_requests`: `off`,
      `allowlist` (the built-in read-only batch lookups of `config/defaults.py` plus cache rules that list POST),
      or `all`; every other method never. A request that is not cacheable is `OFF`.
    - Rules (row 55): the most specific enabled rule that covers the method wins; rules shipped as defaults are
      skipped while `cache_default_rules_enabled` is 0. A rule's `ttl` replaces `cache_ttl_seconds` (0 means
      "never cache this endpoint"), `negative_ttl` replaces `cache_error_ttl_seconds`, and `stale_ttl` replaces
      the stale-while-revalidate window `cache_swr_seconds` (plan 7.6 "rule-overridable"; the shipped presence
      rule uses it for its 15 s SWR window).
    - The credential (plan 6.9, 9.13): a request whose endpoint is on the credential allowlist has auth class
      `cred`. When that allowlist row says `cache_private`, the request is never cached, coalesced, revalidated
      or served stale: it is `OFF`.
    - Stored (row 56, plan 7.7): any Roblox 2xx under a positive lifetime and within `cache_max_body` bytes;
      Roblox 400, 403 (only when it is not a CSRF challenge), 404 and 410 for the error lifetime; a Roblox 429 as a
      marker until the cooldown ends (when `cache_negative_429` is on), never as content; 5xx, timeouts and every
      Roxy-side failure never. The upstream layer's hints are honored: a 2xx with `cacheable=False` and a 4xx
      without `negative_ttl_s` are not stored. An answer fetched with the credential is never stored under an
      anonymous key (defense in depth for plan 6.9).

What to read next
    `roxy/cache/store.py` (where decisions are carried out), then `roxy/cache/service.py`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol

from roxy.cache.keys import canonical_method
from roxy.config.catalog import owner_deadline_s
from roxy.config.constants import CACHEABLE_ERROR_STATUSES
from roxy.config.defaults import POST_CACHE_ALLOWLIST
from roxy.core.reasons import AuthClass, ReasonCode
from roxy.rules.match import compile_pattern, normalize_target
from roxy.rules.models import CacheRuleRow
from roxy.rules.store import RulesSnapshot

DEFAULT_OWNER_DEADLINE_S: Final = 36.0
"""Plan 5.2 with default settings: 4 s + 15 s x 2 + 2 s. Used only if the settings cannot be read."""

_OWNER_KEYS: Final = ("queue_wait_interactive_ms", "request_timeout", "upstream_max_attempts", "backoff_cap_ms")

_POST_ALLOWLIST: Final = tuple(compile_pattern(pattern, "regex") for pattern in POST_CACHE_ALLOWLIST)
"""The built-in read-only POST lookups (plan 15.5), compiled once."""

_CSRF_FAILURE_TEXT: Final = b"token validation failed"
"""What Roblox's body says when a 403 is a CSRF challenge rather than "you may not see this resource"."""


class SettingsReader(Protocol):
    """The read side of `config/runtime.py: RuntimeSettings` this module needs."""

    def get(self, key: str) -> Any: ...


class PostMode(StrEnum):
    """Values of `cache_post_requests`."""

    OFF = "off"
    ALLOWLIST = "allowlist"
    ALL = "all"


@dataclass(frozen=True, slots=True)
class CacheSettings:
    """One consistent copy of the cache settings (plan 15.3 D), read once per settings version."""

    enabled: bool
    ttl_s: int
    error_ttl_s: int
    swr_s: int
    stale_s: int
    disk_enabled: bool
    max_entries: int
    max_bytes: int
    max_body: int
    memory_entries: int
    memory_bytes: int
    eviction_policy: str
    compress: bool
    coalesce: bool
    coalesce_wait_ms: int
    post_mode: str
    respect_no_cache: bool
    serve_throttled: bool
    negative_429: bool
    default_rules: bool
    swr_max_inflight: int
    owner_deadline_s: float
    cooldown_default_s: int
    cooldown_max_s: int
    flush_interval_s: float

    @classmethod
    def read(cls, settings: SettingsReader) -> CacheSettings:
        """Read every cache setting through `settings.get` (an in-memory snapshot, never the database)."""
        get = settings.get
        owner = owner_deadline_s({key: get(key) for key in _OWNER_KEYS})
        return cls(
            enabled=bool(get("cache_enabled")),
            ttl_s=max(0, int(get("cache_ttl_seconds"))),
            error_ttl_s=max(0, int(get("cache_error_ttl_seconds"))),
            swr_s=max(0, int(get("cache_swr_seconds"))),
            stale_s=max(0, int(get("cache_stale_seconds"))),
            disk_enabled=bool(get("cache_disk_enabled")),
            max_entries=max(0, int(get("cache_max_entries"))),
            max_bytes=max(0, int(get("cache_max_bytes"))),
            max_body=max(0, int(get("cache_max_body"))),
            memory_entries=max(0, int(get("cache_memory_entries"))),
            memory_bytes=max(0, int(get("cache_memory_bytes"))),
            eviction_policy=str(get("cache_eviction_policy")),
            compress=bool(get("cache_compress")),
            coalesce=bool(get("cache_coalesce")),
            coalesce_wait_ms=max(0, int(get("cache_coalesce_wait_ms"))),
            post_mode=str(get("cache_post_requests")),
            respect_no_cache=bool(get("cache_respect_no_cache")),
            serve_throttled=bool(get("cache_serve_throttled")),
            negative_429=bool(get("cache_negative_429")),
            default_rules=bool(get("cache_default_rules_enabled")),
            swr_max_inflight=max(0, int(get("swr_max_inflight"))),
            owner_deadline_s=owner if owner is not None and owner > 0 else DEFAULT_OWNER_DEADLINE_S,
            cooldown_default_s=max(1, int(get("cooldown_default_s"))),
            cooldown_max_s=max(1, int(get("cooldown_max_s"))),
            flush_interval_s=max(0.2, float(get("metrics_flush_interval_ms")) / 1000),
        )

    @property
    def follower_wait_s(self) -> float:
        """How long a single-flight follower waits: `cache_coalesce_wait_ms`, or the owner deadline when 0 (6.9)."""
        return self.coalesce_wait_ms / 1000 if self.coalesce_wait_ms > 0 else self.owner_deadline_s

    @property
    def shared_tier_on(self) -> bool:
        """Whether entries may be written to cache.db (`cache_disk_enabled` and both caps above 0)."""
        return self.disk_enabled and self.max_entries > 0 and self.max_bytes > 0


@dataclass(frozen=True, slots=True)
class RequestPolicy:
    """What the cache will do for one request, decided before any lookup."""

    cacheable: bool
    off_reason: str | None
    """Why the request is `OFF`: `disabled`, `method`, `private_credential` (None when cacheable)."""
    auth_class: AuthClass
    rule: CacheRuleRow | None = None
    private: bool = False
    bypass_lookup: bool = False
    """The caller sent `Cache-Control: no-cache` and `cache_respect_no_cache` is on: skip the lookup."""
    ttl_s: int = 0
    negative_ttl_s: int = 0
    swr_s: int = 0
    stale_s: int = 0
    coalesce: bool = False
    """Use fleet single-flight. Off when nothing could be stored anyway (a rule with lifetime 0)."""

    @property
    def stale_window_s(self) -> int:
        """How long after expiry an entry may still be served (REVALIDATING within `swr_s`, STALE within this)."""
        return max(self.swr_s, self.stale_s)


def _rule_applies(rule: CacheRuleRow, method: str, default_rules: bool) -> bool:
    return method in rule.methods and (default_rules or rule.origin != "default")


def select_rule(rules: RulesSnapshot, target: str, method: str, default_rules: bool) -> CacheRuleRow | None:
    """The most specific enabled cache rule covering `target` and `method` (v1 `match_cache_rule`, plus methods).

    The common case is one `best()` call; the full match list is only walked when the best rule does not cover
    the method or is a disabled default.
    """
    best = rules.cache_rule_for(target)
    if best is None:
        return None
    if _rule_applies(best, method, default_rules):
        return best
    for candidate in rules.cache_rule_index.matching(target):
        if _rule_applies(candidate, method, default_rules):
            return candidate
    return None


def post_allowed(target: str, rule: CacheRuleRow | None, mode: str) -> bool:
    """Whether a POST to `target` may be cached under `cache_post_requests` (parity row 57)."""
    if mode == PostMode.ALL:
        return True
    if mode != PostMode.ALLOWLIST:
        return False
    if rule is not None and "POST" in rule.methods:
        return True
    normalized = normalize_target(target)
    return any(pattern.matches(normalized) for pattern in _POST_ALLOWLIST)


def wants_fresh(headers: Mapping[str, str], respect_no_cache: bool) -> bool:
    """v1 `wants_fresh`: the caller's `Cache-Control` says no-cache or no-store, and the admin allows that."""
    if not respect_no_cache:
        return False
    value = (headers.get("cache-control") or "").lower()
    return "no-cache" in value or "no-store" in value


def request_policy(
    method: str,
    target: str,
    headers: Mapping[str, str],
    cs: CacheSettings,
    rules: RulesSnapshot,
) -> RequestPolicy:
    """Decide the cache's plan for one request (see the module docstring)."""
    verb = canonical_method(method)
    if not cs.enabled:
        return RequestPolicy(cacheable=False, off_reason="disabled", auth_class=AuthClass.ANON)
    credential_rule = rules.credential_rule_for(target, verb)
    auth_class = AuthClass.CRED if credential_rule is not None else AuthClass.ANON
    if credential_rule is not None and credential_rule.cache_private:
        # Plan 6.9: never stored, never coalesced, never revalidated, never served stale.
        return RequestPolicy(cacheable=False, off_reason="private_credential", auth_class=auth_class, private=True)
    rule = select_rule(rules, target, verb, cs.default_rules)
    if verb == "POST":
        if not post_allowed(target, rule, cs.post_mode):
            return RequestPolicy(cacheable=False, off_reason="method", auth_class=auth_class)
    elif verb != "GET":
        return RequestPolicy(cacheable=False, off_reason="method", auth_class=auth_class)
    ttl = rule.ttl if rule is not None else cs.ttl_s
    if rule is not None and rule.ttl == 0:
        negative_ttl = 0  # a lifetime of 0 means "never cache this endpoint", its errors included
    elif rule is not None and rule.negative_ttl > 0:
        negative_ttl = rule.negative_ttl
    else:
        negative_ttl = cs.error_ttl_s
    swr = rule.stale_ttl if rule is not None and rule.stale_ttl > 0 else cs.swr_s
    return RequestPolicy(
        cacheable=True,
        off_reason=None,
        auth_class=auth_class,
        rule=rule,
        bypass_lookup=wants_fresh(headers, cs.respect_no_cache),
        ttl_s=max(0, ttl),
        negative_ttl_s=max(0, negative_ttl),
        swr_s=swr,
        stale_s=cs.stale_s,
        coalesce=cs.coalesce and ttl > 0,
    )


class StoreKind(StrEnum):
    """What `store_decision` chose."""

    ENTRY = "entry"  # a 2xx answer, served as content
    NEGATIVE = "negative"  # a definitive Roblox error, replayed with its status (plan 7.7)
    MARKER = "marker"  # a per-key 429 marker: never served, only keeps callers away from Roblox
    NONE = "none"


@dataclass(frozen=True, slots=True)
class StoreDecision:
    """The outcome of `store_decision`. `skipped` is True when v1 would have counted the answer as Skipped."""

    kind: StoreKind
    ttl_s: int = 0
    why: str = ""
    skipped: bool = False


class UpstreamAnswer(Protocol):
    """The parts of `upstream/service.py: UpstreamResult` (DESIGN 11.3) the policy reads."""

    @property
    def status(self) -> int: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    @property
    def body(self) -> bytes: ...

    @property
    def auth_class(self) -> AuthClass: ...

    @property
    def upstream_status(self) -> int | None: ...

    @property
    def reason(self) -> ReasonCode: ...

    @property
    def retry_after_s(self) -> int | None: ...

    @property
    def cooldown_s(self) -> int | None: ...


def is_csrf_challenge(headers: Mapping[str, str], body: bytes) -> bool:
    """True when a 403 is Roblox asking for a CSRF token (never cacheable), not a permission answer (plan 7.7)."""
    if any(str(name).lower() == "x-csrf-token" for name in headers):
        return True
    return _CSRF_FAILURE_TEXT in body[:2048].lower()


def marker_ttl(result: UpstreamAnswer, cs: CacheSettings, hint: int | None = None) -> int:
    """How long a per-key 429 marker lives: until the cooldown ends (plan 7.7), clamped to [1, cooldown_max_s]."""
    for candidate in (result.cooldown_s, result.retry_after_s, hint):
        if candidate is not None and int(candidate) > 0:
            return max(1, min(int(candidate), cs.cooldown_max_s))
    return max(1, min(cs.cooldown_default_s, cs.cooldown_max_s))


def store_decision(result: UpstreamAnswer, policy: RequestPolicy, cs: CacheSettings) -> StoreDecision:
    """Decide what to keep from one upstream answer (see the module docstring for the table).

    The upstream layer's hints (DESIGN 11.3) are honored when present: `cacheable` says a 2xx may be stored as
    content, and `negative_ttl_s` is set (to a number) for a 4xx it judged negative-cacheable (status and CSRF
    checked, never on a private credential call). Lifetimes always come from this module (rules and settings).
    """
    if not policy.cacheable or policy.private:
        return StoreDecision(StoreKind.NONE, why="not_cacheable")
    if AuthClass(result.auth_class) == AuthClass.CRED and policy.auth_class != AuthClass.CRED:
        return StoreDecision(StoreKind.NONE, why="auth_class_mismatch")
    upstream = result.upstream_status
    reason = ReasonCode(result.reason)
    negative_hint: int | None = getattr(result, "negative_ttl_s", None)
    if upstream == 429:
        if cs.negative_429:
            return StoreDecision(StoreKind.MARKER, ttl_s=marker_ttl(result, cs, negative_hint), why="upstream_429")
        return StoreDecision(StoreKind.NONE, why="upstream_429")
    if upstream is None or reason.is_failure:
        return StoreDecision(StoreKind.NONE, why="failure")  # Roxy-side failures and 5xx are never content
    if 200 <= upstream < 300:
        if not getattr(result, "cacheable", True):
            return StoreDecision(StoreKind.NONE, why="upstream_veto")
        if policy.ttl_s <= 0:
            return StoreDecision(StoreKind.NONE, why="ttl_zero", skipped=True)
        if len(result.body) > cs.max_body:
            return StoreDecision(StoreKind.NONE, why="too_large", skipped=True)
        return StoreDecision(StoreKind.ENTRY, ttl_s=policy.ttl_s)
    if upstream in CACHEABLE_ERROR_STATUSES:
        if hasattr(result, "negative_ttl_s") and negative_hint is None:
            return StoreDecision(StoreKind.NONE, why="upstream_veto")  # the upstream judged it not negative-cacheable
        if upstream == 403 and is_csrf_challenge(result.headers, result.body):
            return StoreDecision(StoreKind.NONE, why="csrf_challenge")
        if policy.negative_ttl_s <= 0:
            return StoreDecision(StoreKind.NONE, why="error_ttl_zero", skipped=True)
        if len(result.body) > cs.max_body:
            return StoreDecision(StoreKind.NONE, why="too_large", skipped=True)
        return StoreDecision(StoreKind.NEGATIVE, ttl_s=policy.negative_ttl_s)
    return StoreDecision(StoreKind.NONE, why="status_not_cacheable", skipped=True)


__all__ = [
    "DEFAULT_OWNER_DEADLINE_S",
    "CacheSettings",
    "PostMode",
    "RequestPolicy",
    "SettingsReader",
    "StoreDecision",
    "StoreKind",
    "UpstreamAnswer",
    "is_csrf_challenge",
    "marker_ttl",
    "post_allowed",
    "request_policy",
    "select_rule",
    "store_decision",
    "wants_fresh",
]
