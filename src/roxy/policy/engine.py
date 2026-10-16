"""The endpoint policy engine: one `PolicyDecision` per request, from the seed, the overrides and the switches.

What this is
    `EndpointPolicy(seed, overrides, categories)` and its `decide(host, method, path, query)`, plus
    `CredentialGrant`, the small object `RulesSnapshot.credential_rule_for` hands the upstream and the cache when a
    request may carry the credential.

Why it exists
    BRIEF.md section 3: a request gets exactly one verdict, from a fixed order of sources, so the abuse check, the
    cache and the upstream can never disagree about whether the credential goes out.

How it works
    Precedence, first match wins:
      1. An admin override for the operation (`endpoint_policy_override`, keyed by the seed id, or by
         `unknown:<METHOD>:<template>` for an operation the seed does not list). Disabled overrides are ignored.
         Two limits: `strip_credential` on the operation's category beats an ALLOW_TOKEN override (it is the panic
         switch), and an operation the seed does not list never carries the account on anything but GET or HEAD.
      2. The category switch of the operation's category (`endpoint_policy_category`): `block_all` blocks it,
         `strip_credential` turns ALLOW_TOKEN into ALLOW_ANON.
      3. The seed row's verdict.
      4. A host default (`host_defaults` in the seed) for hosts Roblox does not document.
      5. An unknown operation: anything but GET or HEAD is BLOCK; a GET whose path holds a danger word (`/my/`,
         `logout`, `password`, ...) is BLOCK; any other GET is ALLOW_ANON (sent, never with the credential).
    Then the query guards (`QUERY_GUARDS`) can turn an allowed request into BLOCK, for verdicts that depend on a
    parameter (friend server lists, private group roles).
    The credential is only ever granted for ALLOW_TOKEN and only for GET, HEAD and POST (`CREDENTIAL_METHODS`): no
    override can put it on a PUT, PATCH or DELETE. A grant for an operation Roblox does not require a sign-in for is
    `identical_anonymous`, so when the account is busy or cooling down the request goes out anonymously instead of
    failing (BRIEF.md 5.4); an operation that requires a sign-in waits for the account or gets 429.

What to read next
    `roxy/abuse/checks/endpoint_policy.py` (the refusal) and `roxy/rules/store.py` (`credential_rule_for`).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from roxy.policy.matcher import TemplateIndex, split_path
from roxy.policy.seed import CATEGORIES, Seed, SeedRow, Verdict

CREDENTIAL_METHODS: Final = frozenset({"GET", "HEAD", "POST"})
"""The only methods the credential is ever attached to, and only for an ALLOW_TOKEN verdict."""

READ_METHODS: Final = frozenset({"GET", "HEAD"})

DANGER_WORDS: Final[tuple[str, ...]] = (
    "/my/",
    "/me/",
    "/users/me",
    "authenticated",
    "logout",
    "login",
    "session",
    "ticket",
    "token",
    "password",
    "twostep",
    "two-step",
    "2sv",
    "recovery",
    "email",
    "phone",
    "birthdate",
    "currency",
    "robux",
    "transaction",
    "payout",
    "billing",
    "payment",
    "purchase",
    "trade",
    "message",
    "notification",
    "settings",
    "permission",
    "audit",
    "join-request",
    "private-server",
    "vip-server",
)
"""Words that make an unknown GET path BLOCK (BRIEF.md 3.5). Matched on the lowercase path with slashes."""

_USER_SEGMENT: Final = re.compile(r"(^|/)user(/|$)")
UNKNOWN_PREFIX: Final = "unknown:"


@dataclass(frozen=True, slots=True)
class QueryGuard:
    """A parameter that turns one allowed operation into BLOCK (BRIEF.md 3.6)."""

    endpoint_ids: frozenset[str]
    param: str
    refuses: Callable[[str], bool]
    reason: str


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


QUERY_GUARDS: Final[tuple[QueryGuard, ...]] = (
    QueryGuard(
        frozenset(
            {
                "games:GET:/v1/games/{placeId}/servers/{serverType}",
                "games:GET:/v2/games/{placeId}/servers/{serverType}",
            }
        ),
        "#segment:-1",
        lambda value: value.strip().lower() in {"1", "friend"},
        "Friend server lists show where the account's friends play.",
    ),
    QueryGuard(
        frozenset(
            {
                "groups:GET:/v1/groups/{groupId}/roles",
                "groups:GET:/v1/roles",
            }
        ),
        "includeprivate",
        _truthy,
        "Private group roles are shown only to members, so asking for them would use the account's memberships.",
    ),
)


@dataclass(frozen=True, slots=True)
class OverrideEntry:
    """What the engine needs from one `endpoint_policy_override` row."""

    endpoint_id: str
    verdict: Verdict
    cache_private: bool = False
    note: str = ""


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The policy's answer for one request."""

    verdict: Verdict
    source: str  # "override", "category", "seed", "host", "unknown" or "guard"
    endpoint_id: str  # the seed id, or `unknown:<METHOD>:<template>`
    category: str
    risk: int
    reason: str  # plain words for the admin (never sent to callers)
    row: SeedRow | None = None
    requires_login: bool = False
    cache_private: bool = False
    rule_id: int = 0
    default_verdict: Verdict | None = None  # what the seed (or the unknown rule) says, before overrides

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    @property
    def known(self) -> bool:
        return self.row is not None


@dataclass(frozen=True, slots=True)
class CredentialGrant:
    """A credential grant for one request (the shape `upstream/routing.py CredentialRule.from_row` reads).

    `pattern` and `type` describe the matched operation for records and insights; `methods` lists the one method
    the grant covers.
    """

    id: int
    pattern: str
    endpoint_id: str
    methods: tuple[str, ...]
    cache_private: bool
    identical_anonymous: bool
    type: str = "policy"
    enabled: bool = True
    note: str = ""


def unknown_id(method: str, template: str) -> str:
    """The override key of an operation the seed does not list."""
    verb = "GET" if method.upper() == "HEAD" else method.upper()
    return f"{UNKNOWN_PREFIX}{verb}:{template.lower()}"


def danger_word(path: str) -> str | None:
    """The first danger word in a lowercase path, or None (`/user/` as a whole segment counts too)."""
    lowered = "/" + "/".join(split_path(path)) + "/"
    for word in DANGER_WORDS:
        if word in lowered:
            return word
    if _USER_SEGMENT.search(lowered):
        return "/user/"
    return None


def _template_of(host: str, path: str) -> str:
    from roxy.metrics.templating import template_for  # local: keeps the policy package import-light

    return str(template_for(host, path))


class EndpointPolicy:
    """The compiled policy for one rules snapshot (module docstring for the order of sources)."""

    __slots__ = ("_categories", "_index", "_overrides", "_rule_ids", "seed")

    def __init__(
        self,
        seed: Seed,
        overrides: Iterable[OverrideEntry] = (),
        categories: Mapping[str, str] | None = None,
        *,
        index: TemplateIndex | None = None,
    ) -> None:
        self.seed = seed
        self._index = index if index is not None else TemplateIndex(seed.rows)
        self._overrides: Mapping[str, OverrideEntry] = MappingProxyType({o.endpoint_id: o for o in overrides})
        self._categories: Mapping[str, str] = MappingProxyType(
            {key: state for key, state in (categories or {}).items() if key in CATEGORIES}
        )
        self._rule_ids: Mapping[str, int] = MappingProxyType({row.id: n for n, row in enumerate(seed.rows, 1)})

    @property
    def index(self) -> TemplateIndex:
        return self._index

    @property
    def overrides(self) -> Mapping[str, OverrideEntry]:
        return self._overrides

    @property
    def categories(self) -> Mapping[str, str]:
        return self._categories

    def category_state(self, category: str) -> str:
        return self._categories.get(category, "defaults")

    # ---- the decision

    def decide(
        self, host: str, method: str, path: str, query: Sequence[tuple[str, str]] = (), template: str | None = None
    ) -> PolicyDecision:
        """The verdict for one request (`host` lowercase, `path` decoded and validated, with a leading slash)."""
        host = host.lower().rstrip(".")
        verb = method.upper()
        row = self._index.find(host, verb, path)
        if row is not None:
            decision = self._known(row, verb)
        else:
            decision = self._unknown(host, verb, path, template)
        if decision.verdict is not Verdict.BLOCK and row is not None:
            guarded = self._guard(decision, row, path, query)
            if guarded is not None:
                return guarded
        return decision

    def decide_target(self, target: str, method: str) -> PolicyDecision:
        """`decide` for a rules target (`host/path`, the form `RulesSnapshot` lookups take)."""
        host, _, rest = target.partition("/")
        return self.decide(host, method, "/" + rest)

    def default_for(self, row: SeedRow) -> Verdict:
        """The verdict a seed row has with no override (its category switch applied)."""
        state = self.category_state(row.category)
        if state == "block_all":
            return Verdict.BLOCK
        if state == "strip_credential" and row.verdict is Verdict.ALLOW_TOKEN:
            return Verdict.ALLOW_ANON
        return row.verdict

    def effective(self, row: SeedRow) -> Verdict:
        """The verdict a seed row has now for its own method: overrides and category switches applied."""
        override = self._overrides.get(row.id)
        if override is None:
            return self.default_for(row)
        if override.verdict is Verdict.ALLOW_TOKEN and self.category_state(row.category) == "strip_credential":
            return Verdict.ALLOW_ANON
        return override.verdict

    def _known(self, row: SeedRow, verb: str) -> PolicyDecision:
        override = self._overrides.get(row.id)
        base: dict[str, Any] = {
            "endpoint_id": row.id,
            "category": row.category,
            "risk": row.risk,
            "row": row,
            "requires_login": row.requires_login,
            "rule_id": self._rule_ids.get(row.id, 0),
            "default_verdict": row.verdict,
        }
        state = self.category_state(row.category)
        if override is not None:
            verdict = self._fit(override.verdict, verb)
            if state == "strip_credential" and verdict is Verdict.ALLOW_TOKEN:
                # The panic switch beats every override: it only ever takes the account away.
                label = CATEGORIES[row.category].label
                reason = f"Category switch strip_credential on {label} (it beats overrides)"
                return PolicyDecision(Verdict.ALLOW_ANON, "category", reason=reason, **base)
            note = f": {override.note}" if override.note else ""
            return PolicyDecision(
                verdict, "override", reason=f"Admin override{note}", cache_private=override.cache_private, **base
            )
        verdict = self._fit(self.default_for(row), verb)
        if state != "defaults" and verdict is not row.verdict:
            label = CATEGORIES[row.category].label
            return PolicyDecision(verdict, "category", reason=f"Category switch {state} on {label}", **base)
        return PolicyDecision(verdict, "seed", reason=row.rationale, **base)

    def _unknown(self, host: str, verb: str, path: str, template: str | None) -> PolicyDecision:
        if template is None and "{" in path:
            template = f"{host}{path}"  # already a template (the insights ask with templates): keep its braces
        key = unknown_id(verb, template or _template_of(host, path))
        default = self.seed.host_defaults.get(host)
        if default is not None:
            verdict, category, risk, reason, source = (
                default.verdict,
                default.category,
                default.risk,
                default.rationale,
                "host",
            )
        elif verb not in READ_METHODS:
            verdict, category, risk, source = Verdict.BLOCK, "platform-misc", 3, "unknown"
            reason = "Not in Roblox's reference: a write Roxy has not reviewed is blocked."
        else:
            word = danger_word(path)
            source, category = "unknown", "platform-misc"
            if word is not None:
                verdict, risk = Verdict.BLOCK, 3
                reason = f"Not in Roblox's reference, and the path holds {word.strip('/')!r}, which is how account"
                reason += " endpoints look."
            else:
                verdict, risk = Verdict.ALLOW_ANON, 2
                reason = "Not in Roblox's reference: sent without the account until an admin reviews it."
        override = self._overrides.get(key)
        if override is not None:
            note = f": {override.note}" if override.note else ""
            chosen = self._fit(override.verdict, verb)
            if chosen is Verdict.ALLOW_TOKEN and verb not in READ_METHODS:
                chosen = Verdict.ALLOW_ANON  # an operation Roxy has not reviewed never carries the account on a write
            return PolicyDecision(
                chosen,
                "override",
                key,
                category,
                risk,
                f"Admin override{note}",
                cache_private=override.cache_private,
                default_verdict=verdict,
            )
        return PolicyDecision(verdict, source, key, category, risk, reason, default_verdict=verdict)

    @staticmethod
    def _fit(verdict: Verdict, verb: str) -> Verdict:
        """ALLOW_TOKEN on a method the credential never carries becomes ALLOW_ANON."""
        if verdict is Verdict.ALLOW_TOKEN and verb not in CREDENTIAL_METHODS:
            return Verdict.ALLOW_ANON
        return verdict

    @staticmethod
    def _guard(
        decision: PolicyDecision, row: SeedRow, path: str, query: Sequence[tuple[str, str]]
    ) -> PolicyDecision | None:
        for guard in QUERY_GUARDS:
            if row.id not in guard.endpoint_ids:
                continue
            if guard.param == "#segment:-1":
                parts = split_path(path)
                values = [parts[-1]] if parts else []
            else:
                values = [value for name, value in query if name.lower() == guard.param]
            if any(guard.refuses(value) for value in values):
                return PolicyDecision(
                    Verdict.BLOCK,
                    "guard",
                    decision.endpoint_id,
                    decision.category,
                    max(decision.risk, 3),
                    guard.reason,
                    row=row,
                    requires_login=decision.requires_login,
                    rule_id=decision.rule_id,
                    default_verdict=decision.default_verdict,
                )
        return None

    # ---- the credential

    def credential_grant(self, target: str, method: str) -> CredentialGrant | None:
        """A grant when `method` on `target` may carry the credential (ALLOW_TOKEN, GET/HEAD/POST), else None."""
        verb = method.upper()
        if verb not in CREDENTIAL_METHODS:
            return None
        decision = self.decide_target(target, verb)
        if decision.verdict is not Verdict.ALLOW_TOKEN:
            return None
        row = decision.row
        return CredentialGrant(
            id=decision.rule_id,
            # An unknown id is `unknown:<METHOD>:<template>`: the pattern is the template alone.
            pattern=row.template if row is not None else decision.endpoint_id.split(":", 2)[2],
            endpoint_id=decision.endpoint_id,
            methods=(verb,),
            cache_private=decision.cache_private,
            # Roblox answers this one without a sign-in too: when the account cannot take it right now, send it
            # anonymously instead of failing (BRIEF.md 5.4). A sign-in-only operation never falls back.
            identical_anonymous=not decision.requires_login,
        )

    def summary(self) -> dict[str, Any]:
        """Counts for the admin page: the effective verdict of every seed row (overrides and switches applied)."""
        counts = {verdict.value: 0 for verdict in Verdict}
        for row in self.seed.rows:
            counts[self.effective(row).value] += 1
        return {
            "rows": len(self.seed.rows),
            "verdicts": counts,
            "overrides": len(self._overrides),
            "categories": dict(self._categories),
        }


__all__ = [
    "CREDENTIAL_METHODS",
    "DANGER_WORDS",
    "QUERY_GUARDS",
    "UNKNOWN_PREFIX",
    "CredentialGrant",
    "EndpointPolicy",
    "OverrideEntry",
    "PolicyDecision",
    "QueryGuard",
    "danger_word",
    "unknown_id",
]
