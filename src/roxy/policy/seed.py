"""The shipped endpoint policy seed: every documented Roblox operation with its reviewed default verdict.

What this is
    `load_seed()` reads `endpoint_policy_seed.json` (shipped inside this package) into a frozen `Seed`: one
    `SeedRow` per Roblox operation (host, method, path template, Roblox's own sign-in label, verdict, category,
    risk, why, and links to Roblox's documentation) plus `host_defaults` for the hosts Roxy allows that Roblox does
    not document. `Verdict`, `CATEGORIES` (the admin page's toggle groups, with plain descriptions) and
    `CATEGORY_STATES` live here too.

Why it exists
    The verdicts are reviewed data, not code: `docs/endpoint_policy/` holds the reviewed copy, the generated catalog
    and the tools that find drift when Roblox changes its APIs (BRIEF.md section 9). A seed that does not validate
    stops start-up, because a broken policy must never quietly allow everything.

How it works
    The file is parsed once per process (`functools.cache`). Validation: every verdict and category is known,
    every risk is 1 to 4, ids are unique and equal `<host label>:<METHOD>:<path>`, every path starts with `/`, and
    every host is a roblox.com host. `tests/unit/policy/test_seed.py` also checks that this copy equals
    `docs/endpoint_policy/endpoint_policy_seed.json`.

What to read next
    `roxy/policy/matcher.py`, then `roxy/policy/engine.py`.
"""

from __future__ import annotations

import enum
import functools
import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from types import MappingProxyType
from typing import Any, Final

SEED_FILE: Final = "endpoint_policy_seed.json"
METHODS: Final = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


class Verdict(enum.StrEnum):
    """What Roxy does with one operation."""

    BLOCK = "BLOCK"
    ALLOW_TOKEN = "ALLOW_TOKEN"  # noqa: S105 (a verdict name, not a secret)
    ALLOW_ANON = "ALLOW_ANON"


VERDICT_LABELS: Final[Mapping[Verdict, str]] = MappingProxyType(
    {
        Verdict.BLOCK: "Blocked",
        Verdict.ALLOW_TOKEN: "Sent with Roxy's account",
        Verdict.ALLOW_ANON: "Sent without an account",
    }
)

LOOSENING: Final[Mapping[Verdict, int]] = MappingProxyType(
    {Verdict.BLOCK: 0, Verdict.ALLOW_ANON: 1, Verdict.ALLOW_TOKEN: 2}
)
"""How open a verdict is. Moving to a higher number loosens the policy (it needs a fresh second factor)."""


@dataclass(frozen=True, slots=True)
class Category:
    """One toggle group of the admin page."""

    key: str
    label: str
    description: str


CATEGORIES: Final[Mapping[str, Category]] = MappingProxyType(
    {
        c.key: c
        for c in (
            Category(
                "login-session-security",
                "Sign-in and account security",
                "Login, logout, signup, sessions, tickets, passwords, two-step verification, passkeys, PINs, recovery,"
                " and email or phone verification.",
            ),
            Category(
                "account-identity",
                "Who the account is",
                "Endpoints that answer with the signed-in account itself, such as /v1/users/authenticated.",
            ),
            Category(
                "account-private-data",
                "The account's private data",
                "Email, phone, birthdate, settings, inbox, notifications, favorites, follows and other data only the"
                " account may read.",
            ),
            Category(
                "account-settings-write",
                "Changing the account",
                "Any change to the account's settings or profile.",
            ),
            Category("social-actions", "Social actions", "Friend, follow, block, message and push registration."),
            Category(
                "group-actions",
                "Group actions",
                "Join, leave, roles, payouts, wall posts, and reads only group members or admins may make.",
            ),
            Category(
                "economy-spend",
                "Robux, purchases and trades",
                "Buying, spending or moving Robux, trades, private servers, premium, sales and revenue.",
            ),
            Category("inventory-private", "The account's inventory", "The account's own inventory views and changes."),
            Category(
                "avatar-write", "Changing the avatar", "Wearing items, outfits, body settings, thumbnail redraws."
            ),
            Category(
                "creator-management",
                "Creator tools",
                "Managing games, places, assets, localization and permissions: develop, publish, configure, upload,"
                " restart servers.",
            ),
            Category(
                "creator-private-data",
                "Creator private data",
                "Analytics, stats, logs and creator-only views of things the account might own or edit.",
            ),
            Category("ads", "Ads", "Ad campaigns, sponsored items and click tracking."),
            Category(
                "open-cloud-key-only",
                "Open Cloud (API key only)",
                "Open Cloud routes that accept only an API key or OAuth. Roxy has neither, and callers may not send"
                " theirs, so these can never work through Roxy.",
            ),
            Category("platform-misc", "Other", "Anything that fits no other group."),
            Category(
                "public-read",
                "Public data",
                "Everything callers should be able to use: catalog, thumbnails, users, groups, games, badges and"
                " other public reads.",
            ),
        )
    }
)

CATEGORY_STATES: Final = ("defaults", "block_all", "strip_credential")
"""`defaults`: each row's own verdict. `block_all`: every row of the category is blocked. `strip_credential`:
every allowed row of the category is sent without the credential (only meaningful for `public-read`)."""


class SeedError(ValueError):
    """The shipped seed failed validation: start-up stops (a broken policy must never allow everything)."""


@dataclass(frozen=True, slots=True)
class SeedRow:
    """One documented Roblox operation and its reviewed default."""

    id: str
    host: str
    method: str
    path: str
    summary: str
    roblox_auth: str
    requires_login: bool
    verdict: Verdict
    category: str
    risk: int
    rationale: str
    notes: str
    deprecated: bool
    feature_doc: str | None
    domain_doc: str

    @property
    def template(self) -> str:
        """`host/path`, the form the Endpoints page and the cache use."""
        return f"{self.host}{self.path}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "summary": self.summary,
            "roblox_auth": self.roblox_auth,
            "requires_login": self.requires_login,
            "verdict": self.verdict.value,
            "category": self.category,
            "risk": self.risk,
            "rationale": self.rationale,
            "notes": self.notes,
            "deprecated": self.deprecated,
            "feature_doc": self.feature_doc,
            "domain_doc": self.domain_doc,
        }


@dataclass(frozen=True, slots=True)
class HostDefault:
    """The verdict for every request to a host Roblox does not document."""

    host: str
    verdict: Verdict
    category: str
    risk: int
    rationale: str


@dataclass(frozen=True, slots=True)
class Seed:
    """The whole shipped policy."""

    generated_on: str
    source_commit: str
    rows: tuple[SeedRow, ...]
    by_id: Mapping[str, SeedRow]
    host_defaults: Mapping[str, HostDefault]

    @property
    def hosts(self) -> frozenset[str]:
        return frozenset(row.host for row in self.rows) | frozenset(self.host_defaults)


def endpoint_id(host: str, method: str, path: str) -> str:
    """The seed id of an operation: `<first host label>:<METHOD>:<path>` (for example `users:GET:/v1/users/{id}`)."""
    return f"{host.split('.', 1)[0]}:{method.upper()}:{path}"


def _verdict(value: Any, where: str) -> Verdict:
    try:
        return Verdict(str(value))
    except ValueError:
        raise SeedError(f"{where}: unknown verdict {value!r}") from None


def _common(raw: Mapping[str, Any], where: str) -> tuple[Verdict, str, int]:
    verdict = _verdict(raw.get("verdict"), where)
    category = str(raw.get("category", ""))
    if category not in CATEGORIES:
        raise SeedError(f"{where}: unknown category {category!r}")
    risk = raw.get("risk")
    if not isinstance(risk, int) or not 1 <= risk <= 4:
        raise SeedError(f"{where}: risk must be 1 to 4")
    return verdict, category, risk


def _host(value: Any, where: str) -> str:
    host = str(value or "").lower()
    if not host.endswith(".roblox.com") or "/" in host:
        raise SeedError(f"{where}: {host!r} is not a roblox.com host")
    return host


def parse_seed(data: Mapping[str, Any]) -> Seed:
    """Validate the parsed JSON and build the `Seed` (raises `SeedError`)."""
    rows: list[SeedRow] = []
    by_id: dict[str, SeedRow] = {}
    for index, raw in enumerate(data.get("endpoints") or ()):
        where = f"endpoints[{index}]"
        host = _host(raw.get("host"), where)
        method = str(raw.get("method", "")).upper()
        if method not in METHODS:
            raise SeedError(f"{where}: unknown method {method!r}")
        path = str(raw.get("path", ""))
        if not path.startswith("/") or "#" in path or "?" in path:
            raise SeedError(f"{where}: path {path!r} must start with / and hold no # or ?")
        verdict, category, risk = _common(raw, where)
        row_id = endpoint_id(host, method, path)
        if raw.get("id") != row_id:
            raise SeedError(f"{where}: id {raw.get('id')!r} should be {row_id!r}")
        if row_id in by_id:
            raise SeedError(f"{where}: duplicate id {row_id!r}")
        row = SeedRow(
            id=row_id,
            host=host,
            method=method,
            path=path,
            summary=str(raw.get("summary") or ""),
            roblox_auth=str(raw.get("roblox_auth") or ""),
            requires_login=bool(raw.get("requires_login")),
            verdict=verdict,
            category=category,
            risk=risk,
            rationale=str(raw.get("rationale") or ""),
            notes=str(raw.get("notes") or ""),
            deprecated=bool(raw.get("deprecated")),
            feature_doc=raw.get("feature_doc") or None,
            domain_doc=str(raw.get("domain_doc") or ""),
        )
        rows.append(row)
        by_id[row_id] = row
    if not rows:
        raise SeedError("the seed has no endpoints")
    defaults: dict[str, HostDefault] = {}
    for host_raw, raw in (data.get("host_defaults") or {}).items():
        host = _host(host_raw, f"host_defaults[{host_raw}]")
        verdict, category, risk = _common(raw, f"host_defaults[{host}]")
        defaults[host] = HostDefault(host, verdict, category, risk, str(raw.get("rationale") or ""))
    source = data.get("source") or {}
    return Seed(
        generated_on=str(data.get("generated_on") or ""),
        source_commit=str(source.get("commit") or ""),
        rows=tuple(rows),
        by_id=MappingProxyType(by_id),
        host_defaults=MappingProxyType(defaults),
    )


@functools.cache
def load_seed() -> Seed:
    """The shipped seed, parsed and validated once per process (raises `SeedError`)."""
    text = resources.files("roxy.policy").joinpath(SEED_FILE).read_text(encoding="utf-8")
    return parse_seed(json.loads(text))


__all__ = [
    "CATEGORIES",
    "CATEGORY_STATES",
    "LOOSENING",
    "METHODS",
    "VERDICT_LABELS",
    "Category",
    "HostDefault",
    "Seed",
    "SeedError",
    "SeedRow",
    "Verdict",
    "endpoint_id",
    "load_seed",
    "parse_seed",
]
