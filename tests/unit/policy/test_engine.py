"""The endpoint policy engine: golden verdicts, precedence, unknown endpoints, query guards and credential grants."""

from __future__ import annotations

import pytest

from roxy.policy.engine import EndpointPolicy, OverrideEntry, danger_word, unknown_id
from roxy.policy.seed import Verdict, load_seed


def policy(overrides: list[OverrideEntry] | None = None, categories: dict[str, str] | None = None) -> EndpointPolicy:
    return EndpointPolicy(load_seed(), overrides or [], categories or {})


@pytest.mark.parametrize(
    ("host", "method", "path"),
    [
        ("auth.roblox.com", "POST", "/v1/logout"),
        ("auth.roblox.com", "POST", "/v2/logout"),
        ("auth.roblox.com", "POST", "/v3/logout"),
        ("auth.roblox.com", "POST", "/v1/session/refresh"),
        ("users.roblox.com", "GET", "/v1/users/authenticated"),
        ("groups.roblox.com", "GET", "/v1/groups/7/membership"),
        ("games.roblox.com", "GET", "/v1/games/920587237/private-servers"),
        ("clientsettings.roblox.com", "GET", "/v2/user-channel"),
        ("twostepverification.roblox.com", "POST", "/v1/users/1/recovery-codes/regenerate"),
        ("accountinformation.roblox.com", "GET", "/v1/phone"),
        ("accountsettings.roblox.com", "POST", "/v1/email"),
        ("economy.roblox.com", "GET", "/v1/user/currency"),
        ("locale.roblox.com", "POST", "/v1/locales/set-user-supported-locale"),
        ("gamejoin.roblox.com", "POST", "/v1/join-game"),
        ("billing.roblox.com", "GET", "/v1/anything"),
    ],
)
def test_golden_blocked(host: str, method: str, path: str) -> None:
    decision = policy().decide(host, method, path)
    assert decision.verdict is Verdict.BLOCK, decision
    assert policy().credential_grant(f"{host}{path}", method) is None


@pytest.mark.parametrize(
    ("host", "method", "path"),
    [
        ("users.roblox.com", "POST", "/v1/usernames/users"),
        ("users.roblox.com", "POST", "/v1/users"),
        ("users.roblox.com", "GET", "/v1/users/156"),
        ("catalog.roblox.com", "GET", "/v2/search/items/details"),
        ("thumbnails.roblox.com", "GET", "/v1/users/avatar-headshot"),
        ("presence.roblox.com", "POST", "/v1/presence/users"),
        ("games.roblox.com", "GET", "/v1/games"),
        ("friends.roblox.com", "GET", "/v1/users/1/followings"),
    ],
)
def test_golden_sent_with_the_account(host: str, method: str, path: str) -> None:
    decision = policy().decide(host, method, path)
    assert decision.verdict is Verdict.ALLOW_TOKEN, decision
    grant = policy().credential_grant(f"{host}{path}", method)
    assert grant is not None
    assert grant.methods == (method,)


def test_sign_in_only_endpoints_never_fall_back_to_anonymous() -> None:
    grant = policy().credential_grant("friends.roblox.com/v1/users/1/followings", "GET")
    assert grant is not None
    assert not grant.identical_anonymous  # Roblox answers it only to signed-in users
    open_grant = policy().credential_grant("users.roblox.com/v1/users/1", "GET")
    assert open_grant is not None
    assert open_grant.identical_anonymous


@pytest.mark.parametrize(
    "target", ["avatar.roblox.com/v2/avatar/users/29371917/outfits", "avatar.roblox.com/v1/users/29371917/outfits"]
)
def test_outfits_never_fall_back_to_an_anonymous_answer(target: str) -> None:
    # Anonymously, isEditable=true answers an empty list: during an account cooldown the caller must get a 429,
    # never an empty answer that looks real (owner report, 2026-10-16).
    grant = policy().credential_grant(target, "GET")
    assert grant is not None
    assert not grant.identical_anonymous


def test_anonymous_tier_never_gets_the_credential() -> None:
    decision = policy().decide("catalog.roblox.com", "POST", "/v1/catalog/items/details/complete")
    assert decision.verdict is Verdict.ALLOW_ANON
    assert policy().credential_grant("catalog.roblox.com/v1/catalog/items/details/complete", "POST") is None


def test_override_beats_category_beats_seed() -> None:
    row_id = "users:GET:/v1/users/{userId}"
    switched = policy(categories={"public-read": "block_all"})
    assert switched.decide("users.roblox.com", "GET", "/v1/users/1").verdict is Verdict.BLOCK
    assert switched.decide("users.roblox.com", "GET", "/v1/users/1").source == "category"
    both = policy([OverrideEntry(row_id, Verdict.ALLOW_ANON)], {"public-read": "block_all"})
    decision = both.decide("users.roblox.com", "GET", "/v1/users/1")
    assert decision.verdict is Verdict.ALLOW_ANON
    assert decision.source == "override"


def test_strip_credential_beats_an_allow_token_override() -> None:
    row_id = "users:GET:/v1/users/{userId}"
    switched = policy([OverrideEntry(row_id, Verdict.ALLOW_TOKEN)], {"public-read": "strip_credential"})
    assert switched.decide("users.roblox.com", "GET", "/v1/users/1").verdict is Verdict.ALLOW_ANON
    assert switched.credential_grant("users.roblox.com/v1/users/1", "GET") is None
    assert switched.effective(load_seed().by_id[row_id]) is Verdict.ALLOW_ANON


def test_an_unknown_write_never_carries_the_account() -> None:
    key = unknown_id("POST", "users.roblox.com/v9/batch")
    loose = policy([OverrideEntry(key, Verdict.ALLOW_TOKEN)])
    decision = loose.decide("users.roblox.com", "POST", "/v9/batch", template="users.roblox.com/v9/batch")
    assert decision.verdict is Verdict.ALLOW_ANON
    assert loose.credential_grant("users.roblox.com/v9/batch", "POST") is None


def test_strip_credential_switch() -> None:
    stripped = policy(categories={"public-read": "strip_credential"})
    assert stripped.decide("users.roblox.com", "GET", "/v1/users/1").verdict is Verdict.ALLOW_ANON
    assert stripped.credential_grant("users.roblox.com/v1/users/1", "GET") is None
    # A blocked row stays blocked: the switch only takes the account away.
    assert stripped.decide("auth.roblox.com", "POST", "/v1/logout").verdict is Verdict.BLOCK


def test_the_account_never_goes_with_put_patch_or_delete() -> None:
    row_id = "avatar:PATCH:/v1/avatar/set-scales"
    if row_id not in load_seed().by_id:
        row_id = next(r.id for r in load_seed().rows if r.method == "PATCH")
    row = load_seed().by_id[row_id]
    loose = policy([OverrideEntry(row_id, Verdict.ALLOW_TOKEN)])
    assert loose.decide(row.host, row.method, row.path).verdict is Verdict.ALLOW_ANON
    assert loose.credential_grant(row.template, row.method) is None


def test_unknown_endpoints() -> None:
    p = policy()
    read = p.decide("users.roblox.com", "GET", "/v9/whatever/123")
    assert read.verdict is Verdict.ALLOW_ANON
    assert read.source == "unknown"
    assert read.endpoint_id.startswith("unknown:GET:users.roblox.com/")
    assert p.decide("users.roblox.com", "DELETE", "/v9/whatever").verdict is Verdict.BLOCK
    assert p.decide("users.roblox.com", "POST", "/v9/whatever").verdict is Verdict.BLOCK
    for path in ("/v9/my/stuff", "/v9/users/me", "/v2/logout-all", "/v1/user/things", "/v1/x/password-reset"):
        assert p.decide("users.roblox.com", "GET", path).verdict is Verdict.BLOCK, path


def test_an_unknown_endpoint_can_be_reviewed() -> None:
    key = unknown_id("GET", "users.roblox.com/v9/whatever/{id}")
    reviewed = policy([OverrideEntry(key, Verdict.ALLOW_TOKEN)])
    template = "users.roblox.com/v9/whatever/{id}"
    decision = reviewed.decide("users.roblox.com", "GET", "/v9/whatever/123", template=template)
    assert decision.verdict is Verdict.ALLOW_TOKEN
    assert decision.source == "override"


def test_danger_words() -> None:
    assert danger_word("/v1/my/friends") == "/my/"
    assert danger_word("/v1/user/settings") is not None
    assert danger_word("/v1/users/1/username-history") is None


@pytest.mark.parametrize("server_type", ["1", "Friend", "friend", "FRIEND"])
def test_friend_server_lists_are_blocked(server_type: str) -> None:
    decision = policy().decide("games.roblox.com", "GET", f"/v1/games/1/servers/{server_type}")
    assert decision.verdict is Verdict.BLOCK
    assert decision.source == "guard"
    assert policy().decide("games.roblox.com", "GET", "/v1/games/1/servers/0").verdict is Verdict.ALLOW_TOKEN


def test_private_group_roles_are_blocked() -> None:
    p = policy()
    assert p.decide("groups.roblox.com", "GET", "/v1/groups/1/roles").verdict is Verdict.ALLOW_TOKEN
    guarded = p.decide("groups.roblox.com", "GET", "/v1/groups/1/roles", [("includePrivate", "true")])
    assert guarded.verdict is Verdict.BLOCK


def test_summary_counts_every_row() -> None:
    summary = policy().summary()
    assert sum(summary["verdicts"].values()) == summary["rows"] == 992
