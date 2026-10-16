"""Template matching: letter case, trailing slashes, `:verb` segments and specificity."""

from __future__ import annotations

from roxy.policy.matcher import TemplateIndex, split_path
from roxy.policy.seed import load_seed

INDEX = TemplateIndex(load_seed().rows)


def found(host: str, method: str, path: str) -> str | None:
    row = INDEX.find(host, method, path)
    return None if row is None else row.id


def test_split_path() -> None:
    assert split_path("/v1/Users/") == ("v1", "users")
    assert split_path("/") == ()
    assert split_path("") == ()


def test_letter_case_and_trailing_slash_do_not_matter() -> None:
    assert found("auth.roblox.com", "POST", "/V1/Logout/") == "auth:POST:/v1/logout"
    assert found("AUTH.roblox.com", "post", "/v1/LOGOUT") == "auth:POST:/v1/logout"


def test_literal_beats_parameter() -> None:
    assert found("users.roblox.com", "GET", "/v1/users/authenticated") == "users:GET:/v1/users/authenticated"
    assert found("users.roblox.com", "GET", "/v1/users/42") == "users:GET:/v1/users/{userId}"


def test_head_uses_the_get_row() -> None:
    assert found("users.roblox.com", "HEAD", "/v1/users/42") == "users:GET:/v1/users/{userId}"


def test_colon_verbs() -> None:
    assert found("apis.roblox.com", "POST", "/toolbox-service/v2/assets:search") == (
        "apis:POST:/toolbox-service/v2/assets:search"
    )
    archive = found("apis.roblox.com", "POST", "/assets/v1/assets/55:archive")
    assert archive is not None
    assert archive.endswith("{assetId}:archive")


def test_a_parameter_value_cannot_escape_its_row() -> None:
    # A userId holding a colon or odd characters still lands on the BLOCK row.
    path = "/v1/users/1:2/recovery-codes/regenerate"
    assert found("twostepverification.roblox.com", "POST", path) == (
        "twostepverification:POST:/v1/users/{userId}/recovery-codes/regenerate"
    )


def test_wrong_method_or_segment_count_is_unknown() -> None:
    assert found("users.roblox.com", "DELETE", "/v1/users/42") is None
    assert found("users.roblox.com", "GET", "/v1/users/42/extra/deep") is None
    assert found("nothing.roblox.com", "GET", "/v1/users/42") is None


def test_spec_host_suffix_paths_are_clean() -> None:
    assert found("auth.roblox.com", "GET", "/v1/metadata") == "auth:GET:/v1/metadata"
    assert found("friends.roblox.com", "GET", "/v1/metadata") == "friends:GET:/v1/metadata"
