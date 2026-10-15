"""Endpoint templating parity with v1 (`app/diagnostics.py` `_templatize`, parity row 74) and the vocabulary bound.

The worked examples come from .remake/v1notes/diagnostics.md section 5 (verified there by executing v1). The property
test compares `templatize` with a verbatim copy of the v1 functions on generated paths, including the edge cases the
notes call out (non-ASCII digits, uppercase hex, empty segments, 15 versus 16 hex characters).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from roxy.metrics import templating
from roxy.metrics.templating import OTHER, TEMPLATE_VERSION, VocabularyGate, template_for, templatize

REPO = Path(__file__).resolve().parents[3]

# --- verbatim copy of v1 app/diagnostics.py lines 14-71 (the code under comparison) ---------------------------------
_V1_NAMES = {
    "users": "userId",
    "user": "userId",
    "games": "gameId",
    "universes": "universeId",
    "universe": "universeId",
    "places": "placeId",
    "place": "placeId",
    "groups": "groupId",
    "group": "groupId",
    "assets": "assetId",
    "asset": "assetId",
    "badges": "badgeId",
    "badge": "badgeId",
    "bundles": "bundleId",
    "outfits": "outfitId",
    "items": "itemId",
    "passes": "passId",
    "gamepasses": "gamePassId",
    "servers": "serverId",
    "thumbnails": "thumbnailId",
}
_V1_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_V1_HEX = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_V1_TOKEN = re.compile(r"^[A-Za-z0-9_-]+$")


def _v1_is_id_segment(seg: str) -> bool:
    if seg.isdigit():
        return True
    if _V1_UUID.match(seg):
        return True
    if len(seg) >= 16 and _V1_HEX.match(seg):
        return True
    if len(seg) >= 24 and _V1_TOKEN.match(seg) and any(c.isdigit() for c in seg):  # noqa: SIM103 (verbatim v1)
        return True
    return False


def _v1_templatize(path: str) -> str:
    segments = path.split("/")
    out = []
    for i, seg in enumerate(segments):
        if _v1_is_id_segment(seg):
            prev = segments[i - 1].lower() if i > 0 else ""
            out.append("{" + _V1_NAMES.get(prev, "id") + "}")
        else:
            out.append(seg)
    return "/".join(out)


# ----------------------------------------------------------------------------------------------------------------------

V1_EXAMPLES = [
    ("avatar.roblox.com/v2/avatar/users/29371917/outfits", "avatar.roblox.com/v2/avatar/users/{userId}/outfits"),
    ("games.roblox.com/v1/games/9583680112/votes", "games.roblox.com/v1/games/{gameId}/votes"),
    ("users.roblox.com/v1/users", "users.roblox.com/v1/users"),
    ("thumbnails.roblox.com/v1/users/avatar-headshot", "thumbnails.roblox.com/v1/users/avatar-headshot"),
    ("games.roblox.com/v1/games/123/servers/Public", "games.roblox.com/v1/games/{gameId}/servers/Public"),
    ("games.roblox.com/v1/games/123/servers/0/abc", "games.roblox.com/v1/games/{gameId}/servers/{serverId}/abc"),
    ("groups.roblox.com/v1/groups/5/roles/77/users", "groups.roblox.com/v1/groups/{groupId}/roles/{id}/users"),
    ("x.roblox.com/v1/Users/55", "x.roblox.com/v1/Users/{userId}"),
    ("x.roblox.com/123/456", "x.roblox.com/{id}/{id}"),
    ("x.roblox.com/v1/users//55", "x.roblox.com/v1/users//{id}"),
    ("x.roblox.com/v1/thing/123e4567-e89b-12d3-a456-426614174000", "x.roblox.com/v1/thing/{id}"),
    ("x.roblox.com/v1/hash/0123456789abcdef", "x.roblox.com/v1/hash/{id}"),
    ("x.roblox.com/v1/hash/0123456789abcde", "x.roblox.com/v1/hash/0123456789abcde"),
    ("x.roblox.com/v1/tok/abcdefghijklmnopqrstuvw1", "x.roblox.com/v1/tok/{id}"),
    ("x.roblox.com/v1/tok/abcdefghijklmnopqrstuvwx", "x.roblox.com/v1/tok/abcdefghijklmnopqrstuvwx"),
    ("x.roblox.com/v1/a/-1", "x.roblox.com/v1/a/-1"),
    ("x.roblox.com/v1/gamepasses/9", "x.roblox.com/v1/gamepasses/{gamePassId}"),
]


@pytest.mark.parametrize(("path", "expected"), V1_EXAMPLES)
def test_v1_worked_examples(path: str, expected: str) -> None:
    assert templatize(path) == expected
    assert _v1_templatize(path) == expected  # the copy above really is v1


def test_placeholder_table_is_v1s() -> None:
    assert templating._ID_COLLECTION_NAMES == _V1_NAMES


def test_v1_copy_matches_the_v1_source() -> None:
    """Guard the verbatim copy: the names table in app/diagnostics.py must equal the one used here."""
    source = (REPO / "app" / "diagnostics.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_ID_COLLECTION_NAMES" for t in node.targets
        ):
            found = ast.literal_eval(node.value)
    assert found == _V1_NAMES


segment = st.one_of(
    st.from_regex(r"[0-9]{1,12}", fullmatch=True),
    st.from_regex(r"[0-9a-fA-F]{14,20}", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_-]{20,30}", fullmatch=True),
    st.uuids().map(str),
    st.uuids().map(lambda u: str(u).upper()),
    st.sampled_from([*sorted(_V1_NAMES), "v1", "v2", "", "Users", "GAMES", "٣٤", "-1", "abc"]),
    st.text(alphabet=st.characters(blacklist_categories=["Cs"], blacklist_characters="/"), max_size=12),
)


@settings(max_examples=400)
@given(st.lists(segment, min_size=1, max_size=8))
def test_templatize_equals_v1_on_generated_paths(parts: list[str]) -> None:
    path = "/".join(parts)
    assert templatize(path) == _v1_templatize(path)


def test_non_ascii_digits_are_ids_like_v1() -> None:
    assert templatize("x.roblox.com/v1/users/٣٤") == "x.roblox.com/v1/users/{userId}"


@pytest.mark.parametrize(
    ("host", "path", "expected"),
    [
        ("games.roblox.com", "/v1/games/123/votes", "games.roblox.com/v1/games/{gameId}/votes"),
        ("games.roblox.com", "v1/games/123/votes?x=1", "games.roblox.com/v1/games/{gameId}/votes"),
        ("games.roblox.com", "/v1/games/123/votes/", "games.roblox.com/v1/games/{gameId}/votes"),
        ("games.roblox.com", "games.roblox.com/v1/games/123", "games.roblox.com/v1/games/{gameId}"),
        ("games.roblox.com", "/", "games.roblox.com"),
        ("", "users.roblox.com/v1/users/1", "users.roblox.com/v1/users/{userId}"),
    ],
)
def test_template_for(host: str, path: str, expected: str) -> None:
    assert template_for(host, path) == expected


def test_template_length_is_bounded() -> None:
    long_path = "/".join("word" + str(i) + "x" for i in range(200))
    assert len(template_for("x.roblox.com", long_path)) == templating.MAX_TEMPLATE_CHARS


def test_template_version() -> None:
    assert TEMPLATE_VERSION == 1


def test_remap_templates_retemplates_examples() -> None:
    assert templating.remap_templates({"old/{x}": "a.roblox.com/v1/users/5?x=1"}) == {
        "old/{x}": "a.roblox.com/v1/users/{userId}"
    }


def test_vocabulary_gate_bounds_distinct_values() -> None:
    gate = VocabularyGate(3)
    assert [gate.admit(v) for v in ("a", "b", "a", "c", "d", "b")] == ["a", "b", "a", "c", OTHER, "b"]
    assert gate.rejected == 1
    gate.reset(["d", "e", "f", "g"])
    assert gate.admit("d") == "d"
    assert gate.admit("a") == OTHER  # the refresh keeps only the busiest names
    assert len(gate) == 3
    gate.reset(["x", OTHER, ""])
    assert len(gate) == 1
    assert gate.admit("y") == "y"
