"""Key spread (parity row 65, CACHE-KEYSPLIT evidence; v1 smoke 3428-3473; v1 bug B9 fixed)."""

from __future__ import annotations

from roxy.cache.spread import SpreadRow, compute_spread, rows_from_db


def _row(path: str, params: list[tuple[str, str]], hits: int = 0, method: str = "GET") -> SpreadRow:
    return SpreadRow(method, "games.roblox.com", path, tuple(params), hits, 100)


def test_cache_buster_is_suspect_like_v1_smoke() -> None:
    rows = [_row("v1/games/9583680112/votes", [("t", str(1000 + n))]) for n in range(6)]
    [group] = compute_spread(rows)
    assert group.entries == 6
    assert group.hits == 0
    assert group.suspect
    assert group.suspect_param == "t"
    assert group.varying[0].name == "t"
    assert group.varying[0].values == 6
    assert group.as_dict()["Varying"][0]["Values"] == 6


def test_meaningful_params_with_hits_are_not_suspect() -> None:
    rows = [_row("v1/games/votes", [("universeIds", str(n))], hits=5) for n in range(10)]
    [group] = compute_spread(rows)
    assert not group.suspect
    assert group.suspect_param == "universeIds"  # v1 reports the top parameter either way


def test_small_groups_and_parameterless_groups_are_not_suspect() -> None:
    few = [_row("v1/a", [("t", str(n))]) for n in range(4)]
    plain = [_row("v1/b", []) for _ in range(10)]
    groups = {g.path: g for g in compute_spread(few + plain)}
    assert not groups["v1/a"].suspect
    assert not groups["v1/b"].suspect
    assert groups["v1/b"].suspect_param == ""


def test_large_groups_can_still_be_suspect_b9_fixed() -> None:
    """v1 capped distinct values at 501, so 627+ distinct entries could never be Suspect."""
    rows = [_row("v1/busted", [("cb", str(n))]) for n in range(2000)]
    [group] = compute_spread(rows, max_values=500)
    assert group.varying[0].saturated
    assert group.suspect


def test_thresholds_are_parameters_and_order_is_suspect_first() -> None:
    suspect = [_row("v1/x", [("t", str(n))]) for n in range(5)]
    bigger = [_row("v1/y", [("id", "1")]) for _ in range(50)]
    groups = compute_spread(suspect + bigger)
    assert groups[0].path == "v1/x"
    assert groups[0].suspect
    assert not compute_spread(suspect, min_entries=6)[0].suspect
    assert compute_spread(suspect + bigger, limit=1) == groups[:1]


def test_rows_from_db_decodes_params_json() -> None:
    raw = [
        ("GET", "games.roblox.com", "v1/x", '{"params":[["t","1"]],"stripped":[]}', 3, 50),
        ("GET", "h", "p", "{bad", 0, 1),
    ]
    rows = rows_from_db(raw)
    assert rows[0].params == (("t", "1"),)
    assert rows[0].hits == 3
    assert rows[1].params == ()
