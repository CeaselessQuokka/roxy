"""Tables for the admin API (DESIGN.md section 13, plan row 89): the spec and its sort allowlist, paging bounds,
in-memory paging, the answer shape, read model pages, and reading every page for an export."""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.api import common
from roxy.admin.api.common import (
    ApiError,
    Column,
    TableQuery,
    TableSpec,
    check_table_query,
    collect_pages,
    page_rows,
    table_answer,
    table_from_read_model,
    table_params,
)
from roxy.metrics import queries

SPEC = TableSpec(
    name="endpoints",
    columns=(
        Column("key", "Endpoint", "The endpoint template."),
        Column("requests", "Requests", "Every request.", "requests"),
        Column("p95_ms", "p95", "95th percentile latency.", "ms"),
        Column("note", "Note", sortable=False),
    ),
    default_sort="requests",
    extra_sort_keys=("hit_ratio",),
)


def query(**kwargs: Any) -> TableQuery:
    base: dict[str, Any] = {"page": 1, "page_size": 25, "sort": None, "order": None, "q": None}
    base.update(kwargs)
    return check_table_query(SPEC, **base)


def refused(**kwargs: Any) -> dict[str, str]:
    with pytest.raises(ApiError) as caught:
        query(**kwargs)
    assert caught.value.status_code == 422
    assert caught.value.error_code == "invalid_table_query"
    return caught.value.error_fields


def test_spec_rules() -> None:
    assert SPEC.sortable == frozenset({"key", "requests", "p95_ms", "hit_ratio"})
    assert SPEC.columns_info()[1] == {
        "key": "requests",
        "label": "Requests",
        "help": "Every request.",
        "unit": "requests",
    }
    with pytest.raises(ValueError):
        TableSpec("Bad Name", SPEC.columns, "requests")
    with pytest.raises(ValueError):
        TableSpec("dupes", (Column("a", "A"), Column("a", "A again")), "a")
    with pytest.raises(ValueError):
        TableSpec("unsortable", SPEC.columns, "note")


def test_defaults_and_choices() -> None:
    assert query() == TableQuery(1, 25, "requests", "desc", "")
    chosen = query(page=3, page_size=250, sort="hit_ratio", order="asc", q="  games  ")
    assert chosen == TableQuery(3, 250, "hit_ratio", "asc", "games")
    assert (chosen.offset, chosen.descending) == (500, False)
    assert common.PAGE_SIZES == (10, 25, 50, 100, 250)


def test_paging_and_sorting_bounds() -> None:
    assert set(refused(page=0)) == {"page"}
    assert set(refused(page=common.MAX_PAGE + 1)) == {"page"}
    assert set(refused(page_size=20)) == {"page_size"}
    assert set(refused(sort="note")) == {"sort"}  # a column that is not sortable
    assert set(refused(sort="requests; DROP TABLE dims")) == {"sort"}
    assert set(refused(order="up")) == {"order"}
    assert set(refused(q="x" * (common.MAX_SEARCH_CHARS + 1))) == {"q"}
    assert set(refused(page=-1, page_size=1, sort="x", order="x")) == {"page", "page_size", "sort", "order"}


def test_metrics_page_is_the_same_request() -> None:
    page = query(page=2, page_size=50, sort="p95_ms", order="asc", q="games").metrics_page()
    assert page == queries.Page(page=2, size=50, sort="p95_ms", descending=False, search="games")
    assert page.checked() == page


ROWS: list[dict[str, Any]] = [
    {"key": "b", "requests": 5, "p95_ms": None, "note": "Games"},
    {"key": "a", "requests": 9, "p95_ms": 30.0, "note": "users"},
    {"key": "C", "requests": 5, "p95_ms": 10.0, "note": "games too"},
    {"key": "d", "requests": None, "p95_ms": 20.0, "note": ""},
]


def test_page_rows_sorts_missing_values_last_in_both_orders() -> None:
    items, total = page_rows(ROWS, query(sort="requests", order="desc"))
    assert total == 4
    assert [r["key"] for r in items] == ["a", "b", "C", "d"]  # ties keep their order; None last
    items, _ = page_rows(ROWS, query(sort="requests", order="asc"))
    assert [r["key"] for r in items] == ["b", "C", "a", "d"]
    items, _ = page_rows(ROWS, query(sort="key", order="asc"))
    assert [r["key"] for r in items] == ["a", "b", "C", "d"]  # text sorts without regard to case
    items, _ = page_rows(ROWS, query(sort="p95_ms", order="asc"))
    assert [r["key"] for r in items] == ["C", "d", "a", "b"]


def test_page_rows_search_and_pages() -> None:
    items, total = page_rows(ROWS, query(q="GAMES"), search_keys=("note",))
    assert total == 2
    assert {r["key"] for r in items} == {"b", "C"}
    assert page_rows(ROWS, query(q="games"))[1] == 2  # no search keys: every value of a row is searched
    assert page_rows(ROWS, query(q="users"), search_keys=("key",))[1] == 0
    many = [{"key": f"k{n:03d}", "requests": n, "note": ""} for n in range(60)]
    second, total = page_rows(many, query(page=2, page_size=25, sort="requests", order="asc"))
    assert total == 60
    assert [r["requests"] for r in second] == list(range(25, 50))
    beyond, total = page_rows(many, query(page=9, page_size=10))
    assert (beyond, total) == ([], 60)


def test_table_answer_shape() -> None:
    tq = query(page=2, page_size=10, sort="key", order="asc")
    answer = table_answer(SPEC, tq, [{"key": "x"}], 11)
    assert answer == {
        "items": [{"key": "x"}],
        "total": 11,
        "page": 2,
        "page_size": 10,
        "sort": "key",
        "order": "asc",
        "columns": SPEC.columns_info(),
    }
    paged = {"total": 3, "page": 1, "size": 25, "sort": "requests", "descending": True, "rows": [{"key": "a"}]}
    assert table_from_read_model(SPEC, query(), paged)["items"] == [{"key": "a"}]
    assert table_from_read_model(SPEC, query(), paged)["total"] == 3


async def test_table_params_dependency() -> None:
    dependency = table_params(SPEC)
    assert dependency.__name__ == "table_params_endpoints"
    assert await dependency() == TableQuery(1, 25, "requests", "desc", "")
    assert await dependency(page=2, page_size=10, sort="key", order="asc", q="x") == TableQuery(
        2, 10, "key", "asc", "x"
    )
    with pytest.raises(ApiError):
        await dependency(page_size=11)


async def test_collect_pages_reads_until_the_total_or_the_cap() -> None:
    data = list(range(612))
    calls: list[tuple[int, int]] = []

    async def fetch(page: int, size: int) -> tuple[list[int], int]:
        calls.append((page, size))
        return data[(page - 1) * size : page * size], len(data)

    rows, total = await collect_pages(fetch)
    assert (rows, total) == (data, 612)
    assert calls == [(1, 250), (2, 250), (3, 250)]
    capped, total = await collect_pages(fetch, page_size=100, max_rows=150)
    assert (capped, total) == (data[:150], 612)

    async def shrinking(page: int, size: int) -> tuple[list[int], int]:
        return ([1] if page == 1 else []), 99  # the total said more, the data ran out

    assert await collect_pages(shrinking) == ([1], 99)
