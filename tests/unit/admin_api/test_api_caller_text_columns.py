"""Every admin API table declares its caller-text columns (DESIGN 13.1 `caller_text`; review round 4, secfix-5).

What this is
    A discovery test over every `TableSpec` of the admin API areas, and a unit test of how a table answer lists the
    columns. `Column(caller_text=True)` marks a column holding text a caller chose; `common.table_answer` lists the
    marked columns in the answer's `caller_text`, and `common.add_caller_text` adds a route's extra fields (nested
    ones, dotted) without dropping them.

Why it exists
    The P11 pages read `caller_text` to decide what must never be rendered as markup (plan 9.16). Finding secfix-5:
    the Security probe log (written by any scanner on the internet) and the Protection attempts tabs listed caller
    paths and User-Agents with no `caller_text` at all, because each route declared its list by hand. A column
    whose key is in `common.CALLER_TEXT_COLUMN_KEYS` (a path, a probed URL, a User-Agent, a username, a template,
    an error or event detail) now has to carry the mark wherever it appears, so a new table cannot forget it.

How it works
    Imports every module of `roxy.admin.api`, collects the module-level `TableSpec` objects and checks the marks.

What to read next
    `roxy/admin/api/common.py` (`Column`, `CALLER_TEXT_COLUMN_KEYS`, `table_answer`, `add_caller_text`),
    `tests/integration/admin_api/test_r4_secfix_caller_text.py` (the two answers through the real app).
"""

from __future__ import annotations

import importlib
import pkgutil

import roxy.admin.api as api_package
from roxy.admin.api.common import (
    CALLER_TEXT_COLUMN_KEYS,
    Column,
    TableQuery,
    TableSpec,
    add_caller_text,
    table_answer,
)


def _specs() -> list[tuple[str, TableSpec]]:
    found: dict[int, tuple[str, TableSpec]] = {}
    for info in pkgutil.iter_modules(api_package.__path__):
        module = importlib.import_module(f"{api_package.__name__}.{info.name}")
        for name, value in vars(module).items():
            if isinstance(value, TableSpec):
                found.setdefault(id(value), (f"{info.name}.{name}", value))
    return list(found.values())


def test_every_caller_text_column_of_every_table_is_declared() -> None:
    specs = _specs()
    assert len(specs) >= 40, [name for name, _spec in specs]  # the discovery found the areas' tables
    missing = [
        f"{name}.{column.key}"
        for name, spec in specs
        for column in spec.columns
        if column.key in CALLER_TEXT_COLUMN_KEYS and not column.caller_text
    ]
    assert missing == [], f"caller-text columns without Column(caller_text=True): {missing}"


def test_the_tables_secfix_5_named_declare_their_caller_text() -> None:
    by_name = {spec.name: spec for _name, spec in _specs()}
    assert {"reason", "target", "path", "user_agent"} <= set(by_name["probes"].caller_text)
    assert {"reason"} <= set(by_name["probe_summary"].caller_text)
    assert {"username"} <= set(by_name["admin_logins"].caller_text)
    assert {"path", "methods"} <= set(by_name["refusal_attempts"].caller_text)
    assert {"directive", "blocked", "document", "source"} <= set(by_name["csp_reports"].caller_text)


def test_a_table_answer_lists_its_caller_text_and_routes_only_add_to_it() -> None:
    spec = TableSpec(
        name="sample",
        columns=(
            Column("path", "Path", caller_text=True),
            Column("count", "Count"),
            Column("ua", "UA", caller_text=True),
        ),
        default_sort="count",
    )
    answer = table_answer(spec, TableQuery(sort="count"), [], 0)
    assert answer["caller_text"] == ["path", "ua"]
    assert add_caller_text(answer, ["ua", "detail.error"])["caller_text"] == ["path", "ua", "detail.error"]
    plain = TableSpec(name="plain", columns=(Column("count", "Count"),), default_sort="count")
    assert "caller_text" not in table_answer(plain, TableQuery(sort="count"), [], 0)
    assert add_caller_text({}, ("name",)) == {"caller_text": ["name"]}
