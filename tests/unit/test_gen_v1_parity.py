"""Tests of `scripts/gen_v1_parity.py` and of the committed `tests/V1_PARITY.md` (plan 19.11).

What this is
    Unit tests of the parity table generator: the enumeration of the v1 suites (by AST for the smoke suite, by line
    for the deploy suite), the Markdown cell handling, the merge that keeps the human columns, the `--check` rules
    (empty cells, reasons without a plan section, malformed or unknown test ids, a stale table) and the open findings
    view. Two tests read the real repository: every v1 check has exactly one row, and every cited test exists.

Why it exists
    The table is only worth something while it is complete and honest. If the generator silently skipped a check,
    lost what someone wrote when a v1 line moved, or accepted a test id that no longer exists, P14 would sign off on
    a parity argument with holes in it.

How it works
    The script is loaded from its path with `importlib` (scripts are not a package). Synthetic v1 files go to a
    temporary root, so `main()` runs end to end without touching the repository. The repository tests compare the
    table with an independent AST walk of `tests/smoke_test.py` and resolve every cited id to a function definition
    with `ast` (no import, no pytest collection, so they stay fast).

What to read next
    `scripts/gen_v1_parity.py`, then `tests/V1_PARITY.md` and `tests/parity/`.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "gen_v1_parity.py"


def _load() -> ModuleType:
    name = "gen_v1_parity_under_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gen = _load()

SMOKE = """import os

def check(name, condition, detail=""):
    pass

print("== First section ==")
check("first", True)
check(f"second {1}", True)
for key in ("a", "b"):
    check(f"loop {key}", True)

def helper():
    check("inside a helper", True)

print("\\n== Second | section ==")
check("first", True)
check("with | pipe and `tick`", True)
"""

DEPLOY = """#!/bin/bash
check() { :; }
echo "== Scenario one =="
check "exits 0" "1"
check "says \\"hello\\"" "1"
echo ""
echo "== Scenario two =="
  check "exits 0" "1"
echo "========================================"
"""


def make_root(tmp_path: Path, smoke: str = SMOKE, deploy: str = DEPLOY) -> Path:
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "smoke_test.py").write_text(smoke, encoding="utf-8")
    (root / "tests" / "deploy_test.sh").write_text(deploy, encoding="utf-8")
    return root


def fill(rows: list[Any], coverage: str = "`tests/unit/test_x.py::test_ok`") -> None:
    for row in rows:
        row.what = f"What {row.check.location} checks."
        row.coverage = coverage


# ------------------------------------------------------------------------------------------------ enumeration


def test_smoke_checks_by_line_section_function_and_label() -> None:
    checks = gen.smoke_checks(SMOKE)
    assert [(c.line, c.section_id, c.section, c.function, c.label) for c in checks] == [
        (7, "S001", "First section", "", "first"),
        (8, "S001", "First section", "", 'f"second {1}"'),
        (10, "S001", "First section", "", 'f"loop {key}"'),
        (13, "S001", "First section", "helper", "inside a helper"),
        (16, "S002", "Second | section", "", "first"),
        (17, "S002", "Second | section", "", "with | pipe and `tick`"),
    ]
    assert checks[3].location == "smoke_test.py:13"
    assert checks[3].location_text == "smoke_test.py:13 in helper()"


def test_deploy_checks_by_scenario() -> None:
    checks = gen.deploy_checks(DEPLOY)
    assert [(c.line, c.section_id, c.section, c.label) for c in checks] == [
        (4, "D1", "Scenario one", "exits 0"),
        (5, "D1", "Scenario one", 'says "hello"'),
        (8, "D2", "Scenario two", "exits 0"),
    ]


def test_every_check_of_the_real_v1_suites_has_one_row() -> None:
    checks = gen.enumerate_checks(REPO)
    smoke = [c for c in checks if c.file == "smoke_test.py"]
    deploy = [c for c in checks if c.file == "deploy_test.sh"]
    tree = ast.parse((REPO / "tests" / "smoke_test.py").read_text(encoding="utf-8"))
    independent = sorted(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "check"
    )
    assert [c.line for c in smoke] == independent
    assert len(smoke) == 735  # .remake/v1notes/smoke.md section 1: 735 call sites (759 runs)
    assert len({c.section_id for c in smoke}) == 117
    assert len(deploy) == 46
    assert len({c.section_id for c in deploy}) == 9
    counts = gen.counts_by_section(gen.Row(c) for c in smoke)
    assert (counts["S001"], counts["S067"], counts["S117"]) == (4, 28, 11)


# ------------------------------------------------------------------------------------------------ cells


@pytest.mark.parametrize(
    "text", ["plain", "a | b", "`x`", "``double``", "ends with `", "pipe\\|escaped", "", "`a|b` and c"]
)
def test_label_cells_round_trip(text: str) -> None:
    cell = gen.escape_cell(gen.code_span(text))
    line = f"| smoke_test.py:1 | {cell} | what | `tests/a.py::test_b` |"
    cells = gen.split_cells(line)
    assert len(cells) == 4
    assert gen.unescape_cell(gen.read_code_span(cells[1])) == text


def test_escape_cell_makes_one_line_and_escapes_every_pipe() -> None:
    assert gen.escape_cell("a\nb | c \\| d") == "a b \\| c \\\\| d"
    assert gen.unescape_cell(gen.escape_cell("a\nb | c \\| d")) == "a b | c \\| d"


# ------------------------------------------------------------------------------------------------ merge


def test_render_and_parse_round_trip(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    merged = gen.merge(gen.enumerate_checks(root), [])
    fill(merged.rows)
    merged.rows[0].coverage = "intentionally changed: a | b (plan 7.13); covered by `tests/unit/test_x.py::test_ok`"
    parsed = gen.parse_table(gen.render(merged.rows))
    assert [(p.location, p.label, p.what, p.coverage) for p in parsed] == [
        (r.check.location, r.check.label, r.what, r.coverage) for r in merged.rows
    ]
    assert parsed[4].section == "Second | section"


def test_merge_keeps_human_columns_and_follows_moved_lines(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    first = gen.merge(gen.enumerate_checks(root), [])
    fill(first.rows)
    table = gen.render(first.rows)
    shifted = SMOKE.replace('print("== First section ==")', '# a new comment line\nprint("== First section ==")')
    shifted = shifted.replace('check("first", True)\ncheck(f"second', 'check("first", True)\n\ncheck(f"second', 1)
    moved_root = make_root(tmp_path / "moved", smoke=shifted)
    again = gen.merge(gen.enumerate_checks(moved_root), gen.parse_table(table))
    assert [row.what for row in again.rows] == [row.what for row in first.rows]  # nothing people wrote is lost
    assert ("smoke_test.py:7", "smoke_test.py:8") in again.moved
    assert again.dropped == []
    # The two checks labeled "first" in different sections keep their own rows.
    assert again.rows[4].what == first.rows[4].what


def test_merge_drops_rows_of_removed_checks_and_leaves_new_rows_empty(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    first = gen.merge(gen.enumerate_checks(root), [])
    fill(first.rows)
    smaller = SMOKE.replace('check("with | pipe and `tick`", True)\n', 'check("brand new", True)\n')
    again = gen.merge(
        gen.enumerate_checks(make_root(tmp_path / "b", smoke=smaller)), gen.parse_table(gen.render(first.rows))
    )
    assert [row.label for row in again.dropped] == ["with | pipe and `tick`"]
    new = [row for row in again.rows if row.check.label == "brand new"]
    assert [(row.what, row.coverage) for row in new] == [("", "")]


# ------------------------------------------------------------------------------------------------ the check


def test_problems_catch_every_kind_of_incomplete_cell(tmp_path: Path) -> None:
    rows = gen.merge(gen.enumerate_checks(make_root(tmp_path)), []).rows
    fill(rows)
    rows[0].what = " "
    rows[1].coverage = ""
    rows[2].coverage = "intentionally changed: because it is nicer"
    rows[3].coverage = "covered by the smoke test"
    rows[4].coverage = "`tests/unit/test_x.py::test_ok` and more words"
    rows[5].coverage = "`tests/unit/test_x.py::test_ok[param]`, `tests/unit/test_x.py::test_gone`"
    found = gen.problems(rows, {"tests/unit/test_x.py::test_ok"})
    text = "\n".join(found)
    assert "smoke_test.py:7: empty 'What it checks' cell" in text
    assert "smoke_test.py:8: empty 'v2 coverage' cell" in text
    assert "smoke_test.py:10: the reason names no plan section" in text
    assert "smoke_test.py:13: cite a test id" in text
    assert "smoke_test.py:16: a covered cell must hold only backticked test ids" in text
    assert "is not a test id" in text  # parameters are not part of an id
    assert "smoke_test.py:17: tests/unit/test_x.py::test_gone is not in the pytest collection" in text
    assert len(found) == 7


@pytest.mark.parametrize(
    "reason",
    [
        "the 7.13 table",
        "constraint C1",
        "owner decision D5",
        "principle P9",
        "row 26",
        "rows 21, 34",
        "plan section 14",
        "DESIGN 13",
        "recorded in CHANGES.md",
    ],
)
def test_reasons_that_name_a_plan_section_are_accepted(reason: str, tmp_path: Path) -> None:
    rows = gen.merge(gen.enumerate_checks(make_root(tmp_path)), []).rows
    fill(rows, coverage=f"intentionally changed: {reason}")
    assert gen.problems(rows, set()) == []


def test_main_writes_then_checks_against_a_collection_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = make_root(tmp_path)
    assert gen.main(["--root", str(root)]) == 0  # first run: rows with empty human cells
    collection = tmp_path / "collected.txt"
    collection.write_text("tests/unit/test_x.py::test_ok[a]\ntests/unit/test_x.py::test_ok[b]\n", encoding="utf-8")
    assert gen.main(["--root", str(root), "--check", "--collection", str(collection)]) == 1
    assert "empty 'What it checks' cell" in capsys.readouterr().out
    table = root / gen.TABLE_FILE
    rows = gen.merge(gen.enumerate_checks(root), gen.parse_table(table.read_text(encoding="utf-8"))).rows
    fill(rows)
    table.write_text(gen.render(rows), encoding="utf-8")
    assert gen.main(["--root", str(root), "--check", "--collection", str(collection)]) == 0
    assert "0 problems" in capsys.readouterr().out
    collection.write_text("tests/unit/test_x.py::test_other\n", encoding="utf-8")
    assert gen.main(["--root", str(root), "--check", "--collection", str(collection)]) == 1
    assert "is not in the pytest collection" in capsys.readouterr().out
    assert gen.main(["--root", str(root)]) == 0  # a regeneration keeps the filled cells
    assert gen.main(["--root", str(root), "--check", "--no-collection"]) == 0


def test_check_refuses_a_stale_table(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = make_root(tmp_path)
    rows = gen.merge(gen.enumerate_checks(root), []).rows
    fill(rows)
    (root / gen.TABLE_FILE).write_text(gen.render(rows), encoding="utf-8")
    (root / "tests" / "smoke_test.py").write_text(SMOKE + 'check("added later", True)\n', encoding="utf-8")
    assert gen.main(["--root", str(root), "--check", "--no-collection"]) == 1
    out = capsys.readouterr().out
    assert "is not up to date" in out
    assert "empty 'v2 coverage' cell" in out


def test_a_failed_collection_is_an_error_not_a_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = make_root(tmp_path)
    assert gen.main(["--root", str(root), "--check", "--collection", str(tmp_path / "missing.txt")]) == 2
    assert "error:" in capsys.readouterr().err


# ------------------------------------------------------------------------------------------------ findings

PARITY_TEST = """import pytest

@pytest.mark.xfail(strict=True, reason="finding parity-7: the thing is missing")
async def test_pinned() -> None:
    assert False

@pytest.mark.xfail(reason="not strict, not a finding")
def test_loose() -> None:
    assert False

def test_plain() -> None:
    assert True
"""


def test_strict_xfails_pin_rows_and_show_as_open_findings(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    (root / "tests" / "parity").mkdir()
    (root / "tests" / "parity" / "test_v1_demo.py").write_text(PARITY_TEST, encoding="utf-8")
    xfails = gen.strict_xfails(root)
    assert xfails == {"tests/parity/test_v1_demo.py::test_pinned": "finding parity-7: the thing is missing"}
    rows = gen.merge(gen.enumerate_checks(root), []).rows
    fill(rows, coverage="`tests/parity/test_v1_demo.py::test_plain`")
    rows[0].coverage = "`tests/parity/test_v1_demo.py::test_pinned`"
    rows[1].coverage = "intentionally changed: plan 7.13; covered by `tests/parity/test_v1_demo.py::test_pinned`"
    summary = gen.summarize(rows, xfails)
    assert (summary.covered_parity, summary.changed, summary.open_findings) == (len(rows) - 1, 1, 1)
    text = gen.render(rows, xfails)
    assert "| parity-7 | `tests/parity/test_v1_demo.py::test_pinned` | smoke_test.py:7 |" in text
    assert gen.render(rows, {}).count("None: every covered row passes.") == 1


# ------------------------------------------------------------------------------------------------ the real table


def _defined(test_id: str) -> bool:
    """True when `tests/...py::name` (or `::Class::name`) is a function defined in that file."""
    path, *names = test_id.split("::")
    file = REPO / path
    if not file.is_file():
        return False
    body: list[ast.stmt] = ast.parse(file.read_text(encoding="utf-8")).body
    for name in names[:-1]:
        classes = [n for n in body if isinstance(n, ast.ClassDef) and n.name == name]
        if not classes:
            return False
        body = classes[0].body
    return any(isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == names[-1] for n in body)


def test_the_committed_table_is_complete_current_and_cites_real_tests() -> None:
    merged, text = gen.build(REPO)
    assert (REPO / gen.TABLE_FILE).read_text(encoding="utf-8") == text, "run python scripts/gen_v1_parity.py"
    assert merged.dropped == []
    assert gen.problems(merged.rows, None) == []
    cited = {test_id for row in merged.rows for test_id in gen.coverage_ids(row.coverage)}
    missing = sorted(test_id for test_id in cited if not _defined(test_id))
    assert missing == []
    assert gen.summarize(merged.rows).empty == 0


def test_every_strict_xfail_in_tests_parity_names_a_finding_and_is_cited() -> None:
    xfails = gen.strict_xfails(REPO)
    merged, _ = gen.build(REPO)
    cited = {test_id for row in merged.rows for test_id in gen.coverage_ids(row.coverage)}
    for test_id, reason in xfails.items():
        assert gen.FINDING_RE.search(reason), (test_id, reason)
        assert test_id in cited, test_id
