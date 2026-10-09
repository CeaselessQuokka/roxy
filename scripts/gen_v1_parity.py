#!/usr/bin/env python3
"""Generate and check tests/V1_PARITY.md: every v1 smoke check and deploy check, and what covers it in v2.

What this is
    A command line tool for plan 19.11. `python scripts/gen_v1_parity.py` rewrites `tests/V1_PARITY.md`, a table
    with one row per v1 check: every `check(...)` call in `tests/smoke_test.py` (by its line, its section and the
    function around it) and every `check ...` line of the scenarios in `tests/deploy_test.sh`. Each row has the v1
    location, the v1 label, "What it checks" (one line) and "v2 coverage": the pytest ids that prove v2 keeps the
    behavior, or `intentionally changed: <reason and plan section>`. `--check` writes nothing and exits 1 when a
    cell is empty, a reason names no plan section, a test id is not in the pytest collection, or the table is not
    what a regeneration would write.

Why it exists
    v1 had about 750 smoke checks and the golden refusal tests cover only part of them, so a behavior that only the
    smoke suite tested could disappear unnoticed (plan C3, 19.11). The two human columns are the parity argument;
    the script makes sure that argument stays complete (a new or moved v1 check gets a row), honest (every cited
    test exists) and readable (a regeneration keeps what people wrote).

How it works
    - Enumeration. The smoke suite is parsed with `ast` (never imported: it runs itself on import). Every call to
      the name `check` is one row; its section is the last `print("== ... ==")` before it (ids S001, S002, ... in
      file order) and its function is the `def` around it, if any. The deploy suite is read line by line: every
      line that calls `check "..."` is one row and its scenario is the last `echo "== ... =="` (ids D1, D2, ...).
    - Merge. The existing table is parsed back; rows are matched by v1 location (`smoke_test.py:129`). A row whose
      line moved is matched by its file, section title, label and position among equal labels instead, so a
      reformat of the v1 file never loses what people wrote. Rows that match nothing are reported and dropped.
    - Cells. A coverage cell is either a comma separated list of backticked test ids (`tests/...py::test_name`,
      without parameters) or starts with `intentionally changed:`. Any backticked text with `::` in it, in either
      form, is a test id and must exist. A reason must name a plan section (`7.13`, `C1`, `row 26`, `D5`, `P9`,
      `section 14`, `DESIGN 13`, `CHANGES.md` and similar).
    - Collection. `--check` runs `pytest --collect-only -q tests` (or reads `--collection FILE`, one id per line)
      and compares ids with their `[parameters]` removed.
    - Open findings. A test in `tests/parity/` marked `pytest.mark.xfail(strict=True, reason="finding parity-N:
      ...")` pins a v1 behavior v2 lacks. The script reads those markers with `ast` and lists, per finding, the
      rows that cite the test; the summary counts them, so a fix (which removes the marker) shows in the table.
    - Output is deterministic (sorted by file and line), so `--check` compares byte for byte.

What to read next
    `tests/V1_PARITY.md` (the result), `.remake/v1notes/smoke.md` (the reading of every v1 check this table was
    first filled from) and `tests/parity/` (the v2 tests written for v1 behaviors nothing else covered).
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SMOKE_FILE = "tests/smoke_test.py"
DEPLOY_FILE = "tests/deploy_test.sh"
TABLE_FILE = "tests/V1_PARITY.md"

CHANGED_PREFIX = "intentionally changed:"
"""How a coverage cell says v2 does this differently on purpose (plan 19.11)."""

PARITY_TESTS_PREFIX = "tests/parity/"
"""Tests written for this table; the summary counts the rows they cover apart from the older tests."""

TEST_ID_RE = re.compile(r"`([^`]*::[^`]*)`")
"""A backticked test id inside a coverage cell."""

ID_SHAPE_RE = re.compile(r"^tests/[\w./-]+\.py(::\w+)+$")
"""What a cited test id must look like: a path under tests/ and one or more `::name` parts, no parameters."""

PLAN_SECTION_RE = re.compile(
    r"(\b\d{1,2}\.\d{1,2}\b|\bC[1-7]\b|\bD\d{1,2}\b|\bP\d{1,2}\b|\brows? \d{1,3}\b|\bsection \d{1,2}\b"
    r"|\bDESIGN\b|CHANGES\.md|\bLEAD_NOTES\b|\bF\d{1,2}\b)"
)
"""A plan reference in an "intentionally changed" reason: a section number, a constraint, an owner decision, a
principle, a parity row, a DESIGN.md section or a CHANGES.md entry."""

LOCATION_RE = re.compile(r"^(?P<file>smoke_test\.py|deploy_test\.sh):(?P<line>\d+)")
"""The key part of the first cell of a table row."""

SMOKE_SECTION_RE = re.compile(r"^\s*=+\s*(?P<title>.*?)\s*=+\s*$")
DEPLOY_SECTION_RE = re.compile(r'^echo\s+"==\s*(?P<title>.*?)\s*=="\s*$')
DEPLOY_CHECK_RE = re.compile(r'^\s*check\s+"(?P<label>(?:[^"\\]|\\.)*)"')


# ------------------------------------------------------------------------------------------------ v1 checks


@dataclass(frozen=True)
class V1Check:
    """One check of a v1 suite: where it is and what the v1 author called it."""

    file: str  # "smoke_test.py" or "deploy_test.sh"
    line: int
    section_id: str  # "S001" for smoke sections, "D1" for deploy scenarios
    section: str  # the section title as printed by the suite
    section_line: int
    label: str  # the first argument of check(...), f-strings as written in the source
    function: str = ""  # the function around the call, "" at module level

    @property
    def location(self) -> str:
        """The merge key: file and line."""
        return f"{self.file}:{self.line}"

    @property
    def location_text(self) -> str:
        """What the first cell shows: the key, plus the function when the check is inside one."""
        return f"{self.location} in {self.function}()" if self.function else self.location


def _section_title(node: ast.AST) -> str | None:
    """The title of a `print("== Title ==")` call, else None."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"):
        return None
    if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
        return None
    text = node.args[0].value
    if "==" not in text:
        return None
    match = SMOKE_SECTION_RE.match(text.strip("\n"))
    return match.group("title") if match else None


def smoke_checks(source: str, file: str = "smoke_test.py") -> list[V1Check]:
    """Every `check(...)` call of the smoke suite, in file order, with its section and function."""
    tree = ast.parse(source)
    lines = source.splitlines()
    functions: list[tuple[int, int, str]] = []
    sections: list[tuple[int, str]] = []
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            functions.append((node.lineno, node.end_lineno or node.lineno, node.name))
        if not isinstance(node, ast.Call):
            continue
        title = _section_title(node)
        if title is not None:
            sections.append((node.lineno, title))
        if isinstance(node.func, ast.Name) and node.func.id == "check":
            calls.append(node)
    sections.sort()
    section_ids = {line: f"S{index:03d}" for index, (line, _title) in enumerate(sections, start=1)}
    checks: list[V1Check] = []
    for call in sorted(calls, key=lambda c: c.lineno):
        before = [entry for entry in sections if entry[0] < call.lineno]
        section_line, title = before[-1] if before else (0, "(before the first section)")
        enclosing = [entry for entry in functions if entry[0] < call.lineno <= entry[1]]
        function = max(enclosing)[2] if enclosing else ""
        checks.append(
            V1Check(
                file=file,
                line=call.lineno,
                section_id=section_ids.get(section_line, "S000"),
                section=title,
                section_line=section_line,
                label=_label(call, lines),
                function=function,
            )
        )
    return checks


def _label(call: ast.Call, lines: Sequence[str]) -> str:
    """The first argument of a check call: a plain string as is, anything else as its source text."""
    if not call.args:
        return "(no label)"
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    segment = ast.get_source_segment("\n".join(lines), first)
    return " ".join((segment or "(label)").split())


def deploy_checks(source: str, file: str = "deploy_test.sh") -> list[V1Check]:
    """Every `check "label" ...` line of the deploy suite, with the scenario it belongs to."""
    checks: list[V1Check] = []
    section_id, section, section_line = "D0", "(before the first scenario)", 0
    count = 0
    for number, text in enumerate(source.splitlines(), start=1):
        heading = DEPLOY_SECTION_RE.match(text)
        if heading and heading.group("title").strip("= "):
            count += 1
            section_id, section, section_line = f"D{count}", heading.group("title"), number
            continue
        match = DEPLOY_CHECK_RE.match(text)
        if match:
            label = match.group("label").replace('\\"', '"')
            checks.append(V1Check(file, number, section_id, section, section_line, label))
    return checks


def enumerate_checks(root: Path) -> list[V1Check]:
    """Both suites, smoke first, each in file order."""
    smoke = (root / SMOKE_FILE).read_text(encoding="utf-8")
    deploy = (root / DEPLOY_FILE).read_text(encoding="utf-8")
    return smoke_checks(smoke) + deploy_checks(deploy)


# ------------------------------------------------------------------------------------------------ the table


@dataclass
class Row:
    """One table row: the generated columns and the two human ones."""

    check: V1Check
    what: str = ""
    coverage: str = ""


@dataclass(frozen=True)
class ParsedRow:
    """A row read back from an existing table."""

    location: str  # "smoke_test.py:129"
    file: str
    section: str
    label: str
    what: str
    coverage: str


def split_cells(line: str) -> list[str]:
    """The cells of a Markdown table line; `\\|` is a pipe inside a cell, not a separator."""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    cells: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body) and body[index + 1] == "|":
            current.append("\\|")
            index += 2
            continue
        if char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    cells.append("".join(current).strip())
    return cells


def escape_cell(text: str) -> str:
    """Text safe for one table cell: one line, every pipe escaped (also inside code spans, as GFM requires).

    Every `|` becomes `\\|`, even one after a backslash, so `unescape_cell` gives back exactly the text it got."""
    flat = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return flat.replace("|", "\\|")


def unescape_cell(text: str) -> str:
    return text.replace("\\|", "|")


def code_span(text: str) -> str:
    """`text` as an inline code span whose fence is longer than any backtick run inside it."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def read_code_span(text: str) -> str:
    """The inverse of `code_span` (plain text is returned as it is)."""
    match = re.fullmatch(r"(`+)(.*)\1", text.strip(), flags=re.DOTALL)
    if not match:
        return text.strip()
    inner = match.group(2)
    if len(inner) >= 2 and inner.startswith(" ") and inner.endswith(" "):
        inner = inner[1:-1]
    return inner


def parse_table(text: str) -> list[ParsedRow]:
    """Every data row of an existing V1_PARITY.md, with the section heading it sits under."""
    rows: list[ParsedRow] = []
    section = ""
    for line in text.splitlines():
        heading = re.match(r"^###\s+[SD]\d+\s+(?P<title>.*?)\s+\((?:smoke_test\.py|deploy_test\.sh) line \d+\)$", line)
        if heading:
            section = unescape_cell(heading.group("title"))
            continue
        if not line.startswith("|"):
            continue
        cells = split_cells(line)
        if len(cells) < 4:
            continue
        key = LOCATION_RE.match(cells[0])
        if key is None:
            continue
        rows.append(
            ParsedRow(
                location=f"{key.group('file')}:{key.group('line')}",
                file=key.group("file"),
                section=section,
                label=unescape_cell(read_code_span(cells[1])),
                what=unescape_cell(cells[2]),
                coverage=unescape_cell(cells[3]),
            )
        )
    return rows


@dataclass
class MergeResult:
    rows: list[Row]
    moved: list[tuple[str, str]] = field(default_factory=list)  # (old location, new location)
    dropped: list[ParsedRow] = field(default_factory=list)


def _label_keys(items: Iterable[tuple[str, str, str]]) -> list[tuple[str, str, str, int]]:
    """(file, section, label, n): the n-th row with that file, section and label, counting from 0."""
    seen: Counter[tuple[str, str, str]] = Counter()
    keys = []
    for item in items:
        keys.append((*item, seen[item]))
        seen[item] += 1
    return keys


def merge(checks: Sequence[V1Check], existing: Sequence[ParsedRow]) -> MergeResult:
    """Fresh rows for `checks`, carrying the human columns over by location, else by section and label."""
    by_location = {row.location: row for row in existing}
    by_label = dict(zip(_label_keys((r.file, r.section, r.label) for r in existing), existing, strict=True))
    used: set[str] = set()
    result = MergeResult(rows=[])
    label_keys = _label_keys((c.file, c.section, c.label) for c in checks)
    for check, label_key in zip(checks, label_keys, strict=True):
        old = by_location.get(check.location)
        if old is not None and old.label == check.label:
            used.add(old.location)
        else:
            old = by_label.get(label_key)
            if old is not None and old.location not in used:
                used.add(old.location)
                result.moved.append((old.location, check.location))
            else:
                old = None
        result.rows.append(Row(check, old.what if old else "", old.coverage if old else ""))
    result.dropped = [row for row in existing if row.location not in used]
    return result


# ------------------------------------------------------------------------------------------------ rendering

HEADER = """# v1 parity: every v1 smoke check and deploy check, and what covers it in v2

Plan 19.11 (and C3): every check of the v1 smoke suite (`tests/smoke_test.py`, one row per `check(...)` call,
by line, section and function) and of the v1 deploy test (`tests/deploy_test.sh`, one row per `check` line of each
scenario) has a row. "v2 coverage" names the pytest ids that prove v2 keeps the behavior, or says
`intentionally changed:` with the reason and the plan section that allows the change (most are recorded in
`CHANGES.md`).

This file is generated by `scripts/gen_v1_parity.py`. The columns "What it checks" and "v2 coverage" are written
by people and kept on every regeneration (matched by v1 location, or by section and label when a line moved).
`python scripts/gen_v1_parity.py --check` fails on an empty cell, on a reason without a plan section, on a test id
that is not in the pytest collection, and on a table that a regeneration would change. Ids are written without
their parameters; the v2 tests written for rows nothing else covered live in `tests/parity/`.

A row whose test is a strict xfail in `tests/parity/` is a v1 behavior v2 does not have yet and no plan section
lets go: the test fails today for the reason its marker gives (a numbered finding) and turns into an error the day
the behavior is fixed. Whoever fixes it removes the marker and runs the script again, which moves the rows out of
"Open findings".
"""


def coverage_ids(cell: str) -> list[str]:
    """Every test id cited in a coverage cell, in order."""
    return [match.strip() for match in TEST_ID_RE.findall(cell)]


def is_changed(cell: str) -> bool:
    return cell.strip().lower().startswith(CHANGED_PREFIX)


FINDING_RE = re.compile(r"finding (?P<finding>parity-\d+)")


def _is_xfail_marker(node: ast.AST) -> bool:
    """`pytest.mark.xfail` (or `mark.xfail`) as written in a decorator."""
    return isinstance(node, ast.Attribute) and node.attr == "xfail"


def strict_xfails(root: Path) -> dict[str, str]:
    """`{test id: reason}` of every strict xfail test function in `tests/parity/` (read with `ast`, never run)."""
    found: dict[str, str] = {}
    folder = root / PARITY_TESTS_PREFIX
    for path in sorted(folder.glob("test_*.py")) if folder.is_dir() else []:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for decorator in node.decorator_list:
                if not (isinstance(decorator, ast.Call) and _is_xfail_marker(decorator.func)):
                    continue
                options = {kw.arg: kw.value for kw in decorator.keywords if kw.arg}
                strict = options.get("strict")
                if not (isinstance(strict, ast.Constant) and strict.value is True):
                    continue
                reason = options.get("reason")
                text = reason.value if isinstance(reason, ast.Constant) and isinstance(reason.value, str) else ""
                found[f"{PARITY_TESTS_PREFIX}{path.name}::{node.name}"] = " ".join(text.split())
    return found


@dataclass(frozen=True)
class Summary:
    total: int
    covered_existing: int
    covered_parity: int
    changed: int
    empty: int
    open_findings: int = 0


def pinned_by(row: Row, xfails: Mapping[str, str]) -> list[str]:
    """The strict xfail tests a row cites (empty for a row v2 meets or changed on purpose)."""
    if is_changed(row.coverage):
        return []
    return [test_id for test_id in coverage_ids(row.coverage) if test_id in xfails]


def summarize(rows: Sequence[Row], xfails: Mapping[str, str] | None = None) -> Summary:
    """Row counts: covered by older tests, covered with a tests/parity test, intentionally changed, empty, and how
    many of the covered rows are pinned by an open finding (a strict xfail)."""
    covered_existing = covered_parity = changed = empty = pinned = 0
    for row in rows:
        cell = row.coverage.strip()
        if not cell or not row.what.strip():
            empty += 1
        elif is_changed(cell):
            changed += 1
        elif any(test_id.startswith(PARITY_TESTS_PREFIX) for test_id in coverage_ids(cell)):
            covered_parity += 1
        else:
            covered_existing += 1
        if xfails and cell and pinned_by(row, xfails):
            pinned += 1
    return Summary(len(rows), covered_existing, covered_parity, changed, empty, pinned)


def render_findings(rows: Sequence[Row], xfails: Mapping[str, str]) -> list[str]:
    """The "Open findings" section: each strict xfail test, its reason and the v1 rows it pins."""
    by_test: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        for test_id in pinned_by(row, xfails):
            by_test[test_id].append(row.check.location)
    if not by_test:
        return ["## Open findings\n", "None: every covered row passes.\n"]

    def order(test_id: str) -> tuple[int, str]:
        match = FINDING_RE.search(xfails[test_id])
        return (int(match.group("finding").split("-")[1]) if match else 10**6, test_id)

    parts = ["## Open findings\n", "| Finding | Strict xfail test | v1 rows | Reason |", "|---|---|---|---|"]
    for test_id in sorted(by_test, key=order):
        match = FINDING_RE.search(xfails[test_id])
        name = match.group("finding") if match else "(unnamed)"
        locations = ", ".join(by_test[test_id])
        parts.append(f"| {name} | `{test_id}` | {escape_cell(locations)} | {escape_cell(xfails[test_id])} |")
    parts.append("")
    return parts


def render(rows: Sequence[Row], xfails: Mapping[str, str] | None = None) -> str:
    """The whole V1_PARITY.md text for `rows` (deterministic)."""
    xfails = xfails or {}
    summary = summarize(rows, xfails)
    parts = [HEADER]
    parts.append("## Summary\n")
    parts.append(
        "| Rows | Covered by v2 tests | Covered with a `tests/parity/` test | Intentionally changed | Empty "
        "| Of the covered rows: pinned by an open finding |"
    )
    parts.append("|---|---|---|---|---|---|")
    parts.append(
        f"| {summary.total} | {summary.covered_existing} | {summary.covered_parity} | {summary.changed} | "
        f"{summary.empty} | {summary.open_findings} |\n"
    )
    parts.extend(render_findings(rows, xfails))
    files = {"smoke_test.py": "tests/smoke_test.py", "deploy_test.sh": "tests/deploy_test.sh"}
    grouped: dict[str, dict[tuple[str, int, str], list[Row]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        check = row.check
        grouped[check.file][(check.section_id, check.section_line, check.section)].append(row)
    for file, title in files.items():
        sections = grouped.get(file, {})
        if not sections:
            continue
        parts.append(f"## {title}\n")
        for (section_id, section_line, section), section_rows in sorted(sections.items(), key=lambda i: i[0][1]):
            parts.append(f"### {section_id} {escape_cell(section)} ({file} line {section_line})\n")
            parts.append("| v1 location | v1 check | What it checks | v2 coverage |")
            parts.append("|---|---|---|---|")
            for row in section_rows:
                cells = [
                    row.check.location_text,
                    escape_cell(code_span(row.check.label)),
                    escape_cell(row.what),
                    escape_cell(row.coverage),
                ]
                parts.append("| " + " | ".join(cells) + " |")
            parts.append("")
    return "\n".join(parts).rstrip("\n") + "\n"


# ------------------------------------------------------------------------------------------------ checking


def strip_parameters(test_id: str) -> str:
    return test_id.split("[", 1)[0]


def collected_ids(root: Path, collection: Path | None = None) -> set[str]:
    """Every collected pytest id without parameters, from a file or from `pytest --collect-only`."""
    if collection is not None:
        lines = collection.read_text(encoding="utf-8").splitlines()
    else:
        command = [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "tests"]
        # A fixed argument list, never a shell: the only input is the repository root (the working directory).
        done = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
        if done.returncode != 0:
            tail = "\n".join((done.stdout + done.stderr).splitlines()[-20:])
            raise CollectionFailed(f"pytest --collect-only failed (exit {done.returncode}):\n{tail}")
        lines = done.stdout.splitlines()
    return {strip_parameters(line.strip()) for line in lines if "::" in line}


class CollectionFailed(RuntimeError):
    """The pytest collection could not be read, so no test id can be verified."""


def problems(rows: Sequence[Row], known_ids: set[str] | None) -> list[str]:
    """Everything `--check` refuses, one message per problem (empty when the table is complete)."""
    found: list[str] = []
    for row in rows:
        where = row.check.location
        what, cell = row.what.strip(), row.coverage.strip()
        if not what:
            found.append(f"{where}: empty 'What it checks' cell")
        if not cell:
            found.append(f"{where}: empty 'v2 coverage' cell")
            continue
        ids = coverage_ids(cell)
        if is_changed(cell):
            reason = cell[len(CHANGED_PREFIX) :].strip()
            if not reason:
                found.append(f"{where}: 'intentionally changed:' needs a reason")
            elif not PLAN_SECTION_RE.search(reason):
                found.append(f"{where}: the reason names no plan section: {reason!r}")
        elif not ids:
            found.append(f"{where}: cite a test id in backticks or write 'intentionally changed: <reason>'")
        else:
            rest = TEST_ID_RE.sub("", cell)
            if rest.replace(",", "").strip():
                found.append(f"{where}: a covered cell must hold only backticked test ids: {cell!r}")
        for test_id in ids:
            if not ID_SHAPE_RE.match(test_id):
                found.append(f"{where}: {test_id!r} is not a test id (tests/<path>.py::<name>, no parameters)")
            elif known_ids is not None and test_id not in known_ids:
                found.append(f"{where}: {test_id} is not in the pytest collection")
    return found


# ------------------------------------------------------------------------------------------------ command line


def build(root: Path) -> tuple[MergeResult, str]:
    """Enumerate, merge with the current table and render (writes nothing)."""
    table = root / TABLE_FILE
    existing = parse_table(table.read_text(encoding="utf-8")) if table.exists() else []
    merged = merge(enumerate_checks(root), existing)
    return merged, render(merged.rows, strict_xfails(root))


def summary_line(summary: Summary) -> str:
    return (
        f"{summary.total} rows: {summary.covered_existing} covered by v2 tests, {summary.covered_parity} with a "
        f"tests/parity test, {summary.changed} intentionally changed, {summary.empty} empty; "
        f"{summary.open_findings} pinned by an open finding"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--check", action="store_true", help="verify the table instead of writing it")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root (default: this checkout)")
    parser.add_argument("--collection", type=Path, help="file of collected pytest ids (default: run pytest)")
    parser.add_argument("--no-collection", action="store_true", help="skip the test id existence check")
    args = parser.parse_args(argv)
    root: Path = args.root
    merged, text = build(root)
    for old, new in merged.moved:
        print(f"moved: {old} -> {new}")
    for row in merged.dropped:
        print(f"dropped (no such v1 check any more): {row.location} {row.label!r}")
    summary = summarize(merged.rows, strict_xfails(root))
    if not args.check:
        (root / TABLE_FILE).write_text(text, encoding="utf-8")
        print(f"wrote {TABLE_FILE}: {summary_line(summary)}")
        return 0
    found: list[str] = []
    current = (root / TABLE_FILE).read_text(encoding="utf-8") if (root / TABLE_FILE).exists() else ""
    if current != text:
        found.append(f"{TABLE_FILE} is not up to date: run python scripts/gen_v1_parity.py and fill the new rows")
    known: set[str] | None = None
    if not args.no_collection:
        try:
            known = collected_ids(root, args.collection)
        except (CollectionFailed, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    found.extend(problems(merged.rows, known))
    for message in found:
        print(message)
    print(f"{summary_line(summary)}; {len(found)} problems")
    return 1 if found else 0


def counts_by_section(rows: Iterable[Row]) -> Mapping[str, int]:
    """Rows per section id (the tests compare them with the reading of the v1 suite)."""
    return Counter(row.check.section_id for row in rows)


if __name__ == "__main__":
    sys.exit(main())
