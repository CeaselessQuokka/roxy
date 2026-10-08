"""The Luau highlighter: right tokens, total on any text, safe HTML, and a corpus that runs every scanner line.

What this is
    Unit tests for `roxy.public.luau_highlight`: what each construct is cut into (`tokenize`), the HTML it becomes
    (`highlight`), property tests over random and hostile text (Hypothesis), a bound on time and nesting for
    pathological input, and a line coverage check: every line of every scanner function must run while the
    corpus below and the site's own Luau examples are tokenized.

Why it exists
    The highlighter writes HTML into public pages. Its promises: it never raises (a broken file must not take the
    guide down), the tokens join back to the input exactly (nothing lost or invented), all text is escaped and
    every class name comes from the fixed table (no XSS, plan 9.16), and no inline style or script (plan 9.2).
    A half-finished version once called a method that did not exist, on the path for generic functions
    (`function f<T>`); no test reached that path, so the AttributeError waited for the first generic example.
    The coverage test makes sure every path is reached by at least one input here.

How it works
    `CASES` pairs a source with the tokens it must produce (whitespace left out). The coverage test turns on
    Python 3.12 `sys.monitoring` LINE events with a tool id of its own (so it does not disturb a debugger or a
    coverage tool) and compares the lines that ran with every line of the scanner's functions.

What to read next
    `roxy/public/luau_highlight.py`, then `test_public_guide.py` (fences in the guide) and `test_luau_examples.py`.
"""

from __future__ import annotations

import html
import inspect
import re
import sys
import time
import types
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from roxy.public import luau_highlight, pages
from roxy.public.luau_highlight import CSS_CLASS, MAX_NESTING, Kind, highlight, tokenize

K, S, N, C, B, T, OP, IN, P = (
    Kind.KEYWORD,
    Kind.STRING,
    Kind.NUMBER,
    Kind.COMMENT,
    Kind.BUILTIN,
    Kind.TYPE,
    Kind.OPERATOR,
    Kind.INTERPOLATION,
    Kind.PLAIN,
)


def significant(source: str) -> list[tuple[Kind, str]]:
    """The tokens of `source` without whitespace, as (kind, text) pairs."""
    return [(token.kind, token.text) for token in tokenize(source) if not token.text.isspace()]


# --- what each construct becomes ----------------------------------------------------------------------------------

CASES: list[tuple[str, list[tuple[Kind, str]]]] = [
    # Comments, including unterminated ones and one that ends the text without a line break.
    ("-- note\nx", [(C, "-- note"), (P, "x")]),
    ("--[[ a\nb ]] x", [(C, "--[[ a\nb ]]"), (P, "x")]),
    ("--[==[ ]] ]==]", [(C, "--[==[ ]] ]==]")]),
    ("--[[ never closed", [(C, "--[[ never closed")]),
    ("-- last line", [(C, "-- last line")]),
    # Strings: escapes, long brackets, unterminated ones, `\z`, a Windows line continuation, a final backslash.
    ('"a\\"b" \'c\'', [(S, '"a\\"b"'), (S, "'c'")]),
    ('"open\nx', [(S, '"open'), (P, "x")]),
    ('"ends', [(S, '"ends')]),
    ('"a\\z\n   b"', [(S, '"a\\z\n   b"')]),
    ('"a\\zb"', [(S, '"a\\zb"')]),
    ('"a\\\r\nb"', [(S, '"a\\\r\nb"')]),
    ('"a\\', [(S, '"a\\')]),
    ("[[long\n]] [==[x]]y]==]", [(S, "[[long\n]]"), (S, "[==[x]]y]==]")]),
    ("[[open", [(S, "[[open")]),
    ("t[1]", [(P, "t"), (P, "["), (N, "1"), (P, "]")]),
    # Backtick strings: expressions inside braces, empty parts, nesting, escapes, and every way one can end.
    ("`a{b}c`", [(S, "`a"), (IN, "{"), (P, "b"), (IN, "}"), (S, "c`")]),
    ("`{a}{b}`", [(S, "`"), (IN, "{"), (P, "a"), (IN, "}"), (IN, "{"), (P, "b"), (IN, "}"), (S, "`")]),
    (
        "`x{`y{1}`}`",
        [(S, "`x"), (IN, "{"), (S, "`y"), (IN, "{"), (N, "1"), (IN, "}"), (S, "`"), (IN, "}"), (S, "`")],
    ),
    ("`{ {1} }`", [(S, "`"), (IN, "{"), (P, "{"), (N, "1"), (P, "}"), (IN, "}"), (S, "`")]),
    ("`\\{not code\\``", [(S, "`\\{not code\\``")]),
    ("`open\nx", [(S, "`open"), (P, "x")]),
    ("`open", [(S, "`open")]),
    ("`a{b", [(S, "`a"), (IN, "{"), (P, "b")]),
    ("`a{b}", [(S, "`a"), (IN, "{"), (P, "b"), (IN, "}")]),
    ("`a\\", [(S, "`a\\")]),
    # Numbers.
    (
        "1 1_000 0xFF 0b1010 1.5e10 .5 2E-3",
        [(N, "1"), (N, "1_000"), (N, "0xFF"), (N, "0b1010"), (N, "1.5e10"), (N, ".5"), (N, "2E-3")],
    ),
    ("x.", [(P, "x"), (P, ".")]),
    # Names: globals, libraries as one piece, fields, methods, `type(...)`, unknown characters.
    (
        "print(game.Players, x.game, string.lower, string, task.wait)",
        [
            (B, "print"),
            (P, "("),
            (B, "game"),
            (P, "."),
            (P, "Players"),
            (P, ","),
            (P, "x"),
            (P, "."),
            (P, "game"),
            (P, ","),
            (B, "string.lower"),
            (P, ","),
            (B, "string"),
            (P, ","),
            (B, "task.wait"),
            (P, ")"),
        ],
    ),
    ("s.JSONDecode", [(P, "s"), (P, "."), (B, "JSONDecode")]),
    ("type(v) type (v)", [(B, "type"), (P, "("), (P, "v"), (P, ")"), (B, "type"), (P, "("), (P, "v"), (P, ")")]),
    ("é$", [(P, "é"), (P, "$")]),
    # Method calls and type annotations share `:`.
    (
        'HttpService:GetAsync(url) obj:M "s" obj:M{} local x: number',
        [
            (B, "HttpService"),
            (P, ":"),
            (B, "GetAsync"),
            (P, "("),
            (P, "url"),
            (P, ")"),
            (P, "obj"),
            (P, ":"),
            (P, "M"),
            (S, '"s"'),
            (P, "obj"),
            (P, ":"),
            (P, "M"),
            (P, "{"),
            (P, "}"),
            (K, "local"),
            (P, "x"),
            (P, ":"),
            (T, "number"),
        ],
    ),
    ("x:", [(P, "x"), (P, ":")]),
    # Contextual keywords: `continue`.
    ("continue end", [(K, "continue"), (K, "end")]),
    ("continue", [(K, "continue")]),
    ("continue;", [(K, "continue"), (P, ";")]),
    ("continue -- why\nx = 1", [(K, "continue"), (C, "-- why"), (P, "x"), (OP, "="), (N, "1")]),
    ("continue = 1", [(P, "continue"), (OP, "="), (N, "1")]),
    ("y = continue and z", [(P, "y"), (OP, "="), (P, "continue"), (K, "and"), (P, "z")]),
    # `export`, `type`, `const`.
    ("export type X = number", [(K, "export"), (K, "type"), (T, "X"), (OP, "="), (T, "number")]),
    ("export = 1", [(P, "export"), (OP, "="), (N, "1")]),
    ("type function f() end", [(K, "type"), (K, "function"), (P, "f"), (P, "("), (P, ")"), (K, "end")]),
    ("type then", [(P, "type"), (K, "then")]),
    ("type X", [(K, "type"), (T, "X")]),
    ("type X == 1", [(K, "type"), (T, "X"), (OP, "=="), (N, "1")]),
    ("type A --c\n= B", [(K, "type"), (T, "A"), (C, "--c"), (OP, "="), (T, "B")]),
    ("const MAX = 3", [(K, "const"), (P, "MAX"), (OP, "="), (N, "3")]),
    ("const function f() end", [(K, "const"), (K, "function"), (P, "f"), (P, "("), (P, ")"), (K, "end")]),
    ("const = 1", [(P, "const"), (OP, "="), (N, "1")]),
    ("print(const)", [(B, "print"), (P, "("), (P, "const"), (P, ")")]),
    ("const\nx = 1", [(P, "const"), (P, "x"), (OP, "="), (N, "1")]),
    # Generic parameters after `function` and `function name`, and every `<` that only compares.
    (
        "local function f<T>(x: T): T",
        [
            (K, "local"),
            (K, "function"),
            (P, "f"),
            (OP, "<"),
            (T, "T"),
            (OP, ">"),
            (P, "("),
            (P, "x"),
            (P, ":"),
            (T, "T"),
            (P, ")"),
            (P, ":"),
            (T, "T"),
        ],
    ),
    (
        "function M.f<A, B...>()",
        [
            (K, "function"),
            (P, "M"),
            (P, "."),
            (P, "f"),
            (OP, "<"),
            (T, "A"),
            (P, ","),
            (T, "B"),
            (OP, "..."),
            (OP, ">"),
            (P, "("),
            (P, ")"),
        ],
    ),
    (
        "function<T>(v: T)",
        [(K, "function"), (OP, "<"), (T, "T"), (OP, ">"), (P, "("), (P, "v"), (P, ":"), (T, "T"), (P, ")")],
    ),
    ("a < b", [(P, "a"), (OP, "<"), (P, "b")]),
    ("1<2 (<", [(N, "1"), (OP, "<"), (N, "2"), (P, "("), (OP, "<")]),
    ("x.y<z", [(P, "x"), (P, "."), (P, "y"), (OP, "<"), (P, "z")]),
    ("xfunction f<z", [(P, "xfunction"), (P, "f"), (OP, "<"), (P, "z")]),
    ("f<z", [(P, "f"), (OP, "<"), (P, "z")]),
    # Attributes and casts.
    ("@native @", [(K, "@native"), (P, "@")]),
    ("v :: any", [(P, "v"), (OP, "::"), (T, "any")]),
    # `typeof` in code and in types.
    ("typeof(f(x))", [(K, "typeof"), (P, "("), (P, "f"), (P, "("), (P, "x"), (P, ")"), (P, ")")]),
    ("typeof x", [(K, "typeof"), (P, "x")]),
    (
        "local v: typeof(w) | typeof",
        [(K, "local"), (P, "v"), (P, ":"), (K, "typeof"), (P, "("), (P, "w"), (P, ")"), (OP, "|"), (K, "typeof")],
    ),
    # Types: optional, union, intersection, nil and booleans, packs, qualified names, generics and defaults.
    (
        "local v: A? | nil & true | false",
        [
            (K, "local"),
            (P, "v"),
            (P, ":"),
            (T, "A"),
            (OP, "?"),
            (OP, "|"),
            (K, "nil"),
            (OP, "&"),
            (K, "true"),
            (OP, "|"),
            (K, "false"),
        ],
    ),
    (
        "local v: Mod.Type<number>",
        [(K, "local"), (P, "v"), (P, ":"), (T, "Mod"), (P, "."), (T, "Type"), (OP, "<"), (T, "number"), (OP, ">")],
    ),
    (
        'type M = | "GET" | "POST"',
        [(K, "type"), (T, "M"), (OP, "="), (OP, "|"), (S, '"GET"'), (OP, "|"), (S, '"POST"')],
    ),
    (
        "type F = <T>(T, ...number) -> ...T",
        [
            (K, "type"),
            (T, "F"),
            (OP, "="),
            (OP, "<"),
            (T, "T"),
            (OP, ">"),
            (P, "("),
            (T, "T"),
            (P, ","),
            (OP, "..."),
            (T, "number"),
            (P, ")"),
            (OP, "->"),
            (OP, "..."),
            (T, "T"),
        ],
    ),
    (
        "type G<T = string> = { [string]: T; read a: T, write b: T, read: T, read c }",
        [
            (K, "type"),
            (T, "G"),
            (OP, "<"),
            (T, "T"),
            (OP, "="),
            (T, "string"),
            (OP, ">"),
            (OP, "="),
            (P, "{"),
            (P, "["),
            (T, "string"),
            (P, "]"),
            (P, ":"),
            (T, "T"),
            (P, ";"),
            (P, "read a"),
            (P, ":"),
            (T, "T"),
            (P, ","),
            (P, "write b"),
            (P, ":"),
            (T, "T"),
            (P, ","),
            (P, "read"),
            (P, ":"),
            (T, "T"),
            (P, ","),
            (T, "read"),
            (T, "c"),
            (P, "}"),
        ],
    ),
    (
        'type H = { ["Content-Type"]: string }',
        [
            (K, "type"),
            (T, "H"),
            (OP, "="),
            (P, "{"),
            (P, "["),
            (S, '"Content-Type"'),
            (P, "]"),
            (P, ":"),
            (T, "string"),
            (P, "}"),
        ],
    ),
    ("local v: { string }", [(K, "local"), (P, "v"), (P, ":"), (P, "{"), (T, "string"), (P, "}")]),
    ("type E = <T>", [(K, "type"), (T, "E"), (OP, "="), (OP, "<"), (T, "T"), (OP, ">")]),
    ("local v: ...", [(K, "local"), (P, "v"), (P, ":"), (OP, "...")]),
    ("local v: number --[[ c ]]?", [(K, "local"), (P, "v"), (P, ":"), (T, "number"), (C, "--[[ c ]]"), (OP, "?")]),
    ("local v: T ...", [(K, "local"), (P, "v"), (P, ":"), (T, "T"), (OP, "...")]),
    ("local v: T .. x", [(K, "local"), (P, "v"), (P, ":"), (T, "T"), (OP, ".."), (P, "x")]),
    ("local v: T. ", [(K, "local"), (P, "v"), (P, ":"), (T, "T"), (P, ".")]),
    ("local v: T <x", [(K, "local"), (P, "v"), (P, ":"), (T, "T"), (OP, "<"), (P, "x")]),
    ("(v :: {}) < 1", [(P, "("), (P, "v"), (OP, "::"), (P, "{"), (P, "}"), (P, ")"), (OP, "<"), (N, "1")]),
    # Broken types end where the type ends; the rest is scanned as code.
    ("local v: = 1", [(K, "local"), (P, "v"), (P, ":"), (OP, "="), (N, "1")]),
    ("local v: function", [(K, "local"), (P, "v"), (P, ":"), (K, "function")]),
    ("local v: { = }", [(K, "local"), (P, "v"), (P, ":"), (P, "{"), (OP, "="), (P, "}")]),
    ("local v: { a: number", [(K, "local"), (P, "v"), (P, ":"), (P, "{"), (P, "a"), (P, ":"), (T, "number")]),
    ("local v: (", [(K, "local"), (P, "v"), (P, ":"), (P, "(")]),
    # Unmatched closing brackets in code and in an interpolation.
    (")]}", [(P, ")"), (P, "]"), (P, "}")]),
]


@pytest.mark.parametrize(("source", "expected"), CASES, ids=[repr(source)[:40] for source, _ in CASES])
def test_tokens(source: str, expected: list[tuple[Kind, str]]) -> None:
    assert significant(source) == expected
    assert "".join(token.text for token in tokenize(source)) == source


def test_generic_function_definitions_are_highlighted() -> None:
    """The path that once called a missing method: `<` right after `function name` opens generic parameters."""
    source = "local function first<T>(items: { T }): T?\n\treturn items[1]\nend\n"
    page = str(highlight(source))
    assert '<span class="k">local function</span> first<span class="o">&lt;</span><span class="t">T</span>' in page
    assert '<span class="o">&gt;</span>(items: {' in page


def test_nesting_deeper_than_the_limit_is_scanned_flat() -> None:
    depth = MAX_NESTING + 5
    nested_strings = "`{" * depth + "x" + "}`" * depth
    tokens = tokenize(nested_strings)
    assert "".join(token.text for token in tokens) == nested_strings
    assert sum(1 for token in tokens if token.kind is Kind.INTERPOLATION and "{" in token.text) == MAX_NESTING
    for source in ("local v: " + "{" * depth, "typeof(" * depth, "local v: " + "(" * depth + ")" * depth):
        assert "".join(token.text for token in tokenize(source)) == source


# --- HTML -------------------------------------------------------------------------------------------------------

SPAN_OPEN = re.compile(r'<span class="([a-z])">')


def plain_text(markup: str) -> str:
    """The visible text of highlighted HTML: spans removed, entities decoded."""
    return html.unescape(re.sub(r'<span class="[a-z]">|</span>', "", markup))


def assert_safe_html(source: str) -> None:
    page = str(highlight(source))
    assert plain_text(page) == source
    assert set(SPAN_OPEN.findall(page)) <= set(CSS_CLASS.values())
    # The only tags are the spans, each with a class and nothing else (no style, no script, no event handler);
    # any `<` from the input arrives escaped.
    assert "<" not in re.sub(r'<span class="[a-z]">|</span>', "", page)
    assert page.count("<span") == page.count("</span>")


def test_highlight_escapes_and_merges_neighbors() -> None:
    page = str(highlight('end\n\tend -- <b>&"\n"<script>" x'))
    assert page == (
        '<span class="k">end\n\tend</span> <span class="c">-- &lt;b&gt;&amp;"</span>\n'
        '<span class="s">"&lt;script&gt;"</span> x'
    )
    assert str(highlight("x  ")) == "x  "
    assert str(highlight("end  ")) == '<span class="k">end</span>  '
    assert str(highlight("")) == ""


HOSTILE = [
    "</code></pre><script>alert(1)</script>",
    '-- </code><img src=x onerror="alert(1)">',
    '"<style>body{}</style>" `<{"&amp;"}>` [[<iframe>]]',
    "local v: {<script>: number} :: <svg/onload=x>",
    "\x00\x01  ﻿\U0001f600 &lt; &#x3C; &",
]


@pytest.mark.parametrize("source", HOSTILE)
def test_hostile_text_is_escaped(source: str) -> None:
    assert_safe_html(source)
    assert "<script" not in str(highlight(source))


# --- property tests: any text --------------------------------------------------------------------------------------

LUAU_PIECES = [
    "local ", "const ", "function ", "type ", "export ", "continue", "typeof(", "end", " ", "\n", "\t", "--", "--[[",
    "--[==[", "]]", "]==]", "[[", "[=[", "]=]", '"', "'", "`", "{", "}", "(", ")", "[", "]", "<", ">", ":", "::",
    "->", "?", "|", "&", "...", "..", ".", ",", ";", "=", "==", "\\", "\\z", "x", "T", "read ", "game", "string.",
    "0x", "1", ".5", "e", "@", "nil", "true", "é",
]  # fmt: skip


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.sampled_from(LUAU_PIECES), max_size=60).map("".join))
def test_luau_like_text_round_trips(source: str) -> None:
    tokens = tokenize(source)
    assert "".join(token.text for token in tokens) == source
    assert all(token.text for token in tokens)
    assert_safe_html(source)


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=200))
def test_any_text_round_trips(source: str) -> None:
    assert "".join(token.text for token in tokenize(source)) == source
    assert_safe_html(source)


# --- time and recursion on pathological input --------------------------------------------------------------------

PATHOLOGICAL = [
    "<" * 20_000,
    "a<" * 10_000,
    "function" + " " * 20_000 + "f<T>()",
    "local v: " + "typeof(x: " * 5_000,
    "local v: " + "<" * 10_000,
    "local v: " + "{" * 20_000,
    "local v: " + "(" * 20_000,
    "typeof(" * 10_000,
    "`{" * 10_000,
    "--[[" * 10_000,
    "[==[" * 10_000,
    '"' + "\\z" * 10_000,
    "continue " * 5_000,
    "x: " * 7_000,
    "type X = " * 3_000,
]


def stack_depth() -> int:
    frame: types.FrameType | None = sys._getframe()
    depth = 0
    while frame is not None:
        frame, depth = frame.f_back, depth + 1
    return depth


@pytest.mark.parametrize("source", PATHOLOGICAL, ids=[repr(source[:12]) for source in PATHOLOGICAL])
def test_pathological_input_is_fast_and_never_recurses_deeply(source: str) -> None:
    limit = sys.getrecursionlimit()
    # 250 frames above this test, far below the default 1000: proves the nesting bound, not a lucky stack size.
    sys.setrecursionlimit(stack_depth() + 250)
    try:
        started = time.monotonic()
        tokens = tokenize(source)
        elapsed = time.monotonic() - started
    finally:
        sys.setrecursionlimit(limit)
    assert "".join(token.text for token in tokens) == source
    assert elapsed < 10.0, f"{elapsed:.2f} s for {len(source)} characters"


# --- the site's own examples ----------------------------------------------------------------------------------------

FENCE = re.compile(r"^```(luau|lua)[ \t]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)


def site_examples() -> list[str]:
    home = [path.read_text(encoding="utf-8") for path in sorted(pages.HOME_EXAMPLES_DIR.glob("*.luau"))]
    guide = [match.group(2) for match in FENCE.finditer(pages.USER_GUIDE_PATH.read_text(encoding="utf-8"))]
    assert home
    assert guide
    return home + guide


def test_site_examples_highlight_their_declarations() -> None:
    for source in site_examples():
        assert_safe_html(source)
        kinds = significant(source)
        assert kinds[0] == (C, "--!strict")
        consts = [index for index, token in enumerate(kinds) if token == (K, "const")]
        assert consts, "every example declares its constants and services with const"
        for index in consts:
            assert kinds[index + 1][0] in (P, B, K), kinds[index : index + 3]  # a name, a service or `function`
        for index, token in enumerate(kinds):
            if token == (K, "type"):
                assert kinds[index + 1][0] is T, kinds[index : index + 3]  # the alias name is a type


# --- every scanner line runs ----------------------------------------------------------------------------------------


def scanner_functions() -> list[types.FunctionType]:
    """Every function written in luau_highlight.py: module functions and `_Scanner` methods (unwrapped)."""
    found: list[types.FunctionType] = []
    candidates = [*vars(luau_highlight).values(), *vars(luau_highlight._Scanner).values()]
    for candidate in candidates:
        function = inspect.unwrap(candidate) if callable(candidate) else candidate
        if isinstance(function, types.FunctionType) and function.__code__.co_filename == luau_highlight.__file__:
            found.append(function)
    return found


def code_lines(code: types.CodeType) -> set[int]:
    """Lines that hold instructions, without the `def` line (it only holds the frame setup, which reports no
    line event), including nested code objects."""
    lines = {line for _, _, line in code.co_lines() if line is not None and line != code.co_firstlineno}
    for constant in code.co_consts:
        if isinstance(constant, types.CodeType):
            lines |= code_lines(constant)
    return lines


def all_codes(code: types.CodeType) -> Iterator[types.CodeType]:
    yield code
    for constant in code.co_consts:
        if isinstance(constant, types.CodeType):
            yield from all_codes(constant)


def run_traced(work: Callable[[], None], codes: list[types.CodeType]) -> set[int]:
    """Run `work` and return the lines of `codes` that ran (sys.monitoring LINE events on those code objects
    only, under a tool id nobody else holds, so a debugger or a coverage tool keeps working)."""
    monitoring = sys.monitoring
    tool = next((tool for tool in (3, 4, 2, 5) if monitoring.get_tool(tool) is None), None)
    if tool is None:
        pytest.skip("every free sys.monitoring tool id is taken by another tool")
    seen: set[int] = set()

    def on_line(code: types.CodeType, line: int) -> None:
        seen.add(line)

    monitoring.use_tool_id(tool, "luau highlight coverage test")
    try:
        monitoring.register_callback(tool, monitoring.events.LINE, on_line)
        for code in codes:
            monitoring.set_local_events(tool, code, monitoring.events.LINE)
        work()
    finally:
        for code in codes:
            monitoring.set_local_events(tool, code, 0)
        monitoring.register_callback(tool, monitoring.events.LINE, None)
        monitoring.free_tool_id(tool)
    return seen


def corpus() -> Iterator[str]:
    yield from (source for source, _ in CASES)
    yield from HOSTILE
    yield from site_examples()
    yield "`{" * (MAX_NESTING + 2) + "}`" * (MAX_NESTING + 2)
    yield "typeof(" * (MAX_NESTING + 2)
    yield "local v: " + "{" * (MAX_NESTING + 2)
    yield "end  "


def test_corpus_runs_every_scanner_line() -> None:
    codes = [code for function in scanner_functions() for code in all_codes(function.__code__)]
    expected: set[int] = set()
    for function in scanner_functions():
        expected |= code_lines(function.__code__)
    assert len(expected) > 200, "the scanner functions were not found"

    def work() -> None:
        for source in corpus():
            highlight(source)

    seen = run_traced(work, codes)
    missing = sorted(expected - seen)
    source_lines = Path(luau_highlight.__file__).read_text(encoding="utf-8").splitlines()
    assert missing == [], "\n".join(f"line {line}: {source_lines[line - 1].strip()}" for line in missing)
