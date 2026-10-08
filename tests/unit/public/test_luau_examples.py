"""The Luau examples on the public site: strict, typed, and accepted by the Luau type checker.

What this is
    Tests over every Luau example a visitor can copy: the home page snippets (`templates/public/examples/*.luau`)
    and every `luau` or `lua` fence in `docs/USER_GUIDE.md`. The style tests always run. The type check runs
    `luau-analyze --mode=strict` (from github.com/luau-lang/luau releases) with both the new and the old type
    solver, and is skipped when that binary is not installed (`~/.local/bin` or the PATH).

Why it exists
    The owner asked for examples that are solid, idiomatic and fully typed: `--!strict` at the top, typed
    signatures, explicit types for decoded JSON, `pcall` around every call that can raise, `Retry-After` honored
    with a fallback and jitter, constants for the base URL and the limits, and no globals. A reviewer reading 400
    lines of Luau misses things a type checker does not, and an example that does not compile teaches the wrong
    lesson to everyone who copies it.

How it works
    luau-analyze knows the Luau standard library but not Roblox, so `roblox_api.luau` (next to this file) is
    pasted right after each example's `--!strict` line; it declares `game`, `task` and `warn` with Roblox's own
    types. Reported line numbers are mapped back to the example's lines. The guide's `RoxyClient` module is written
    to `RoxyClient.luau`, and the script that uses it has its `require(ServerScriptService.RoxyClient)` pointed at
    that file, so the module's exported types are checked across the require exactly as Studio would.

What to read next
    `roblox_api.luau`, `docs/USER_GUIDE.md` chapter 3, `roxy/templates/public/examples/`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from roxy.public import pages

HERE = Path(__file__).resolve().parent
PRELUDE = (HERE / "roblox_api.luau").read_text(encoding="utf-8")
PRELUDE_LINES = PRELUDE.count("\n")
FENCE = re.compile(r"^```(luau|lua)[ \t]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
MODULE_NAME = "RoxyClient"
REQUIRE_MODULE = f"require(ServerScriptService.{MODULE_NAME})"
DIAGNOSTIC = re.compile(r"^(?P<file>[^(]+)\((?P<line>\d+),(?P<column>\d+)(?:-\d+)?\): (?P<message>.+)$")


@dataclass(frozen=True)
class Example:
    """One copyable Luau example: where it comes from and its exact text."""

    name: str
    source: str


def home_examples() -> list[Example]:
    paths = sorted(pages.HOME_EXAMPLES_DIR.glob("*.luau"))
    assert paths, pages.HOME_EXAMPLES_DIR
    return [Example(f"home_{path.stem}", path.read_text(encoding="utf-8")) for path in paths]


def guide_examples() -> list[Example]:
    text = pages.USER_GUIDE_PATH.read_text(encoding="utf-8")
    found = [Example(f"guide_{index}", match.group(2)) for index, match in enumerate(FENCE.finditer(text), start=1)]
    assert found, "the guide has no luau fences"
    return found


ALL_EXAMPLES = home_examples() + guide_examples()


def find_luau_analyze() -> str | None:
    found = shutil.which("luau-analyze")
    if found:
        return found
    local = Path.home() / ".local" / "bin" / "luau-analyze"
    return str(local) if local.is_file() and os.access(local, os.X_OK) else None


# --- style: true for every example, with or without the type checker -------------------------------------------


def without_comments(source: str) -> str:
    """The example with `--` line comments cut off (good enough here: no example has `--` inside a string)."""
    return "\n".join(line.split("--", 1)[0] for line in source.splitlines())


@pytest.mark.parametrize("example", ALL_EXAMPLES, ids=lambda example: example.name)
def test_example_is_strict_typed_and_global_free(example: Example) -> None:
    lines = example.source.splitlines()
    assert lines[0] == "--!strict", "strict mode must be the first line, or Studio ignores it"
    code = without_comments(example.source)
    # Nothing is assigned as a global at the top level (strict mode, checked below by luau-analyze, also reports
    # any unknown global inside a function).
    assert not re.search(r"^[A-Za-z_]\w*\s*=(?!=)", code, re.MULTILINE), "a global assignment"
    assert not re.search(r"^function \w+\s*\(", code, re.MULTILINE), "functions are const or module fields"
    # Every function signature is typed: each parameter has an annotation, and named functions declare a return.
    for match in re.finditer(r"\bfunction\s*([\w.:]*)\s*\(([^)]*)\)(\s*:)?", code):
        for parameter in filter(None, (part.strip() for part in match.group(2).split(","))):
            assert ":" in parameter, (example.name, match.group(0))
        if match.group(1):
            assert match.group(3), f"{example.name}: {match.group(0)} has no return type"
    if "RequestAsync" in code or "GetAsync" in code:
        assert "pcall(" in code, "HttpService calls raise on failure, so every example wraps them in pcall"
    if "JSONDecode" in code:
        assert re.search(r"pcall\(function\(\): \w+", code), "the decoding pcall names the type of its result"
    # Decoded JSON is checked before use: whoever reads `.data` first confirms it is a table.
    if re.search(r"\.data\b", code):
        assert re.search(r'typeof\([\w.]+\.data\) ~= "table"', code), "decoded JSON is used without a check"
    # `any` appears only where a comment explains why (JSONDecode returns it; a module cannot know each shape).
    if re.search(r"\bany\b", code):
        assert "`any`" in example.source, "an `any` without a comment saying why"


DECLARATION = re.compile(r"^\t*(?P<keyword>local|const)\s+(?:function\s+)?(?P<names>[\w\s,:{}\[\]?]+?)\s*(?:=|\(|$)")


def declarations(code: str) -> list[tuple[str, list[str], bool]]:
    """Every `local` or `const` declaration, at any depth: (keyword, names, is_function)."""
    found = []
    for line in code.splitlines():
        match = DECLARATION.match(line)
        if match is None:
            continue
        names = [part.split(":", 1)[0].strip() for part in match.group("names").split(",")]
        found.append((match.group("keyword"), names, " function " in f" {line.strip()} "))
    return found


def is_reassigned(code: str, name: str) -> bool:
    """True when `name` is assigned again after its declaration (`name = `, `name += `, `name ..= `...)."""
    return re.search(rf"^\t*{re.escape(name)}\s*(?:[-+*/%^]|\.\.|//)?=(?!=)", code, re.MULTILINE) is not None


@pytest.mark.parametrize("example", ALL_EXAMPLES, ids=lambda example: example.name)
def test_const_for_every_binding_that_never_changes(example: Example) -> None:
    """Owner request 2026-10-07: `const` wherever a name is never assigned again (services, URLs, limits, module
    tables, functions, values inside functions), `local` only for names that change, UPPER_SNAKE_CASE for true
    constants (top-level numbers and strings)."""
    code = without_comments(example.source)
    found = declarations(code)
    assert any(keyword == "const" for keyword, *_ in found)
    assert sum(len(names) for _, names, _ in found) >= 3, "the declaration scan found too little"
    for keyword, names, is_function in found:
        for name in names:
            if keyword == "local":
                assert not is_function, f"{example.name}: `local function {name}` is never reassigned; use const"
                assert is_reassigned(code, name), f"{example.name}: `local {name}` never changes; use const"
            else:
                assert not is_reassigned(code, name), f"{example.name}: const {name} is assigned again"
            if re.fullmatch(r"[A-Z][A-Z0-9_]+", name):
                assert keyword == "const", f"{example.name}: {name} looks like a constant but is not const"
    for match in re.finditer(r'^const (\w+)\s*=\s*(?:-?\d|"|\{ ")', code, re.MULTILINE):
        assert re.fullmatch(r"[A-Z][A-Z0-9_]+", match.group(1)), f"{example.name}: constant {match.group(1)}"


@pytest.mark.parametrize("example", ALL_EXAMPLES, ids=lambda example: example.name)
def test_roblox_conventions(example: Example) -> None:
    """GetService once at the top, task.wait never the old wait, and Retry-After capped (no endless waiting)."""
    code = without_comments(example.source)
    services = re.findall(r'GetService\("(\w+)"\)', code)
    assert len(services) == len(set(services)), "each service is fetched once"
    for line in code.splitlines():
        if "GetService(" in line:
            assert re.match(r'^const (\w+) = game:GetService\("\1"\)$', line), f"GetService at the top: {line}"
    assert not re.search(r"(?<![.\w])(wait|delay|spawn)\(", code), "use task.wait, task.delay, task.spawn"
    if "Retry-After" in code and "retryWaitSeconds" in code:
        assert "MAX_WAIT_SECONDS" in code, "a Retry-After wait is capped"
    assert not re.search(r"\bwhile true do\b", code), "no busy loops"


@pytest.mark.parametrize("example", ALL_EXAMPLES, ids=lambda example: example.name)
def test_request_examples_handle_success_429_and_other_codes(example: Example) -> None:
    code = without_comments(example.source)
    if "RequestAsync" not in code or "HEADER_NAMES" in code:
        return  # the header printing example only reads headers; it retries nothing
    assert "StatusCode == 200" in code
    assert "StatusCode == 429" in code
    assert "FALLBACK_WAIT_SECONDS" in code  # a sane fallback when Retry-After is missing or unusable
    assert "math.random()" in code  # jitter
    assert re.search(r"\n\t+else\n", code), "every other status code has its own branch"


def test_home_examples_are_also_in_the_guide() -> None:
    """One source of truth: each home snippet appears in the guide word for word, so the two never drift."""
    guide = {example.source for example in guide_examples()}
    for example in home_examples():
        assert example.source in guide, example.name


# --- the type checker -------------------------------------------------------------------------------------------


def checked_file(source: str) -> str:
    """The example with the Roblox stand-ins pasted after its first line (`--!strict` must stay first).

    `require(ServerScriptService.RoxyClient)` becomes a require of the module's file, and the same line still
    reads `ServerScriptService.RoxyClient` as a ModuleScript, so line numbers and the use of the service stay.
    """
    first, _, rest = source.partition("\n")
    by_file = f'require("./{MODULE_NAME}"); local _module: ModuleScript = ServerScriptService.{MODULE_NAME}'
    return f"{first}\n{PRELUDE}{rest.replace(REQUIRE_MODULE, by_file)}"


def example_line(line: int) -> int | None:
    """Map a checked file's line back to the example (None for a line of the stand-ins)."""
    if line == 1:
        return 1
    if line <= 1 + PRELUDE_LINES:
        return None
    return line - PRELUDE_LINES


@pytest.mark.parametrize("solver", ["new", "old"])
def test_examples_pass_luau_analyze_in_strict_mode(tmp_path: Path, solver: str) -> None:
    analyze = find_luau_analyze()
    if analyze is None:
        pytest.skip("luau-analyze is not installed (github.com/luau-lang/luau releases, into ~/.local/bin)")
    files: dict[str, Example] = {}
    for example in ALL_EXAMPLES:
        is_module = re.search(rf"^return {MODULE_NAME}\s*$", example.source, re.MULTILINE) is not None
        name = f"{MODULE_NAME}.luau" if is_module else f"{example.name}.luau"
        assert name not in files, f"two examples would both be {name}"
        files[name] = example
        (tmp_path / name).write_text(checked_file(example.source), encoding="utf-8")
    result = subprocess.run(
        [analyze, "--mode=strict", f"--solver={solver}", *sorted(files)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    problems: list[str] = []
    keep_continuation = False  # a long type error goes on over several lines that do not start with a file name
    for raw in (result.stdout + result.stderr).splitlines():
        match = DIAGNOSTIC.match(raw.strip())
        if match is None:
            if keep_continuation and problems:
                problems[-1] += "\n    " + raw.strip()
            elif raw.strip():
                problems.append(f"unparsed output: {raw}")
            continue
        line = example_line(int(match.group("line")))
        reported = files.get(Path(match.group("file")).name)
        where = reported.name if reported is not None else match.group("file")
        message = match.group("message")
        keep_continuation = True
        if line is None:
            if message.startswith(("TypeError", "SyntaxError")):
                problems.append(f"{where} (roblox_api.luau part): {message}")
            else:
                keep_continuation = False  # a lint about the stand-ins themselves (`task` unused in one example)
            continue
        problems.append(f"{where}:{line}:{match.group('column')}: {message}")
    assert problems == [], "\n".join(problems)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
