"""Adversarial review (public site lens): the Luau examples against the conventions the guide says they follow.

What this is
    Checks over every Luau example a visitor can copy (the `luau` and `lua` fences of `docs/USER_GUIDE.md` and the
    home snippets in `templates/public/examples/`) against two promises that chapter 3 of the guide makes in so many
    words: every example "gives every function typed parameters and a return type", and "wraps every `HttpService`
    call in `pcall`, because those calls raise an error instead of returning one".

Why it exists
    The owner asked for fully typed examples (2026-10-07), and the guide tells readers what conventions to copy.
    The existing style test (`test_luau_examples.py`) only requires a return type on NAMED functions, so the
    anonymous functions handed to `pcall` (`pcall(function() return HttpService:RequestAsync(...) end)`) have none
    (six of them: four guide examples and the two home snippets they repeat); and the POST example calls
    `HttpService:JSONEncode(request)` outside any `pcall`. luau-analyze accepts both (the types are inferred, and
    JSONEncode of that literal cannot fail), so this is not a type error: it is the guide saying one thing and
    showing another.
    - Finding public-6 (fixed): each pcall wrapper now names its result (`function(): HttpResponse`, a type each
      example declares for the parts of the RequestAsync answer it reads), and the POST example encodes its body
      inside the pcall. `test_luau_examples.py` now checks both promises too, with a block-aware scan.

How it works
    Plain text scanning. A function is any `function` keyword followed by a parameter list; its return type is a
    `:` right after the closing parenthesis. An `HttpService:Method(` call counts as wrapped when a
    `pcall(function` opens on its line or on one of the three lines before it (every wrapped call in the examples is
    written that way). The test now passes and pins both promises.

What to read next
    `docs/USER_GUIDE.md` chapter 3, `tests/unit/public/test_luau_examples.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

from roxy.public import pages

FENCE = re.compile(r"^```(luau|lua)[ \t]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
FUNCTION = re.compile(r"\bfunction\b\s*[\w.:]*\s*(?:<[^>]*>)?\s*\(([^)]*)\)(\s*:)?")
HTTP_CALL = re.compile(r"\bHttpService:(\w+)\(")
GUIDE_PROMISES = (
    "gives every function typed parameters and a return type",
    "wraps every `HttpService` call in\n`pcall`",
)


def examples() -> list[tuple[str, str]]:
    guide = pages.USER_GUIDE_PATH.read_text(encoding="utf-8")
    found = [(f"guide_{index}", match.group(2)) for index, match in enumerate(FENCE.finditer(guide), start=1)]
    found += [
        (f"home_{path.stem}", path.read_text(encoding="utf-8"))
        for path in sorted(pages.HOME_EXAMPLES_DIR.glob("*.luau"))
    ]
    return found


def code_lines(source: str) -> list[str]:
    return [line.split("--", 1)[0] for line in source.splitlines()]


def broken_promises(name: str, source: str) -> list[str]:
    lines = code_lines(source)
    problems: list[str] = []
    for number, line in enumerate(lines, start=1):
        for match in FUNCTION.finditer(line):
            if match.group(2) is None:
                problems.append(f"{name}:{number}: function without a return type: {line.strip()}")
        for match in HTTP_CALL.finditer(line):
            if not inside_pcall(lines, number - 1):
                problems.append(f"{name}:{number}: HttpService:{match.group(1)} outside pcall: {line.strip()}")
    return problems


def inside_pcall(lines: list[str], index: int) -> bool:
    """Is line `index` inside a `pcall(function ... end)` that opens on it or on one of the 3 lines before it? An
    `end)` on a line before it closes such a block first, so a call after a closed pcall is not inside one."""
    for back in range(index, max(-1, index - 4), -1):
        if back < index and lines[back].strip().startswith("end)"):
            return False
        if "pcall(function" in lines[back]:
            return True
    return False


def test_rr_public_guide_still_makes_both_promises() -> None:
    """The premise: chapter 3 states both conventions (if the wording changes, this review test must follow)."""
    text = pages.USER_GUIDE_PATH.read_text(encoding="utf-8")
    for promise in GUIDE_PROMISES:
        assert promise in text, promise


def test_rr_public_every_example_keeps_the_guides_stated_conventions() -> None:
    problems = [problem for name, source in examples() for problem in broken_promises(name, source)]
    print("\n" + "\n".join(problems))
    assert problems == []


def test_rr_public_the_scanner_sees_what_it_should() -> None:
    """Guards the scan itself, so the test above cannot pass by finding nothing."""
    sample = (
        "const ok, value = pcall(function(): string\n\treturn HttpService:GetAsync(URL)\nend)\n"
        "const bad = pcall(function()\n\treturn 1\nend)\nconst body = HttpService:JSONEncode(x)\n"
    )
    found = broken_promises("sample", sample)
    assert len(found) == 2, found
    assert any("without a return type" in problem for problem in found)
    assert any("JSONEncode outside pcall" in problem for problem in found)
    assert Path(pages.USER_GUIDE_PATH).is_file()
    assert len(examples()) >= 9
