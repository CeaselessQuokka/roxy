"""Style guard: the plan C5 writing rules applied to strings at runtime (rendered pages, emails, API messages).

What this is
    `find_dashes(text)` and `assert_no_dashes(text)` catch em and en dash characters; `find_style_issues(text)`
    also applies the US spelling rules from `scripts/style_words.txt`. Tests call these on rendered HTML, email
    bodies, refusal messages and the LLM export.

Why it exists
    `scripts/check_style.py` checks source files, but some text only exists after rendering: a template that
    assembles a sentence, a message built from a setting value, a page that includes admin-authored text. Plan
    19.8 asks for rendered pages to pass the same rules, so the same engine is used here.

How it works
    The dash check is built in (two characters, by code point). The spelling check loads `scripts/check_style.py`
    from the repository checkout by file path (it is a standalone script, not part of the installed package), so
    both tools share one implementation and one word list. In an installed release without the scripts
    directory, `find_style_issues` falls back to the dash check only; production code never depends on it.

What to read next
    `scripts/check_style.py` and `scripts/style_words.txt`.
"""

from __future__ import annotations

import importlib.util
import sys
from functools import cache
from pathlib import Path
from types import ModuleType

EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)
_DASH_NAMES = {EM_DASH: "em dash (U+2014)", EN_DASH: "en dash (U+2013)"}

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECK_STYLE_SCRIPT = REPO_ROOT / "scripts" / "check_style.py"


def find_dashes(text: str) -> list[tuple[int, int, str]]:
    """Every em or en dash in `text` as (line, column, name), both counted from 1."""
    found: list[tuple[int, int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for column, char in enumerate(line, start=1):
            if char in _DASH_NAMES:
                found.append((number, column, _DASH_NAMES[char]))
    return found


def assert_no_dashes(text: str, where: str = "text") -> None:
    """Raise AssertionError naming every dash in `text` (for tests)."""
    found = find_dashes(text)
    if found:
        listing = ", ".join(f"line {line} column {column}: {name}" for line, column, name in found[:20])
        raise AssertionError(f"{where} contains dash characters (plan C5): {listing}")


@cache
def _check_style_module() -> ModuleType | None:
    if not CHECK_STYLE_SCRIPT.is_file():
        return None
    spec = importlib.util.spec_from_file_location("roxy_check_style", CHECK_STYLE_SCRIPT)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    # Registered before running it, so its dataclasses can resolve their own module (standard importlib recipe).
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def find_style_issues(text: str, where: str = "<text>") -> list[str]:
    """Every C5 problem in `text` (dashes and British spellings) as `where:line:column: message` strings."""
    module = _check_style_module()
    if module is None:
        return [f"{where}:{line}:{column}: {name}" for line, column, name in find_dashes(text)]
    rules = module.load_rules()
    return [str(issue) for issue in module.check_text(text, rules, where)]


def assert_style_clean(text: str, where: str = "text") -> None:
    """Raise AssertionError listing every C5 problem in `text` (for tests of rendered output)."""
    issues = find_style_issues(text, where)
    if issues:
        raise AssertionError("style problems (plan C5):\n" + "\n".join(issues[:50]))
