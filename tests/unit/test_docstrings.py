"""Teaching docstrings (plan principle P7): every v2 module opens with the same four short parts.

What this is
    One test that reads every module under `src/roxy` (packages included) and checks that its docstring has the
    four sections "What this is", "Why it exists", "How it works" and "What to read next", and that every file
    or document a docstring points at as `docs/...` exists.

Why it exists
    The owner learns the code base from these docstrings. A package `__init__` with an empty docstring, or one
    pointing at a guide that does not exist, breaks the reading path at its first step (spec review 12).

How it works
    `ast.get_docstring` on each file, then plain substring checks; no module is imported.

What to read next
    `src/roxy/__init__.py` (where the reading order starts) and any module's docstring.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "roxy"
SECTIONS = ("What this is", "Why it exists", "How it works", "What to read next")
MODULES = sorted(path for path in SOURCE.rglob("*.py") if "__pycache__" not in path.parts)


@pytest.mark.parametrize("path", MODULES, ids=lambda p: str(p.relative_to(SOURCE)))
def test_module_docstring_has_the_four_parts(path: Path) -> None:
    docstring = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))) or ""
    missing = [section for section in SECTIONS if section not in docstring]
    assert missing == [], f"{path.relative_to(ROOT)} lacks {missing}"


def test_docs_named_in_docstrings_and_pyproject_exist() -> None:
    texts = [path.read_text(encoding="utf-8") for path in MODULES]
    texts.append((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    named = {match for text in texts for match in re.findall(r"\bdocs/[A-Za-z0-9_./-]+\.md\b", text)}
    missing = sorted(name for name in named if not (ROOT / name).is_file())
    assert missing == []


def test_changes_md_records_plan_conflicts() -> None:
    """Spec review 11: DESIGN.md section 0 and plan 18.1 require CHANGES.md with this section."""
    text = (ROOT / "CHANGES.md").read_text(encoding="utf-8")
    assert "## Plan conflicts and deviations" in text
    for topic in ("Memory sizing", "credential_endpoint_allowlist", "re_compat", "multiget-place-details"):
        assert topic in text, topic
