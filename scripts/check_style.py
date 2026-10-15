#!/usr/bin/env python3
"""Writing style check (plan C5): no em or en dash characters, and US English spelling, everywhere in v2.

What this is
    A command line checker. `python scripts/check_style.py` scans the default v2 tree (src, tests, scripts, docs,
    deploy, .github and the root *.md files); `python scripts/check_style.py PATH...` scans the given files or
    directories (REMAKE_PLAN.md is scanned this way, as the P0 gate). It prints `path:line:column: message` for
    each problem and exits 1 if there was any, 0 otherwise.

Why it exists
    The owner asked for no em dash (U+2014) or en dash (U+2013) characters and US spelling in code, comments, UI
    text, docs and test names. A rule nobody checks erodes, so CI runs this on every push, and it reads its word
    list from `scripts/style_words.txt` so the owner and CI see exactly the same rules.

How it works
    Dashes: every line is searched for the two characters and for the HTML entities that render them; there are no
    exceptions. Words: each rule in style_words.txt is a case-insensitive regular expression for a British
    spelling. It is wrapped so it matches only whole words plus common inflections (the rule `colo[u]r` also
    catches the plural and past forms, and `optimi[s]e` the -ing, -er and -ation forms), never the inside of a
    longer word. Examples in this file keep the brackets, so it passes its own check. Before the word rules run,
    text matched by the file's [exceptions] section (URLs, identifiers such as asyncio's `Task.cancel[l]ed()`) is
    blanked out.
    Walking a directory skips generated directories, the v1 source and the third-party libraries vendored byte
    for byte (`SKIPPED_RELATIVE_PATHS` gives the reason for each entry); a file named on the command line is
    always checked.
    The script uses only the standard library, so it runs with any Python 3.12, with or without the project
    environment. `roxy/core/style_guard.py` loads this file to apply the same rules to rendered pages in tests.

What to read next
    `scripts/style_words.txt` (the rules), then `roxy/core/style_guard.py`.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORDS_FILE = Path(__file__).resolve().parent / "style_words.txt"

DEFAULT_ROOTS = ("src", "tests", "scripts", "docs", "deploy", ".github")
"""Directories scanned when no path is given, plus every *.md file at the repository root."""

ROOT_MARKDOWN_SKIPPED_BY_DEFAULT = frozenset({"REMAKE_PLAN.md"})
"""The plan is checked when named explicitly (`check_style.py REMAKE_PLAN.md`, a separate CI step)."""

SKIPPED_DIR_NAMES = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".hypothesis",
        "test-results",
        "playwright-report",
    }
)
"""Generated directories skipped wherever they appear."""

SKIPPED_RELATIVE_PATHS = frozenset(
    {
        "app",  # v1 source, replaced by src/roxy
        "Tooling",  # v1 deploy tooling
        "Unused",
        "env2",  # v1 virtualenv
        ".venv",
        ".remake",  # working notes of the remake run
        "tests/fixtures/v1",  # v1 data used as test input; must stay byte-identical to v1
        # Third-party libraries vendored byte for byte. Their text is not ours to rewrite: editing them to satisfy
        # our style rules would fork the library, and for the served ones (htmx, Alpine, uPlot) it would also break
        # the SRI hashes recorded in src/roxy/static/vendor/VERSIONS.md, so browsers would refuse the files.
        "src/roxy/static/vendor",
        "tests/e2e/vendor",  # axe-core, used only by the accessibility tests, copied unchanged from its release
        # The v1 test suites under tests/ (smoke_test.py, deploy_test.sh, boot_check.sh) are scanned like
        # everything else: plan C5 has no exception for them, and their dashes were only in comments.
    }
)
"""Paths (relative to the repository root, forward slashes) skipped when reached by walking a directory.
A file named explicitly on the command line is always checked."""

BINARY_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".webp",
        ".avif",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".pdf",
        ".zip",
        ".gz",
        ".zst",
        ".br",
        ".db",
        ".sqlite",
        ".pyc",
        ".whl",
        ".so",
        ".mo",
        ".lock",
    }
)

# The two characters, written by code point so this file contains neither of them.
EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)
_DASH_FORMS: tuple[tuple[str, str], ...] = (
    (EM_DASH, "em dash character (U+2014)"),
    (EN_DASH, "en dash character (U+2013)"),
    # HTML entities render as the same characters in a browser. Assembled from parts, again so this file is clean.
    ("&" + "mdash;", "em dash HTML entity"),
    ("&" + "ndash;", "en dash HTML entity"),
    ("&#" + "8212;", "em dash HTML entity"),
    ("&#" + "8211;", "en dash HTML entity"),
    ("&#x" + "2014;", "em dash HTML entity"),
    ("&#x" + "2013;", "en dash HTML entity"),
)
_DASH_RE = re.compile("|".join(re.escape(form) for form, _name in _DASH_FORMS), re.IGNORECASE)
_DASH_NAMES = {form.lower(): name for form, name in _DASH_FORMS}

# Inflections a banned word may carry and still be the same (banned) word.
# (A superset of the list `config/catalog.py` uses for setting texts, so this check is never the weaker one.)
_SUFFIXES = "s|es|d|ed|ing|ings|al|ally|ly|ful|less|able|ably|er|ers|ist|ists|ite|ites|ism|hood|ation|ations|y"
# Inflections that drop a final "e" first (the -ing, -ation, -er and -able forms of `optimi[s]e`).
_E_DROP_SUFFIXES = "ing|ings|ation|ations|er|ers|able"


@dataclass(frozen=True)
class WordRule:
    pattern: str  # the regular expression as written in the words file
    replacement: str  # the US spelling to use instead


@dataclass(frozen=True)
class Rules:
    words: tuple[WordRule, ...]
    exceptions: tuple[str, ...]
    word_re: re.Pattern[str] | None
    exception_re: re.Pattern[str] | None


@dataclass(frozen=True)
class Issue:
    path: str
    line: int
    column: int
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}: {self.message}"


def parse_rules(text: str) -> Rules:
    """Parse the words file format (see the top of style_words.txt)."""
    words: list[WordRule] = []
    exceptions: list[str] = []
    section = "words"
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]") and line[1:-1] in ("words", "exceptions"):
            section = line[1:-1]
            continue
        if section == "words":
            parts = line.split(None, 1)
            if len(parts) != 2:
                raise ValueError(f"style words line {number}: expected '<pattern> <replacement>', got {raw!r}")
            pattern, replacement = parts[0], parts[1].strip()
            re.compile(pattern)  # fail early, with the line number in the traceback context
            words.append(WordRule(pattern, replacement))
        else:
            re.compile(line)
            exceptions.append(line)
    return Rules(
        words=tuple(words),
        exceptions=tuple(exceptions),
        word_re=_compile_words(words),
        exception_re=re.compile("|".join(f"(?:{e})" for e in exceptions), re.IGNORECASE) if exceptions else None,
    )


def _compile_words(words: Sequence[WordRule]) -> re.Pattern[str] | None:
    """One regular expression for all rules; the named group that matched says which rule it was."""
    if not words:
        return None
    alternatives: list[str] = []
    for index, rule in enumerate(words):
        alternatives.append(f"(?P<w{index}>(?:{rule.pattern})(?:{_SUFFIXES})?)")
        if rule.pattern.endswith("e") and not rule.pattern.endswith("\\e"):
            alternatives.append(f"(?P<e{index}>(?:{rule.pattern[:-1]})(?:{_E_DROP_SUFFIXES}))")
    # Whole words only: no letter directly before or after (digits, underscores and punctuation are boundaries,
    # so an identifier like `ui_colo[u]r` without the brackets is caught too).
    return re.compile(r"(?<![A-Za-z])(?:" + "|".join(alternatives) + r")(?![A-Za-z])", re.IGNORECASE)


def load_rules(path: Path = DEFAULT_WORDS_FILE) -> Rules:
    return parse_rules(path.read_text(encoding="utf-8"))


def _blank(match: re.Match[str]) -> str:
    return " " * len(match.group(0))


def check_text(text: str, rules: Rules, path: str = "<text>") -> list[Issue]:
    """Every style problem in `text` (line and column numbers start at 1)."""
    issues: list[Issue] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for match in _DASH_RE.finditer(line):
            name = _DASH_NAMES.get(match.group(0).lower(), "dash")
            advice = "use a semicolon, colon, comma, parentheses or a plain hyphen"
            issues.append(Issue(path, number, match.start() + 1, f"{name}: {advice}"))
        if rules.word_re is None:
            continue
        scrubbed = rules.exception_re.sub(_blank, line) if rules.exception_re is not None else line
        for match in rules.word_re.finditer(scrubbed):
            group = match.lastgroup or ""
            rule = rules.words[int(group[1:])] if group[1:].isdigit() else None
            replacement = rule.replacement if rule is not None else "the US spelling"
            issues.append(
                Issue(path, number, match.start() + 1, f"British spelling {match.group(0)!r}: use {replacement!r}")
            )
    return issues


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return True
    try:
        with path.open("rb") as handle:
            return b"\0" in handle.read(8192)
    except OSError:
        return True


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _skipped(path: Path) -> bool:
    relative = _relative(path)
    if any(relative == skip or relative.startswith(skip + "/") for skip in SKIPPED_RELATIVE_PATHS):
        return True
    return path.name in SKIPPED_DIR_NAMES and path.is_dir()


def iter_files(paths: Iterable[Path]) -> Iterator[Path]:
    """Files to scan: explicit files always; directories walked with the skip lists applied."""
    for path in paths:
        if path.is_file():
            yield path
            continue
        if not path.is_dir():
            raise FileNotFoundError(f"no such file or directory: {path}")
        for directory, subdirs, files in os.walk(path):
            current = Path(directory)
            subdirs[:] = sorted(d for d in subdirs if not _skipped(current / d))
            for name in sorted(files):
                candidate = current / name
                if not _skipped(candidate) and not _is_binary(candidate):
                    yield candidate


def default_paths(root: Path = REPO_ROOT) -> list[Path]:
    """The default v2 tree: the DEFAULT_ROOTS that exist plus root *.md (except the plan, checked explicitly)."""
    paths = [root / name for name in DEFAULT_ROOTS if (root / name).exists()]
    paths.extend(sorted(p for p in root.glob("*.md") if p.is_file() and p.name not in ROOT_MARKDOWN_SKIPPED_BY_DEFAULT))
    return paths


def check_paths(paths: Iterable[Path], rules: Rules) -> list[Issue]:
    issues: list[Issue] = []
    for path in iter_files(paths):
        text = path.read_text(encoding="utf-8", errors="replace")
        issues.extend(check_text(text, rules, _relative(path)))
    return issues


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check for em/en dashes and British spellings (plan C5).")
    parser.add_argument("paths", nargs="*", type=Path, help="files or directories (default: the v2 tree)")
    parser.add_argument("--words", type=Path, default=DEFAULT_WORDS_FILE, help="the banned words file")
    args = parser.parse_args(argv)
    rules = load_rules(args.words)
    paths = list(args.paths) if args.paths else default_paths()
    try:
        issues = check_paths(paths, rules)
    except FileNotFoundError as exc:
        print(f"check_style: {exc}", file=sys.stderr)
        return 2
    github = os.environ.get("GITHUB_ACTIONS") == "true"
    for issue in issues:
        print(issue)
        if github:  # also shown inline on the pull request diff
            print(f"::error file={issue.path},line={issue.line},col={issue.column}::{issue.message}")
    scanned = "the given paths" if args.paths else "the v2 tree"
    if issues:
        print(f"check_style: {len(issues)} problem(s) in {scanned}", file=sys.stderr)
        return 1
    print(f"check_style: OK ({scanned})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
