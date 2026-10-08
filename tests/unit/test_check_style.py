"""Tests for scripts/check_style.py (plan C5): dashes, British spellings, inflections, exceptions, URLs, the CLI."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
EM, EN = chr(0x2014), chr(0x2013)


def b(*parts: str) -> str:
    """Join word parts at runtime, so a British spelling under test never appears in this file's source."""
    return "".join(parts)


@pytest.fixture(scope="module")
def cs() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_style_under_test", REPO / "scripts" / "check_style.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def rules(cs: ModuleType) -> object:
    return cs.load_rules()


def messages(cs: ModuleType, rules: object, text: str) -> list[str]:
    return [issue.message for issue in cs.check_text(text, rules, "t.txt")]


def test_em_and_en_dash_fail(cs: ModuleType, rules: object) -> None:
    found = cs.check_text(f"ok line\nToo many requests {EM} please slow down.\npages 1{EN}3", rules, "x.py")
    assert [(i.line, i.column) for i in found] == [(2, 19), (3, 8)]
    assert "em dash" in found[0].message
    assert "en dash" in found[1].message


def test_dash_html_entities_fail(cs: ModuleType, rules: object) -> None:
    for entity in (b("&", "mdash;"), b("&", "ndash;"), b("&#", "8212;"), b("&#x", "2013;")):
        assert len(cs.check_text(f"<p>a {entity} b</p>", rules, "x.html")) == 1


def test_dash_inside_url_still_fails(cs: ModuleType, rules: object) -> None:
    assert len(cs.check_text(f"see https://example.test/a{EM}b", rules)) == 1


def test_plain_hyphen_passes(cs: ModuleType, rules: object) -> None:
    assert cs.check_text("a plain - hyphen and x-csrf-token", rules) == []


def test_british_word_fails_with_replacement(cs: ModuleType, rules: object) -> None:
    [message] = messages(cs, rules, f"the {b('colo', 'ur')} picker")
    assert "'color'" in message


@pytest.mark.parametrize(
    "word",
    [
        b("Colo", "ur"),
        b("COLO", "URS"),
        b("colo", "ured"),
        b("behavio", "ural"),
        b("optimi", "sed"),
        b("optimi", "sing"),
        b("optimi", "sation"),
        b("initiali", "ser"),
        b("cent", "re"),
        b("cent", "red"),
        b("licen", "ce"),
        b("catalo", "gue"),
        b("cataloguin", "g"),
        b("cancel", "led"),
        b("model", "ling"),
        b("arte", "facts"),
        b("judge", "ment"),
        b("whil", "st"),
        b("gre", "y"),
        b("enro", "l"),
        b("fulfi", "l"),
        b("favo", "urite"),
        b("ui_colo", "ur"),  # identifiers are words too (underscore is a boundary)
    ],
)
def test_british_spellings_and_inflections_fail(cs: ModuleType, rules: object, word: str) -> None:
    assert len(messages(cs, rules, f"x {word} y")) == 1, word


@pytest.mark.parametrize(
    "text",
    [
        "color colors colored behavior optimize normalized canceled labeled modeled",
        "programming programmed programmer programmable",  # US spellings sharing a stem with the banned form
        "analyses",  # the plural of analysis
        "enrolled enrolling fulfilled fulfilling",  # US spellings; those two rules match the exact word only
        "central centralize center centered",  # cent[r]e must not match central
        "license metric meter parameters",
        "asyncio.CancelledError and isCanceled",
        "greyhound",  # \\bgr[e]y\\b is the exact word only
    ],
)
def test_us_spellings_pass(cs: ModuleType, rules: object, text: str) -> None:
    assert messages(cs, rules, text) == []


def test_exceptions_skip_urls_and_identifiers(cs: ModuleType, rules: object) -> None:
    url = f"https://example.test/{b('colo', 'ur')}/{b('cent', 're')}?{b('behavio', 'ur')}=1"
    assert messages(cs, rules, f"see {url} for details") == []
    assert messages(cs, rules, f"if task.{b('cancel', 'led')}(): return") == []
    # The same word outside the URL still fails.
    assert len(messages(cs, rules, f"see {url} for the {b('colo', 'ur')}")) == 1


def test_words_file_and_checker_pass_their_own_check(cs: ModuleType) -> None:
    assert cs.main([str(REPO / "scripts" / "style_words.txt"), str(REPO / "scripts" / "check_style.py")]) == 0


def test_plan_passes_the_style_gate(cs: ModuleType) -> None:
    """P0 exit gate: `python scripts/check_style.py REMAKE_PLAN.md` passes."""
    assert cs.main([str(REPO / "REMAKE_PLAN.md")]) == 0


def test_cli_exit_codes(cs: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    clean = tmp_path / "clean.md"
    clean.write_text("All good; nothing to see.\n", encoding="utf-8")
    dirty = tmp_path / "dirty.md"
    dirty.write_text(f"Bad {EM} line\nthe {b('colo', 'ur')}\n", encoding="utf-8")
    assert cs.main([str(clean)]) == 0
    assert cs.main([str(dirty)]) == 1
    out = capsys.readouterr().out
    assert "dirty.md:1:5: em dash" in out
    assert "dirty.md:2:5: British spelling" in out
    assert cs.main([str(tmp_path / "missing.md")]) == 2


def test_directory_walk_skips_v1_and_generated_dirs(cs: ModuleType) -> None:
    files = {cs._relative(p) for p in cs.iter_files([REPO])}
    assert files, "the repository walk found nothing"
    for skipped in ("app/", "Tooling/", "Unused/", "env2/", ".venv/", ".remake/", "tests/fixtures/v1/", ".git/"):
        assert not any(f.startswith(skipped) for f in files), skipped
    assert "src/roxy/core/redact.py" in files


def test_default_tree(cs: ModuleType) -> None:
    defaults = {p.name for p in cs.default_paths()}
    assert {"src", "tests", "scripts"} <= defaults
    assert "REMAKE_PLAN.md" not in defaults  # checked by naming it explicitly (the P0 gate, a separate CI step)


def test_explicit_file_is_checked_even_in_a_skipped_dir(cs: ModuleType, rules: object) -> None:
    # A file named on the command line is always checked (here a v1 file, which still has dashes).
    v1_file = REPO / "app" / "proxy.py"
    if not v1_file.exists():
        pytest.skip("v1 source not present")
    assert list(cs.iter_files([v1_file])) == [v1_file]


@pytest.mark.parametrize("name", ["tests/smoke_test.py", "tests/deploy_test.sh", "tests/boot_check.sh"])
def test_v1_test_suites_are_scanned_and_clean(cs: ModuleType, rules: object, name: str) -> None:
    """Spec review 13: plan C5 has no exception for the v1 test suites kept under tests/."""
    path = REPO / name
    assert not cs._skipped(path)
    assert cs.check_paths([path], rules) == []
