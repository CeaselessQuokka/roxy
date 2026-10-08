"""Style guard tests: the C5 rules applied to rendered strings."""

from __future__ import annotations

import pytest

from roxy.core.style_guard import assert_no_dashes, assert_style_clean, find_dashes, find_style_issues

EM, EN = chr(0x2014), chr(0x2013)
BRITISH_COLOR = "colo" + "ur"  # assembled at runtime so this file passes the style check itself


def test_find_dashes_reports_line_and_column() -> None:
    assert find_dashes(f"ok\nab{EM}c{EN}") == [(2, 3, "em dash (U+2014)"), (2, 5, "en dash (U+2013)")]
    assert find_dashes("plain - hyphen") == []


def test_assert_no_dashes() -> None:
    assert_no_dashes("fine; really")
    with pytest.raises(AssertionError, match="em dash"):
        assert_no_dashes(f"Too many requests {EM} please slow down.", "refusal text")


def test_find_style_issues_uses_the_word_list() -> None:
    issues = find_style_issues(f"<p>Pick a {BRITISH_COLOR}</p>", "page.html")
    assert len(issues) == 1
    assert issues[0].startswith("page.html:1:")
    assert "'color'" in issues[0]
    assert find_style_issues("<p>Pick a color</p>") == []


def test_assert_style_clean() -> None:
    assert_style_clean("Too many requests; please slow down.")
    with pytest.raises(AssertionError):
        assert_style_clean(f"{BRITISH_COLOR}s {EM} dashes")
