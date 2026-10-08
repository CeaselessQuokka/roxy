#!/usr/bin/env python3
"""Contrast check for the dashboard design tokens and the public site palette (plan 14.4, 14.9, 16.1; WCAG 2.2 AA).

What this is
    A command line checker. `python scripts/check_contrast.py` reads `src/roxy/static/css/tokens.css`, resolves
    every color token for the light and the dark theme, and checks each foreground and background pair the
    dashboard uses against its WCAG minimum: 4.5:1 for text, 3:1 for control boundaries, the focus ring and chart
    marks. `python scripts/check_contrast.py --public` does the same for the public site's
    `src/roxy/static/public/site.css`: page text, links, buttons, the status bar, and every Luau highlight color on
    the code background. It prints one line per pair and exits 1 when any pair falls short, 0 otherwise.

Why it exists
    "Meets AA" is a claim that drifts the moment someone nudges a hex value. The plan asks for both themes to pass,
    and this check turns the claim into a test (tests/unit/ui/test_ui_static.py runs the dashboard check,
    tests/unit/public/test_public_assets.py the public one), so a color edit that breaks contrast fails CI instead
    of shipping unreadable text.

How it works
    Each token in tokens.css is `--name: light-dark(<light>, <dark>)` or a single color for both themes; `var()`
    references to other tokens are followed. site.css keeps its light values in the first `:root` block and
    overrides them in a `@media (prefers-color-scheme: dark) { :root { ... } }` block, so `parse_public_tokens`
    reads both blocks into the same (light, dark) form. The WCAG relative luminance of each sRGB color is computed
    (linearize each channel, weight 0.2126 R + 0.7152 G + 0.0722 B), and the contrast ratio is
    (lighter + 0.05) / (darker + 0.05). The pairs below say which token sits on which surface in the components,
    so a token that is never used as text is not held to the text minimum. Standard library only.

What to read next
    `src/roxy/static/css/tokens.css` (the values), then `src/roxy/static/css/components.css` (where pairs come from);
    for the public site, `src/roxy/static/public/site.css` and `src/roxy/public/luau_highlight.py`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOKENS_FILE = REPO_ROOT / "src" / "roxy" / "static" / "css" / "tokens.css"
PUBLIC_CSS_FILE = REPO_ROOT / "src" / "roxy" / "static" / "public" / "site.css"
THEMES = ("light", "dark")

TEXT_MIN = 4.5  # WCAG 1.4.3: body text (the dashboard's 12 to 16 px text is never "large")
NON_TEXT_MIN = 3.0  # WCAG 1.4.11: control boundaries, focus indicators, chart marks (plan 14.4)

SURFACES = ("bg", "surface-1", "surface-2", "surface-3")
CHART_SURFACES = ("bg", "surface-1", "surface-2")  # charts and controls never sit on the hover color
TEXT_TOKENS = ("text", "text-muted", "accent", "ok", "warn", "bad", "info")
STATUS = ("ok", "warn", "bad", "info")


@dataclass(frozen=True)
class Pair:
    foreground: str
    background: str
    minimum: float
    why: str


@dataclass(frozen=True)
class Result:
    theme: str
    foreground: str
    background: str
    ratio: float
    minimum: float
    ok: bool
    why: str


def required_pairs() -> list[Pair]:
    """Every token pair the components put together, with the minimum WCAG asks of it."""
    pairs: list[Pair] = []
    for fg in TEXT_TOKENS:
        for bg in SURFACES:
            pairs.append(Pair(fg, bg, TEXT_MIN, "text on a surface"))
    for status in STATUS:
        # Badges and banners: the status color as text on its own soft background, plus body text on it.
        pairs.append(Pair(status, f"{status}-soft", TEXT_MIN, "status badge text"))
        pairs.append(Pair("text", f"{status}-soft", TEXT_MIN, "banner body text"))
        pairs.append(Pair("text-muted", f"{status}-soft", TEXT_MIN, "banner secondary text"))
        # Solid status buttons (Resume proxy on the pause banner) put inverse text on the status color.
        pairs.append(Pair("text-inverse", status, TEXT_MIN, "text on a solid status color"))
    pairs.append(Pair("on-accent", "accent-bg", TEXT_MIN, "primary button text"))
    pairs.append(Pair("accent", "accent-soft", TEXT_MIN, "selected item text"))
    pairs.append(Pair("text", "accent-soft", TEXT_MIN, "text in a selected row"))
    pairs.append(Pair("bg", "text", TEXT_MIN, "tooltip text (the tooltip inverts the page colors)"))
    for bg in SURFACES:
        pairs.append(Pair("focus-ring", bg, NON_TEXT_MIN, "focus indicator"))
    for bg in CHART_SURFACES:
        pairs.append(Pair("border-strong", bg, NON_TEXT_MIN, "input and switch boundary"))
        pairs.append(Pair("accent-bg", bg, NON_TEXT_MIN, "primary button and checked switch"))
        for index in range(1, 9):
            pairs.append(Pair(f"series-{index}", bg, NON_TEXT_MIN, "chart mark"))
    return pairs


# The public site (site.css): which token sits on which surface.
PUBLIC_HIGHLIGHT_TOKENS = (
    "hl-keyword",
    "hl-string",
    "hl-number",
    "hl-comment",
    "hl-builtin",
    "hl-type",
    "hl-operator",
)
"""The Luau highlight colors (`.hl .k` and friends); every one is text on `--code-bg` inside `<pre>`."""


def public_required_pairs() -> list[Pair]:
    """Every token pair site.css puts together, with the minimum WCAG asks of it."""
    pairs = [
        Pair(token, "code-bg", TEXT_MIN, "Luau highlight color in a code block") for token in PUBLIC_HIGHLIGHT_TOKENS
    ]
    for bg in ("bg", "surface", "surface-2", "code-bg"):
        pairs.append(Pair("text", bg, TEXT_MIN, "body text, table headers, the copy button and inline code"))
    for bg in ("bg", "surface", "code-bg"):
        pairs.append(Pair("primary", bg, TEXT_MIN, "link text, also around inline code"))
        pairs.append(Pair("primary-strong", bg, TEXT_MIN, "link text on hover"))
    for bg in ("bg", "surface"):
        pairs.append(Pair("text-dim", bg, TEXT_MIN, "tagline and lead paragraphs"))
        pairs.append(Pair("muted", bg, TEXT_MIN, "footer, muted notes and heading anchors"))
        pairs.append(Pair("primary", bg, NON_TEXT_MIN, "focus ring"))
    pairs.append(Pair("on-primary", "primary", TEXT_MIN, "primary button text"))
    pairs.append(Pair("on-primary", "primary-strong", TEXT_MIN, "primary button text on hover"))
    for status in ("ok", "degraded", "paused"):
        pairs.append(Pair(status, "surface", NON_TEXT_MIN, "status bar cell and state dot"))
    pairs.append(Pair("muted", "surface", NON_TEXT_MIN, "outline of a status cell with no data"))
    return pairs


# ------------------------------------------------------------------------------------------- parsing

_ROOT_BLOCK = re.compile(r":root\s*\{(?P<body>.*?)\n\}", re.DOTALL)
_DECLARATION = re.compile(r"--(?P<name>[a-z0-9-]+)\s*:\s*(?P<value>[^;]+);")
_LIGHT_DARK = re.compile(r"^light-dark\(\s*(?P<light>[^,()]+(?:\([^()]*\))?)\s*,\s*(?P<dark>.+)\)\s*$", re.DOTALL)
_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_VAR = re.compile(r"^var\(\s*--(?P<name>[a-z0-9-]+)\s*\)$")


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def parse_tokens(css: str) -> dict[str, tuple[str, str]]:
    """Token name -> (light value, dark value), from the first `:root { ... }` block."""
    match = _ROOT_BLOCK.search(_strip_comments(css))
    if match is None:
        raise ValueError("tokens.css has no :root block")
    tokens: dict[str, tuple[str, str]] = {}
    for declaration in _DECLARATION.finditer(match.group("body")):
        value = " ".join(declaration.group("value").split())
        both = _LIGHT_DARK.match(value)
        if both:
            tokens[declaration.group("name")] = (both.group("light").strip(), both.group("dark").strip())
        else:
            tokens[declaration.group("name")] = (value, value)
    return tokens


_PUBLIC_LIGHT = re.compile(r"^:root\s*\{(?P<body>[^{}]*)\}", re.MULTILINE)
_PUBLIC_DARK = re.compile(r"@media\s*\(prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{(?P<body>[^{}]*)\}")


def parse_public_tokens(css: str) -> dict[str, tuple[str, str]]:
    """Token name -> (light value, dark value) for site.css: the first top-level `:root` block holds the light
    values, and the `prefers-color-scheme: dark` block overrides some of them for the dark theme."""
    css = _strip_comments(css)
    light_block = _PUBLIC_LIGHT.search(css)
    dark_block = _PUBLIC_DARK.search(css)
    if light_block is None or dark_block is None:
        raise ValueError("site.css needs a :root block and a prefers-color-scheme: dark :root block")

    def declarations(body: str) -> dict[str, str]:
        return {d.group("name"): " ".join(d.group("value").split()) for d in _DECLARATION.finditer(body)}

    light = declarations(light_block.group("body"))
    dark = declarations(dark_block.group("body"))
    return {name: (value, dark.get(name, value)) for name, value in light.items()}


def resolve(tokens: dict[str, tuple[str, str]], name: str, theme: str, depth: int = 0) -> str:
    """The final hex color of a token in one theme, following var() references."""
    if depth > 10:
        raise ValueError(f"--{name}: var() references loop")
    if name not in tokens:
        raise KeyError(f"--{name} is not defined in tokens.css")
    value = tokens[name][0 if theme == "light" else 1]
    ref = _VAR.match(value)
    if ref:
        return resolve(tokens, ref.group("name"), theme, depth + 1)
    if not _HEX.match(value):
        raise ValueError(f"--{name} ({theme}) is {value!r}; contrast pairs must be plain hex colors")
    return value


def _channel(value: int) -> float:
    srgb = value / 255
    return srgb / 12.92 if srgb <= 0.04045 else ((srgb + 0.055) / 1.055) ** 2.4


def luminance(hex_color: str) -> float:
    """WCAG relative luminance of `#rgb` or `#rrggbb`."""
    digits = hex_color.lstrip("#")
    if len(digits) == 3:
        digits = "".join(ch * 2 for ch in digits)
    red, green, blue = (int(digits[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(red) + 0.7152 * _channel(green) + 0.0722 * _channel(blue)


def contrast(first: str, second: str) -> float:
    """WCAG contrast ratio between two colors (1.0 to 21.0)."""
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def check(css: str, pairs: Iterable[Pair] | None = None) -> list[Result]:
    """Every dashboard pair (or `pairs`) in both themes, from tokens.css text."""
    return _check(parse_tokens(css), list(pairs) if pairs is not None else required_pairs())


def check_public(css: str, pairs: Iterable[Pair] | None = None) -> list[Result]:
    """Every public site pair (or `pairs`) in both themes, from site.css text."""
    return _check(parse_public_tokens(css), list(pairs) if pairs is not None else public_required_pairs())


def _check(tokens: dict[str, tuple[str, str]], pairs: list[Pair]) -> list[Result]:
    results: list[Result] = []
    for theme in THEMES:
        for pair in pairs:
            ratio = contrast(resolve(tokens, pair.foreground, theme), resolve(tokens, pair.background, theme))
            results.append(
                Result(
                    theme,
                    pair.foreground,
                    pair.background,
                    round(ratio, 2),
                    pair.minimum,
                    ratio >= pair.minimum,
                    pair.why,
                )
            )
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check WCAG contrast of the dashboard tokens or the public site.")
    parser.add_argument(
        "tokens", nargs="?", type=Path, default=None, help="path to tokens.css (or site.css with --public)"
    )
    parser.add_argument("--public", action="store_true", help="check the public site palette in site.css")
    parser.add_argument("--json", action="store_true", help="print the results as JSON")
    parser.add_argument("--failures-only", action="store_true", help="print only the pairs that fail")
    args = parser.parse_args(argv)
    path = args.tokens or (PUBLIC_CSS_FILE if args.public else TOKENS_FILE)
    css = path.read_text(encoding="utf-8")
    results = check_public(css) if args.public else check(css)
    failures = [r for r in results if not r.ok]
    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        for r in failures if args.failures_only else results:
            mark = "ok  " if r.ok else "FAIL"
            print(
                f"{mark} {r.theme:5} {r.ratio:5.2f} >= {r.minimum:3.1f}  --{r.foreground} on --{r.background} ({r.why})"
            )
        print(f"check_contrast: {len(results)} pairs, {len(failures)} failing")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
