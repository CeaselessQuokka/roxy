"""Public site assets: icon weight, stylesheet contrast and non-color cues, the copy button announcement.

What this is
    Unit tests over the files in `roxy/static/public/` and `roxy/templates/public/base.html`: the favicon and the
    Open Graph image are small, the heading anchors in the guide are readable (WCAG 1.4.3), every Luau highlight
    color keeps 4.5:1 against the code background in both themes (here and through `scripts/check_contrast.py
    --public`, which checks every color pair of the public site), every state of the status bar differs by more
    than its color (WCAG 1.4.1 and 1.4.11), and a copy is announced to screen readers through one polite live
    region (WCAG 4.1.3).

Why it exists
    These promises live in static files that no Python code path exercises. v1's 1 MB icons were copied as they
    were, a 0.4 opacity anchor and color-only status cells passed every other test, and the copy button changed
    only its visible text. Each test here pins one of those fixes so a later edit cannot quietly undo it.

How it works
    PNG sizes and dimensions come from the IHDR chunk. The stylesheet is read as text: color tokens from the
    `:root` block (light) and the `prefers-color-scheme: dark` block, rule bodies by selector, and the WCAG
    contrast ratio from the relative luminance of each sRGB color. The script and the base template are checked
    for the live region contract they share.

What to read next
    `roxy/static/public/site.css`, `roxy/static/public/site.js`, `roxy/templates/public/base.html`, and
    `.remake/scripts/p12fix_icons.py` (how the small icons were made from app/static).
"""

from __future__ import annotations

import importlib.util
import re
import struct
import sys
from pathlib import Path
from types import ModuleType

import pytest

from roxy.public import pages
from roxy.public.luau_highlight import CSS_CLASS, SCOPE_CLASS, Kind

STATIC = pages.PUBLIC_STATIC_DIR
# Comments removed, so a comment in front of a rule never becomes part of its selector text.
CSS = re.sub(r"/\*.*?\*/", "", (STATIC / "site.css").read_text(encoding="utf-8"), flags=re.DOTALL)
JS = (STATIC / "site.js").read_text(encoding="utf-8")
BASE = (pages.PUBLIC_TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")

STATUS_STATES = ("operational", "degraded", "paused", "none")


# --- helpers ------------------------------------------------------------------------------------------------------


def png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", path
    assert data[12:16] == b"IHDR", path
    width, height = struct.unpack(">II", data[16:24])
    return int(width), int(height)


def png_chunk_types(path: Path) -> list[bytes]:
    data = path.read_bytes()
    position, kinds = 8, []
    while position < len(data):
        (length,) = struct.unpack(">I", data[position : position + 4])
        kinds.append(data[position + 4 : position + 8])
        position += 12 + length
    return kinds


def tokens(theme: str) -> dict[str, str]:
    """The color tokens of one theme: the light `:root` block, overridden by the dark block for "dark"."""
    light = re.search(r"^:root\s*\{([^}]*)\}", CSS, flags=re.MULTILINE)
    assert light is not None
    values = dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", light.group(1)))
    if theme == "dark":
        dark = re.search(r"@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{([^}]*)\}", CSS)
        assert dark is not None
        values.update(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", dark.group(1)))
    return values


def rule(selector: str) -> dict[str, str]:
    """Declarations of every rule whose selector list contains exactly `selector`, merged in file order."""
    merged: dict[str, str] = {}
    for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", CSS):
        if selector in [part.strip() for part in selectors.split(",")]:
            for name, value in re.findall(r"([a-z-]+)\s*:\s*([^;]+);", body):
                merged[name] = value.strip()
    return merged


def luminance(color: str) -> float:
    def channel(value: int) -> float:
        c = value / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (int(color[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(first: str, second: str) -> float:
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def resolve(value: str, theme: str) -> str:
    match = re.fullmatch(r"var\(--([a-z0-9-]+)\)", value.strip())
    assert match is not None, value
    return tokens(theme)[match.group(1)]


# --- icons (review finding 5) ------------------------------------------------------------------------------------


def test_favicon_is_small() -> None:
    path = STATIC / "roxy_favicon.png"
    assert path.stat().st_size < 16 * 1024  # v1's was 1,075,422 bytes for a 16 to 64 px tab icon
    width, height = png_size(path)
    assert width == height
    assert 32 <= width <= 64


def test_open_graph_image_is_small_and_large_enough_for_link_previews() -> None:
    path = STATIC / "roxy_icon.png"
    assert path.stat().st_size < 60 * 1024  # v1's was 932,130 bytes
    width, height = png_size(path)
    assert width == height
    assert width >= 200  # the smallest square image Open Graph and Twitter summary cards accept


@pytest.mark.parametrize("name", ["roxy_favicon.png", "roxy_icon.png"])
def test_icons_carry_no_metadata(name: str) -> None:
    # v1's files carried EXIF and a 52 KB provenance chunk; a public icon needs pixels only.
    assert set(png_chunk_types(STATIC / name)) <= {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"}


# --- heading anchors in the guide (review finding 8, contrast) ----------------------------------------------------


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_heading_anchor_text_meets_the_text_contrast_minimum(theme: str) -> None:
    anchor = rule(".anchor")
    assert "opacity" not in anchor  # a faded "#" was 1.76:1 (light) and 2.04:1 (dark)
    color = resolve(anchor["color"], theme)
    assert contrast(color, tokens(theme)["bg"]) >= 4.5


# --- Luau highlighting colors (owner request 2026-10-07) ---------------------------------------------------------


def highlight_rules() -> dict[str, str]:
    """Each highlight class (`k`, `s`...) and the color token its `.hl .<class>` rule uses."""
    found: dict[str, str] = {}
    for kind, css_class in CSS_CLASS.items():
        declarations = rule(f".{SCOPE_CLASS} .{css_class}")
        assert "color" in declarations, f"no color rule for .{SCOPE_CLASS} .{css_class} ({kind.value})"
        found[css_class] = declarations["color"]
    return found


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_highlight_colors_meet_the_text_contrast_minimum(theme: str) -> None:
    """WCAG 1.4.3: every highlighted token keeps 4.5:1 against the code background, in both themes."""
    background = tokens(theme)["code-bg"]
    ratios = {css_class: contrast(resolve(value, theme), background) for css_class, value in highlight_rules().items()}
    assert min(ratios.values()) >= 4.5, ratios


def load_contrast_script() -> ModuleType:
    """scripts/check_contrast.py, loaded by path (it is a standalone script, not a package module)."""
    path = Path(__file__).resolve().parents[3] / "scripts" / "check_contrast.py"
    spec = importlib.util.spec_from_file_location("roxy_script_check_contrast_public", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_contrast_script_passes_the_public_palette(capsys: pytest.CaptureFixture[str]) -> None:
    """`scripts/check_contrast.py --public`: every pair site.css uses, both themes, highlight colors included."""
    script = load_contrast_script()
    results = script.check_public((STATIC / "site.css").read_text(encoding="utf-8"))
    assert [result for result in results if not result.ok] == []
    assert {result.theme for result in results} == {"light", "dark"}
    checked = {(result.foreground, result.background) for result in results}
    for value in highlight_rules().values():  # every color a `.hl .x` rule uses is held to 4.5:1 on --code-bg
        assert (value.removeprefix("var(--").removesuffix(")"), "code-bg") in checked
    assert script.main(["--public", "--failures-only"]) == 0
    assert "0 failing" in capsys.readouterr().out


def test_contrast_script_catches_a_weak_highlight_color() -> None:
    script = load_contrast_script()
    css = (STATIC / "site.css").read_text(encoding="utf-8").replace("--hl-comment: #59636f;", "--hl-comment: #9aa3ad;")
    failing = [result for result in script.check_public(css) if not result.ok]
    assert [(result.theme, result.foreground) for result in failing] == [("light", "hl-comment")]


def test_highlight_colors_are_tokens_set_for_both_themes() -> None:
    light, dark = tokens("light"), tokens("dark")
    names = {value.removeprefix("var(--").removesuffix(")") for value in highlight_rules().values()}
    for name in names:
        assert name.startswith("hl-"), name
        assert light[name] != dark[name], f"--{name} needs its own dark theme value"
    # Comments differ by more than color (WCAG 1.4.1): they are italic.
    assert rule(f".{SCOPE_CLASS} .{CSS_CLASS[Kind.COMMENT]}").get("font-style") == "italic"


# --- status bar (review finding 9) -------------------------------------------------------------------------------


def cue(state: str) -> tuple[str, str, str]:
    """What tells a status cell apart without color: its fill pattern, border style and height."""
    declarations = rule(f".cell-{state}")
    background = declarations.get("background", "")
    pattern = re.sub(r"var\(--[a-z0-9-]+\)", "COLOR", background) if "gradient" in background else "solid"
    if background.strip() in ("none", "transparent"):
        pattern = "empty"
    sized = rule(f".uptime .cell-{state}")
    return pattern, declarations.get("border-style", declarations.get("border", "none")), sized.get("height", "")


def test_every_status_state_has_a_cue_besides_color() -> None:
    cues = {state: cue(state) for state in STATUS_STATES}
    assert len(set(cues.values())) == len(STATUS_STATES), cues
    # The pattern alone separates the states, so the legend swatches (all the same size) show the cue too.
    assert len({value[0] + value[1] for value in cues.values()}) == len(STATUS_STATES), cues
    assert cue("maintenance") == cue("paused")  # maintenance is drawn like paused (both refuse with 503)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_status_cells_stand_out_from_the_card(theme: str) -> None:
    surface = tokens(theme)["surface"]
    for state, token in (("operational", "ok"), ("degraded", "degraded"), ("paused", "paused")):
        assert contrast(tokens(theme)[token], surface) >= 3.0, (theme, state)
    # "No data" is an outline: its border, not a faint fill, is what must be visible (WCAG 1.4.11).
    none = rule(".cell-none")
    border_color = re.search(r"var\(--[a-z0-9-]+\)", none.get("border", ""))
    assert border_color is not None, none
    assert contrast(resolve(border_color.group(0), theme), surface) >= 3.0


# --- copy buttons (review finding 10) ----------------------------------------------------------------------------


def test_copy_result_is_announced_through_one_polite_live_region() -> None:
    regions = re.findall(r"<[^>]*\brole=\"status\"[^>]*>", BASE)
    assert len(regions) == 1, regions
    region = regions[0]
    assert 'aria-live="polite"' in region
    region_id = re.search(r'\bid="([^"]+)"', region)
    assert region_id is not None
    assert f'getElementById("{region_id.group(1)}")' in JS
    assert "Copied" in JS


def test_copy_button_name_is_its_visible_text() -> None:
    # A fixed aria-label kept the name "Copy code to clipboard" while the visible text said "Copied!" or "Error".
    assert "aria-label" not in JS
