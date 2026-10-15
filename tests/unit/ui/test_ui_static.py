"""Static checks of the dashboard design system: contrast, vendored files, CSP-safe markup and scripts, glossary.

What this is
    Fast tests that read files only (no browser): the token contrast proof, the light-dark() rules (colors only
    inside it, and a fallback block for browsers without it that matches every token), the vendored libraries
    against their recorded hashes, the templates and scripts against the CSP rules, and docs/glossary.yml against
    plan section 21.

Why it exists
    The browser tests (tests/e2e) prove the pages work; these keep the rules from eroding between browser runs:
    one new `style=""` in a template, an `innerHTML` in a script, a token edit that drops contrast below AA, or a
    vendored file that no longer matches its SRI hash would each be caught in milliseconds.

How it works
    scripts/check_contrast.py and scripts/check_style.py are loaded by path (they are standalone scripts). Hashes are
    recomputed with hashlib. Templates and scripts are scanned with small regular expressions aimed at the patterns
    the CSP forbids.

What to read next
    scripts/check_contrast.py, src/roxy/static/vendor/VERSIONS.md, tests/e2e/test_csp_spike.py.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from roxy.core.style_guard import find_dashes

REPO = Path(__file__).resolve().parents[3]
PKG = REPO / "src" / "roxy"
STATIC = PKG / "static"
TEMPLATES = PKG / "templates"
OWNED_TEMPLATES = sorted(
    [
        TEMPLATES / "admin" / "base.html",
        *list((TEMPLATES / "admin" / "_layout").glob("*.html")),
        *list((TEMPLATES / "admin" / "_gallery").glob("*.html")),
        *list((TEMPLATES / "components").glob("*.html")),
        REPO / "tests" / "e2e" / "spike" / "spike.html",
    ]
)
DASHBOARD_MODULES = (
    "app",
    "htmx_setup",
    "net",
    "session",
    "sse",
    "live_tail",
    "palette",
    "charts",
    "tables",
    "theme",
    "tooltip",
    "toast",
    "dialog",
    "format",
    "components",
    "dom",
)
"""The dashboard's own modules (static/js also holds the login page's auth.js, owned by the admin auth phase)."""
JS_FILES = [STATIC / "js" / f"{name}.js" for name in DASHBOARD_MODULES]
CSS_FILES = [STATIC / "css" / f"{name}.css" for name in ("tokens", "layout", "components", "print")]
SEMANTIC_TOKENS = (
    "bg",
    "surface-1",
    "surface-2",
    "surface-3",
    "border",
    "text",
    "text-muted",
    "accent",
    "ok",
    "warn",
    "bad",
    "info",
    "focus-ring",
    *(f"series-{i}" for i in range(1, 9)),
)


def _load_script(name: str) -> ModuleType:
    path = REPO / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"roxy_script_{name}", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def contrast() -> ModuleType:
    return _load_script("check_contrast")


# ------------------------------------------------------------------------------------------- tokens and contrast


def test_every_token_pair_meets_wcag_aa_in_both_themes(contrast: ModuleType) -> None:
    results = contrast.check(contrast.TOKENS_FILE.read_text(encoding="utf-8"))
    failing = [r for r in results if not r.ok]
    assert failing == []
    assert {r.theme for r in results} == {"light", "dark"}
    assert len(results) >= 150


def test_contrast_script_exit_code(contrast: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    assert contrast.main(["--failures-only"]) == 0
    assert "0 failing" in capsys.readouterr().out


def test_contrast_check_catches_a_weak_pair(contrast: ModuleType) -> None:
    css = ":root {\n  --fg: light-dark(#777777, #888888);\n  --bg: light-dark(#ffffff, #000000);\n}\n"
    [light, dark] = contrast.check(css, [contrast.Pair("fg", "bg", 4.5, "test")])
    assert light.ok is False
    assert light.ratio < 4.5
    assert dark.ok is True


def test_contrast_ratio_matches_the_wcag_formula(contrast: ModuleType) -> None:
    assert contrast.contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast.contrast("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)


def test_every_semantic_token_has_a_light_and_a_dark_value(contrast: ModuleType) -> None:
    tokens = contrast.parse_tokens(contrast.TOKENS_FILE.read_text(encoding="utf-8"))
    for name in SEMANTIC_TOKENS:
        assert name in tokens, name
        light, dark = tokens[name]
        assert light != dark, f"--{name} has one value for both themes"


def test_dark_is_the_default_and_the_theme_attribute_wins() -> None:
    css = (STATIC / "css" / "tokens.css").read_text(encoding="utf-8")
    root = css.split(":root {", 1)[1]
    assert "color-scheme: dark;" in root.split("}", 1)[0]
    for theme, scheme in (("dark", "dark"), ("light", "light"), ("system", "light dark")):
        assert re.search(rf':root\[data-theme="{theme}"\]\s*\{{\s*color-scheme: {scheme};', css), theme
    assert "prefers-reduced-motion: reduce" in css


_COLOR = re.compile(r"^(?:#[0-9a-fA-F]{3,8}|rgba?\([^()]*\)|transparent)$")
_LIGHT_DARK_CALL = re.compile(r"light-dark\(\s*([^,()]*(?:\([^()]*\))?)\s*,\s*([^,()]*(?:\([^()]*\))?)\s*\)")
_FALLBACK = "@supports not (color: light-dark(#000, #fff))"


def _main_declarations(contrast: ModuleType) -> dict[str, str]:
    css = contrast._strip_comments(contrast.TOKENS_FILE.read_text(encoding="utf-8"))
    body = contrast._ROOT_BLOCK.search(css).group("body")
    return {m.group("name"): " ".join(m.group("value").split()) for m in contrast._DECLARATION.finditer(body)}


def _side(value: str, side: int) -> str:
    """One theme's value of a declaration: every light-dark(light, dark) replaced by the chosen side."""
    return _LIGHT_DARK_CALL.sub(lambda m: m.group(1 + side).strip(), value)


def test_light_dark_wraps_only_colors(contrast: ModuleType) -> None:
    """light-dark() takes two colors. Wrapping a whole shadow in it makes the token invalid where it is used, and
    the browser falls back to `box-shadow: none` (the first version lost every shadow that way)."""
    for name, value in _main_declarations(contrast).items():
        for match in _LIGHT_DARK_CALL.finditer(value):
            for side in match.groups():
                assert _COLOR.match(side.strip()), f"--{name}: light-dark() side {side!r} is not a color"


def test_browsers_without_light_dark_get_both_themes_from_a_fallback(contrast: ModuleType) -> None:
    """Safari before 17.5 does not know light-dark(), so every color token would be invalid there and a phone
    (plan 14.8) would show the dashboard with no colors. The fallback block must repeat exactly the two sides of
    every light-dark() token: dark by default, light for the light theme and for "system" on a light system."""
    css = contrast._strip_comments(contrast.TOKENS_FILE.read_text(encoding="utf-8"))
    assert _FALLBACK in css
    fallback = css.split(_FALLBACK, 1)[1]
    blocks = {
        "dark": re.search(r"^\s*\{\s*:root\s*\{(.*?)\}", fallback, re.DOTALL),
        "light": re.search(r':root\[data-theme="light"\]\s*\{(.*?)\}', fallback, re.DOTALL),
        "system": re.search(
            r'@media \(prefers-color-scheme: light\)\s*\{\s*:root\[data-theme="system"\]\s*\{(.*?)\}',
            fallback,
            re.DOTALL,
        ),
    }
    themed = {name: value for name, value in _main_declarations(contrast).items() if "light-dark(" in value}
    assert len(themed) >= 40
    for theme, found in blocks.items():
        assert found is not None, f"no {theme} block in the fallback"
        values = {m.group("name"): " ".join(m.group("value").split()) for m in contrast._DECLARATION.finditer(found[1])}
        side = 1 if theme == "dark" else 0
        assert values == {name: _side(value, side) for name, value in themed.items()}, theme
        assert "light-dark(" not in found[1]


# ------------------------------------------------------------------------------------------- vendored files


def _sri(path: Path) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(path.read_bytes()).digest()).decode("ascii")


def _versions_rows() -> list[tuple[Path, int, str]]:
    text = (STATIC / "vendor" / "VERSIONS.md").read_text(encoding="utf-8")
    rows = []
    for match in re.finditer(r"\| `([^`]+\.(?:js|css))` \| (\d+) \| `(sha384-[A-Za-z0-9+/=]+)` \|", text):
        relative, size, sri = match.groups()
        base = STATIC / "vendor" if not relative.startswith("axe-core") else REPO / "tests" / "e2e" / "vendor"
        rows.append((base / relative, int(size), sri))
    return rows


def test_versions_md_lists_every_vendored_file() -> None:
    listed = {path for path, _, _ in _versions_rows()}
    on_disk = {p for p in (STATIC / "vendor").rglob("*") if p.suffix in (".js", ".css")}
    on_disk |= {p for p in (REPO / "tests" / "e2e" / "vendor").rglob("*") if p.suffix == ".js"}
    assert listed == on_disk


@pytest.mark.parametrize("row", _versions_rows(), ids=lambda row: row[0].name)
def test_vendored_file_matches_its_recorded_size_and_sri_hash(row: tuple[Path, int, str]) -> None:
    path, size, sri = row
    assert path.stat().st_size == size
    assert _sri(path) == sri


@pytest.mark.parametrize("template", ["src/roxy/templates/admin/base.html", "tests/e2e/spike/spike.html"])
def test_templates_pin_the_same_sri_hashes(template: str) -> None:
    text = (REPO / template).read_text(encoding="utf-8")
    for path, _, sri in _versions_rows():
        if "axe-core" in str(path):
            continue
        assert sri in text, f"{template} does not pin {path.name}"


# ------------------------------------------------------------------------------------------- CSP-safe markup


@pytest.mark.parametrize("path", OWNED_TEMPLATES, ids=lambda p: str(p.relative_to(REPO)))
def test_templates_have_no_inline_styles_handlers_or_unnonced_scripts(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    markup = re.sub(r"\{#.*?#\}", "", text, flags=re.DOTALL)  # Jinja comments may mention what is forbidden
    assert not re.search(r"\sstyle\s*=", markup), "inline style attribute (CSP style-src has no 'unsafe-inline')"
    assert not re.search(r"\son[a-z]+\s*=", markup), "inline event handler"
    assert "javascript:" not in markup.lower()
    for tag in re.findall(r"<script\b[^>]*>", markup):
        assert 'nonce="{{ csp_nonce }}"' in tag, tag
    for tag in re.findall(r"<style\b[^>]*>", markup):
        assert 'nonce="{{ csp_nonce }}"' in tag, tag


@pytest.mark.parametrize(
    "path",
    [*sorted((TEMPLATES / "components").glob("*.html")), TEMPLATES / "admin" / "_gallery" / "fragment.html"],
    ids=lambda p: p.name,
)
def test_fragment_templates_never_contain_script(path: Path) -> None:
    """Plan 9.2: htmx swaps server fragments, and a fragment must never carry a script."""
    markup = re.sub(r"\{#.*?#\}", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
    assert "<script" not in markup.lower()


FORBIDDEN_JS = {
    r"\beval\s*\(": "eval",
    r"new\s+Function\b": "new Function",
    r"\.innerHTML\b": "innerHTML (build DOM with textContent)",
    r"\.outerHTML\s*=": "outerHTML assignment",
    r"insertAdjacentHTML": "insertAdjacentHTML",
    r"document\.write": "document.write",
    r"setAttribute\(\s*[\"']style[\"']": "style attribute (CSP)",
    r"\.cssText\b": "cssText (an inline style string)",
    r"set(?:Timeout|Interval)\(\s*[\"'`]": "timer with a code string",
    r"https?://(?!www\.w3\.org/2000/svg)": "absolute URL (everything is same origin)",
}


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_dashboard_scripts_never_evaluate_strings_or_write_html(path: Path) -> None:
    code = path.read_text(encoding="utf-8")
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"(?m)^\s*//.*$", "", code)
    found = [label for pattern, label in FORBIDDEN_JS.items() if re.search(pattern, code)]
    assert found == []


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_every_module_is_in_the_import_map(path: Path) -> None:
    base = (TEMPLATES / "admin" / "base.html").read_text(encoding="utf-8")
    assert f'"{path.stem}"' in base, f"{path.name} is missing from MODULES in base.html"


@pytest.mark.parametrize("path", CSS_FILES, ids=lambda p: p.name)
def test_stylesheets_load_nothing_from_other_origins(path: Path) -> None:
    css = path.read_text(encoding="utf-8")
    assert not re.search(r"url\(\s*[\"']?https?:", css)
    assert "@import" not in css


def test_print_styles_load_only_for_print() -> None:
    base = (TEMPLATES / "admin" / "base.html").read_text(encoding="utf-8")
    assert re.search(r"static_url\('css/print\.css'\) \}\}\" media=\"print\"", base)


# ------------------------------------------------------------------------------------------- glossary


def _plan_glossary_terms() -> list[str]:
    plan = (REPO / "REMAKE_PLAN.md").read_text(encoding="utf-8")
    section = plan.split("## 21. Glossary", 1)[1]
    terms = []
    for line in section.splitlines():
        match = re.match(r"\| ([^|]+?) \| [^|]+ \|$", line)
        if match and match.group(1) not in ("Term", "---"):
            terms.append(match.group(1).strip())
    return terms


def _glossary() -> list[dict[str, str]]:
    data = yaml.safe_load((REPO / "docs" / "glossary.yml").read_text(encoding="utf-8"))
    terms: list[dict[str, str]] = data["terms"]
    return terms


def test_glossary_has_every_plan_section_21_term() -> None:
    plan_terms = _plan_glossary_terms()
    assert len(plan_terms) >= 50
    ours = {entry["term"] for entry in _glossary()}
    assert [term for term in plan_terms if term not in ours] == []


def test_glossary_entries_are_well_formed() -> None:
    entries = _glossary()
    ids = [entry["id"] for entry in entries]
    assert len(ids) == len(set(ids))
    for entry in entries:
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", entry["id"]), entry["id"]
        assert entry["source"] in ("plan", "dashboard", "roxy"), entry["id"]
        definition = entry["definition"].strip()
        assert definition.endswith("."), entry["id"]
        sentences = re.findall(r"[.!?](?:\s|$)", definition)
        assert 1 <= len(sentences) <= 2, f"{entry['id']}: {len(sentences)} sentences"
        assert find_dashes(definition) == [], entry["id"]


def test_glossary_includes_the_v1_dashboard_terms() -> None:
    """v1's own glossaries (cache and throttle cards, dashboard notes section 9.4) survive (parity row 87)."""
    terms = {entry["term"] for entry in _glossary()}
    for term in (
        "Hit",
        "Miss",
        "TTL",
        "Expired",
        "Stale",
        "Entry",
        "Evicted",
        "Purge",
        "Rung",
        "Multiplier",
        "Decay",
        "Burst",
        "Cooldown",
    ):
        assert term in terms, term


# ------------------------------------------------------------------------------------------- writing style


def test_design_system_files_pass_the_style_check() -> None:
    check_style = _load_script("check_style")
    paths = [
        *OWNED_TEMPLATES,
        *JS_FILES,
        *CSS_FILES,
        STATIC / "vendor" / "VERSIONS.md",
        REPO / "docs" / "glossary.yml",
        REPO / "scripts" / "check_contrast.py",
        PKG / "admin" / "gallery.py",
        *sorted((REPO / "tests" / "e2e").glob("*.py")),
        *sorted(Path(__file__).parent.glob("*.py")),
    ]
    rules = check_style.load_rules()
    assert [str(issue) for issue in check_style.check_paths(paths, rules)] == []
