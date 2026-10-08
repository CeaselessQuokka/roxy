"""Render docs/SETTINGS.md from the settings catalog.

What this is
    A small command line tool: `python scripts/gen_settings_docs.py` writes `docs/SETTINGS.md`, the reference
    page for every runtime setting (plan 15.2: "The catalog renders docs/SETTINGS.md"). `--check` compares
    instead of writing and exits 1 when the file is out of date, which is how CI keeps the docs honest.

Why it exists
    The settings catalog (`roxy/config/catalog.py`) is the single source of truth (plan principle P3). Writing
    the reference by hand would drift from it within a week; generating it means the docs, the settings editor
    and the LLM export always say the same thing.

How it works
    It imports `roxy.config.catalog` (adding `src/` to the import path when run from a checkout), walks the
    groups in Settings page order, and writes one section per group and one block per key. Each block has a
    table with every `SettingSpec` field, plus the enum options as a list. Durations and sizes also show a
    human form ("900 seconds (15m)", "536870912 bytes (512 MiB)"). The output is deterministic, so `--check`
    can compare byte for byte.

What to read next
    `roxy/config/catalog.py` (where the data comes from) and `roxy/config/spec.py` (what each field means).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "SETTINGS.md"

_APPLY_TEXT = {
    "live": "live (hot reload fleet-wide within about a second)",
    "restart": "restart (environment value; needs a service restart)",
}
_OP_TEXT = {"eq": "=", "ne": "is not", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "in": "is one of"}


def load_catalog() -> ModuleType:
    """Import `roxy.config.catalog`, making `src/` importable when the package is not installed."""
    src = str(REPO_ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    import roxy.config.catalog as catalog  # imported here, after the path tweak, on purpose

    return catalog


def _cell(text: Any) -> str:
    """Make a value safe inside a Markdown table cell."""
    value = str(text).replace("\r\n", "\n").replace("|", "\\|").replace("\n", "<br>")
    return value if value.strip() else "none"


def _code_list(items: Iterable[str]) -> str:
    listed = [f"`{item}`" for item in items]
    return ", ".join(listed) if listed else "none"


def _number(value: Any) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _human_duration(seconds: float) -> str:
    """90 -> "1m30s", 7200 -> "2h"; empty for 0 or less."""
    if seconds <= 0:
        return ""
    remaining = int(seconds)
    parts: list[str] = []
    for size, suffix in ((86400, "d"), (3600, "h"), (60, "m"), (1, "s")):
        if remaining >= size:
            parts.append(f"{remaining // size}{suffix}")
            remaining %= size
    return "".join(parts)


def _human_bytes(count: int) -> str:
    """1048576 -> "1 MiB"; only exact multiples get a short form."""
    for size, suffix in ((1024**4, "TiB"), (1024**3, "GiB"), (1024**2, "MiB"), (1024, "KiB")):
        if count >= size and count % size == 0:
            return f"{count // size} {suffix}"
    return ""


def _describe_value(spec: Any, value: Any) -> str:
    """A value as it appears in the docs, with a human hint for durations and sizes."""
    if isinstance(value, list | tuple):
        return ", ".join(str(item) for item in value) if value else "empty list"
    if isinstance(value, str):
        return f'"{value}"' if value else "empty"
    if value is None:
        return "none"
    text = _number(value)
    unit = spec.unit
    if spec.type.value == "duration" and isinstance(value, int | float):
        seconds = value / 1000 if unit.strip().lower() == "ms" else value
        hint = _human_duration(seconds) if unit.strip().lower() in ("ms", "seconds", "s", "") else ""
        return f"{text} {unit or 'seconds'}" + (f" ({hint})" if hint and hint != f"{text}s" else "")
    if spec.type.value == "bytes" and isinstance(value, int) and unit.strip().lower() in ("bytes", "b", ""):
        hint = _human_bytes(value)
        return f"{text} bytes" + (f" ({hint})" if hint else "")
    return f"{text} {unit}".strip()


def _range_text(spec: Any) -> str:
    unit = f" {spec.unit}" if spec.unit else ""
    if spec.type.value == "bool":
        return "0 (off) or 1 (on)"
    if spec.type.value == "enum":
        return "one of " + ", ".join(f"`{value}`" for value in spec.option_values())
    if spec.min is None and spec.max is None:
        return "any"
    if spec.min is None:
        return f"at most {_number(spec.max)}{unit}"
    if spec.max is None:
        return f"at least {_number(spec.min)}{unit}"
    text = f"{_number(spec.min)} to {_number(spec.max)}{unit}"
    if spec.type.value == "bytes" and isinstance(spec.max, int | float) and spec.max == int(spec.max):
        hint = _human_bytes(int(spec.max))
        text += f" (at most {hint})" if hint else ""
    return text


def _high_risk_text(spec: Any) -> str:
    conditions = [
        f"value {_OP_TEXT.get(condition.op.value, condition.op.value)} {condition.value}: {condition.why}"
        for condition in spec.high_risk_if
    ]
    return "\n".join(conditions) if conditions else "none"


def render_spec(spec: Any, catalog: ModuleType) -> list[str]:
    """The Markdown block for one setting."""
    sensitive = bool(spec.sensitive)
    default = catalog.REDACTED if sensitive else _describe_value(spec, catalog.DEFAULTS.get(spec.key, spec.default))
    v1_default = (
        "none" if spec.v1_default is None else catalog.REDACTED if sensitive else _describe_value(spec, spec.v1_default)
    )
    bounds = (
        "none"
        if spec.auto_apply_bounds is None
        else f"{_number(spec.auto_apply_bounds[0])} to " + _number(spec.auto_apply_bounds[1])
    )
    rows: list[tuple[str, Any]] = [
        ("Label", spec.label),
        ("Group", catalog.GROUP_LABELS.get(spec.group, spec.group.value)),
        ("Type", spec.type.value),
        ("Default", default),
        ("Range", _range_text(spec)),
        ("Unit", spec.unit or "none"),
        ("Step", "none" if spec.step is None else _number(spec.step)),
        ("If raised", spec.if_raised or "n/a"),
        ("If lowered", spec.if_lowered or "n/a"),
        ("If enabled", spec.if_enabled or "n/a"),
        ("If disabled", spec.if_disabled or "n/a"),
        ("Risk", spec.risk.value),
        ("High risk when", _high_risk_text(spec)),
        ("Applies", _APPLY_TEXT.get(spec.apply.value, spec.apply.value)),
        ("Dashboard", _code_list(spec.pages)),
        ("Related settings", _code_list(spec.related_settings)),
        ("Related rules", _code_list(spec.related_rules)),
        ("Related recommendations", _code_list(spec.related_recommendations)),
        ("Auto-apply bounds", bounds),
        ("Sensitive", "yes (redacted in exports and logs)" if sensitive else "no"),
        ("Since", spec.since),
        ("v1 key", f"`{spec.renamed_from}`" if spec.renamed_from else "same key, or new in v2"),
        ("v1 default", v1_default),
        ("Max length", "none" if spec.max_length is None else str(spec.max_length)),
        ("Item max length", "none" if spec.item_max_length is None else str(spec.item_max_length)),
        ("Item range", _item_range(spec)),
        ("Pending owner verification", "yes" if spec.pending_owner_verification else "no"),
        ("Notes", spec.notes or "none"),
    ]
    lines = [f"### `{spec.key}`", "", spec.description.strip(), ""]
    lines += ["| Field | Value |", "|---|---|"]
    lines += [f"| {name} | {_cell(value)} |" for name, value in rows]
    if spec.options:
        lines += ["", "Options:", ""]
        lines += [
            f"- `{option.value}` ({option.label}): {option.description}".replace("\n", " ") for option in spec.options
        ]
    lines.append("")
    return lines


def _item_range(spec: Any) -> str:
    if spec.item_min is None and spec.item_max is None:
        return "none"
    low = "any" if spec.item_min is None else _number(spec.item_min)
    high = "any" if spec.item_max is None else _number(spec.item_max)
    return f"{low} to {high}"


def render(catalog: ModuleType | None = None) -> str:
    """The whole of docs/SETTINGS.md as text."""
    cat = load_catalog() if catalog is None else catalog
    grouped: dict[Any, Sequence[Any]] = cat.by_group()
    lines = [
        "# Settings reference",
        "",
        "Generated by `scripts/gen_settings_docs.py` from `roxy/config/catalog.py`. Do not edit this file by hand;",
        "change the setting's declaration and run the script again (CI runs it with `--check`).",
        "",
        f"Catalog version `{cat.CATALOG_VERSION}`, {len(cat.CATALOG)} settings in {len(grouped)} groups.",
        "",
    ]
    if cat.MISSING_MODULES:
        missing = ", ".join(f"`{item.module}`" for item in cat.MISSING_MODULES)
        lines += [f"Partial catalog (built with ROXY_CATALOG_PARTIAL=1): {missing} not loaded.", ""]
    lines += [
        "## How to read this page",
        "",
        "Every setting is live unless its Applies row says otherwise: a change reaches every worker within about a",
        "second. Plain numbers for durations and sizes are in the unit shown; the editor and API also accept text",
        'such as "90s", "15m", "2h", "64 MiB" or "1 GiB" (KB, MB and GB are powers of 1000; KiB, MiB and GiB are',
        "powers of 1024). High-risk values need a reason and a confirmation. Dashboard lists the cards where the",
        "setting can also be edited inline, besides the Settings page.",
        "",
        "## Contents",
        "",
    ]
    for group, specs in grouped.items():
        label = cat.GROUP_LABELS.get(group, group.value)
        lines.append(f"- [{label}](#group-{group.value}) ({len(specs)})")
    lines += ["- [Cross-field rules](#cross-field-rules)", ""]
    lines += [
        '<a id="cross-field-rules"></a>',
        "",
        "## Cross-field rules",
        "",
        "A change is refused when it would break one of these (checked on save and on import):",
        "",
    ]
    lines += [f"- {rule}" for rule in cat.cross_rule_descriptions()]
    lines.append("")
    for group, specs in grouped.items():
        label = cat.GROUP_LABELS.get(group, group.value)
        lines += [f'<a id="group-{group.value}"></a>', "", f"## {label}", ""]
        for spec in specs:
            lines += render_spec(spec, cat)
    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render docs/SETTINGS.md from the settings catalog.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="where to write (default docs/SETTINGS.md)")
    parser.add_argument("--check", action="store_true", help="do not write; exit 1 if the file is out of date")
    parser.add_argument("--stdout", action="store_true", help="print the page instead of writing it")
    args = parser.parse_args(argv)
    text = render()
    if args.stdout:
        sys.stdout.write(text)
        return 0
    output: Path = args.output
    if args.check:
        try:
            current = output.read_text(encoding="utf-8")
        except OSError:
            current = ""
        if current != text:
            print(f"{output} is out of date; run: python scripts/gen_settings_docs.py", file=sys.stderr)
            return 1
        print(f"{output} is up to date")
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
