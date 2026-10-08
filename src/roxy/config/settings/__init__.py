"""The settings catalog content, one module per group of plan 15.3.

What this is
    Twelve modules (`routing.py`, `credential.py`, `upstream.py`, `cache.py`, `throttling.py`, `spam.py`,
    `tarpit.py`, `admin_security.py`, `alerts.py`, `metrics.py`, `insights.py`, `public_site.py`), each exporting
    `SETTINGS: list[SettingSpec]` for its group (DESIGN.md section 4).

Why it exists
    Plan 15.1: every tunable lives in the catalog with its default, range, plain-English effect of raising and
    lowering it, risk, and the dashboard card where it is edited. Several hundred settings in one file would be
    unreadable, so each group of the plan table has its own module next to the text that explains it.

How it works
    The modules only declare data. `roxy/config/catalog.py` imports them in Settings page order, adds the settings
    generated for every recommendation rule (`config/insight_params.py`), checks every default and text at import
    time, and serves the result to the runtime store, the editor, the generated docs and the LLM export.

What to read next
    `roxy/config/spec.py` (what each `SettingSpec` field means), `roxy/config/catalog.py`, then any group module.
"""
