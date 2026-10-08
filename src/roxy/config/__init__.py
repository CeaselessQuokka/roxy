"""Configuration: environment settings, the runtime settings catalog, and the live settings store.

What this is
    The package that answers "what is Roxy configured to do?". Two kinds of configuration live here:
    environment settings (`env.py`: paths, workers, the deployment color; they need a restart) and runtime
    settings (`catalog.py` describes every one, `runtime.py` holds the current values, `settings_service.py`
    changes them with an audit trail; they hot-reload fleet-wide within about a second).

Why it exists
    Plan principle P3: every tunable is declared exactly once, with its type, range, help text and dashboard
    location, so validation, the settings editor, docs/SETTINGS.md and the LLM export can never disagree.

How it works
    `spec.py` defines the vocabulary (`SettingSpec`, `ParamSpec`, ...). The group modules in `settings/` declare
    the settings, `insight_params.py` declares the tunable thresholds of each recommendation rule, and
    `catalog.py` assembles them into `CATALOG`, checks the whole thing at import time, and validates values.
    This package `__init__` deliberately imports nothing, so importing `roxy.config.spec` from a group module
    never triggers catalog assembly halfway through.

What to read next
    `roxy/config/spec.py`, then `roxy/config/catalog.py`, then `roxy/config/runtime.py`.
"""
