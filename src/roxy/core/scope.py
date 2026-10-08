"""Scope helpers: how pure ASGI middleware finds the request state, the app context and live settings.

What this is
    `get_state(scope)` returns the per-request state dict (the same object `request.state` wraps),
    `get_app_context(scope)` the worker's `AppContext` (or None before the lifespan has built it), and
    `setting_int` / `setting_float` a live runtime setting with a safe fallback.

Why it exists
    Roxy's middleware is written as plain ASGI callables (no `BaseHTTPMiddleware`), because those add no extra task
    or memory copy per request and keep streaming responses streaming. Plain ASGI code only has `scope`, so these
    helpers put the "where is everything" knowledge in one place. Limits must come from the runtime settings
    store (plan principle: every tunable lives in `config/catalog.py`), but the middleware also has to work in
    unit tests and in the minutes before the settings store exists, so each lookup falls back to the catalog
    default, then to the value the caller passes.

How it works
    Starlette sets `scope["app"]` to the application before any middleware runs, and the lifespan stores the
    context at `app.state.ctx`. Settings are read through `ctx.settings.get(key)` (an in-memory snapshot, so the
    lookup is a dict access, never a database query). Catalog defaults are cached per key after the first lookup.

What to read next
    `roxy/core/middleware.py` and `roxy/core/deadline.py`, the main users.
"""

from __future__ import annotations

import importlib
from collections.abc import MutableMapping
from typing import Any

_MISSING = object()
_catalog_cache: dict[str, Any] = {}


def get_state(scope: MutableMapping[str, Any]) -> dict[str, Any]:
    """The per-request state dict (`request.state` reads and writes the same dict)."""
    state = scope.setdefault("state", {})
    if not isinstance(state, dict):  # pragma: no cover - only a misbehaving server would do this
        state = dict(state)
        scope["state"] = state
    return state


def get_app_context(scope: MutableMapping[str, Any]) -> Any | None:
    """The worker's `AppContext`, or None when the lifespan has not built one (unit tests, early startup)."""
    app = scope.get("app")
    return getattr(getattr(app, "state", None), "ctx", None)


def catalog_default(key: str) -> Any | None:
    """The catalog default for a setting key, or None when the catalog (or the key) does not exist yet."""
    cached = _catalog_cache.get(key, _MISSING)
    if cached is not _MISSING:
        return cached
    value: Any = None
    try:
        catalog = importlib.import_module("roxy.config.catalog")
    except ModuleNotFoundError as exc:
        # Only "the catalog is not written yet" is tolerated; a catalog that fails to import is a real error.
        if exc.name not in {"roxy.config.catalog", "roxy.config"}:
            raise
        catalog = None
    if catalog is not None:
        spec = getattr(catalog, "CATALOG", {}).get(key)
        value = getattr(spec, "default", None)
    _catalog_cache[key] = value
    return value


def _live_value(scope: MutableMapping[str, Any], key: str) -> Any:
    ctx = get_app_context(scope)
    settings = getattr(ctx, "settings", None)
    if settings is None:
        return _MISSING
    try:
        return settings.get(key)
    except (KeyError, AttributeError, LookupError):
        return _MISSING


def setting_float(scope: MutableMapping[str, Any], key: str, fallback: float) -> float:
    """A numeric runtime setting: live value, else catalog default, else `fallback`."""
    for candidate in (_live_value(scope, key), catalog_default(key)):
        if isinstance(candidate, bool):
            continue
        if isinstance(candidate, int | float):
            return float(candidate)
    return float(fallback)


def setting_int(scope: MutableMapping[str, Any], key: str, fallback: int) -> int:
    """An integer runtime setting: live value, else catalog default, else `fallback`."""
    return int(setting_float(scope, key, fallback))
