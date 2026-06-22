"""IP-rotation upstream (DataImpulse or any HTTP proxy).

Loads the proxy URL from auth.read_rotate_proxy() and reloads it when the file
changes (so all gunicorn workers pick up a credential/endpoint change without a
restart). Provides a random, realistic User-Agent per request via fake-useragent
so rotated requests look like many different browsers rather than one bot.
"""

import auth
import config
import runtime
import time
from threading import Lock

try:
    from fake_useragent import UserAgent

    _ua = UserAgent()
except Exception:  # fake-useragent missing/unavailable: fall back to a fixed UA.
    _ua = None

_FALLBACK_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

_lock = Lock()
_proxy_url = ""
_loaded_mtime = -1.0
_loaded = False


def _maybe_load():
    """(Re)load the proxy URL when the source file changes; cheap to call often."""
    global _proxy_url, _loaded_mtime, _loaded
    mtime = auth.rotate_proxy_mtime()
    if _loaded and mtime == _loaded_mtime:
        return
    with _lock:
        _proxy_url = auth.read_rotate_proxy()
        _loaded_mtime = mtime
        _loaded = True


def is_configured() -> bool:
    """Whether a rotation proxy URL is present (regardless of the on/off setting)."""
    _maybe_load()
    return bool(_proxy_url)


def is_enabled() -> bool:
    """Whether rotation should be used right now (configured AND toggled on)."""
    return is_configured() and bool(runtime.get_setting("rotate_enabled", 1))


def proxies() -> dict | None:
    """A requests-style proxies mapping, or None if not configured."""
    _maybe_load()
    if not _proxy_url:
        return None
    return {"http": _proxy_url, "https": _proxy_url}


def random_user_agent() -> str:
    if _ua is None:
        return _FALLBACK_UA
    try:
        return _ua.random or _FALLBACK_UA
    except Exception:
        return _FALLBACK_UA


def masked_url() -> str:
    """Proxy endpoint with any credentials stripped — safe to show on the dashboard."""
    _maybe_load()
    if not _proxy_url:
        return ""
    url = _proxy_url
    # Strip "user:pass@" if present so the dashboard never shows credentials.
    if "@" in url:
        scheme, _, rest = url.partition("://")
        host = rest.split("@", 1)[-1]
        return f"{scheme}://{host}" if scheme and scheme != url else host
    return url
