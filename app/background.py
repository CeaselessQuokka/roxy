"""Fire-and-forget background timers.

threading.Timer threads are non-daemon by default, so every pending timer
blocks process shutdown until it fires, and an exception inside a callback
kills its thread with an unhandled-exception dump. Every delayed callback in
the app goes through schedule() so neither can happen.
"""

import logging
import threading

_logger = logging.getLogger("roxy.background")


def schedule(delay_seconds: float, fn, *args, **kwargs) -> threading.Timer:
    """Run `fn(*args, **kwargs)` after `delay_seconds` on a daemon timer thread."""

    def safe_call():
        try:
            fn(*args, **kwargs)
        except Exception:
            # Background work must never crash a worker thread; log for the server logs.
            _logger.exception("Background task %r failed", getattr(fn, "__name__", fn))

    timer = threading.Timer(max(0.0, float(delay_seconds)), safe_call)
    timer.daemon = True
    timer.start()
    return timer
