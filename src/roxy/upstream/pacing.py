"""The pacing identity of an endpoint: one key per Roblox endpoint, whatever letter case a caller used.

What this is
    `pacing_template(template)` turns an endpoint template (`metrics/templating.py template_for`, which keeps the
    path's letter case as v1 did) into the form every shared pacing key uses: the `endpoint:` cooldown, breaker and
    bucket keys in hot.db, the bucket's window meter, the rotator's distinct-exit records, and the `upstream_limits`
    rows the adaptive controller writes. The literal parts are lowercased; the `{...}` placeholders the templating
    puts in for ids keep their own names (`{universeId}` stays `{universeId}`).

Why it exists
    Roblox's web APIs route paths without regard to letter case, so `/v1/games`, `/V1/Games` and `/v1/GAMES` are one
    endpoint with one rate limit on Roblox's side. When the pacing keys kept the caller's case, each variant was a
    new endpoint to Roxy: it reached Roblox inside the Retry-After Roblox had just given (plan 7.5: "During a
    cooldown Roxy does not contact that endpoint through that egress at all"), got its own default bucket next to
    the rate the adaptive controller had learned (plan 7.3), and three variants turned one endpoint's 429 into a
    host-wide cooldown for every caller (review finding pipe-2). Folding the case only ever merges keys, so it can
    only make Roxy slower toward Roblox, never faster. The displayed template (metrics, the Live feed, the 429 log)
    is not changed: it is a v1 dimension (plan 14.3).

How it works
    The template is split on its placeholders (a `{` up to the next `}`; the templating percent-encodes a caller's
    own braces, so every brace pair in a template is Roxy's placeholder) and only the text between them is
    lowercased. A small bounded cache keeps the hot path to a dictionary lookup.

What to read next
    `roxy/upstream/buckets.py` (`endpoint_bucket_key`), `roxy/upstream/cooldowns.py` (`endpoint_key`) and
    `roxy/upstream/breaker.py` (`breaker_keys`), the three key builders that call it.
"""

from __future__ import annotations

import functools
import re
from typing import Final

_PLACEHOLDER: Final = re.compile(r"(\{[^{}]*\})")
"""An id placeholder of a template (`{userId}`), kept as written by `pacing_template`."""

PACING_CACHE_SIZE: Final = 4096
"""Templates whose pacing form is remembered per worker (a bound, plan P9; the vocabulary gate keeps about 2,000)."""


@functools.lru_cache(maxsize=PACING_CACHE_SIZE)
def pacing_template(template: str) -> str:
    """`template` with its literal parts lowercased and its `{...}` placeholders unchanged (module docstring)."""
    parts = _PLACEHOLDER.split(template)
    # `re.split` with a capturing group puts the placeholders at the odd positions.
    return "".join(part if index % 2 else part.lower() for index, part in enumerate(parts))


__all__ = ["PACING_CACHE_SIZE", "pacing_template"]
