"""Endpoint blocks: patterns whose requests are refused outright with 403 (plan 4.3 row 46).

What this is
    `match_block` (the most specific enabled block covering a request target) and `block_message` (the block's public
    message or v1's default text).

Why it exists
    The owner sometimes needs to stop one Roblox endpoint being proxied at all (an endpoint that is abused, or one
    Roblox asked not to be hammered) without touching the rest of the service. v1 had the same feature; v2 keeps
    the exact matcher (plan row 111) and the texts.

How it works
    The rules snapshot holds a `PatternIndex` of enabled blocks sorted by specificity (v1 `_specificity`, ties to the
    lowest id). A regex that times out counts as a match (fail closed), so a slow pattern cannot be used to slip
    past a block. A block's `note` is private; its `message` is what callers see.

What to read next
    `roxy/rules/match.py` (pattern semantics), then `roxy/abuse/checks/blocks.py` (the refusal).
"""

from __future__ import annotations

from roxy.abuse.messages import ENDPOINT_BLOCKED, clean_admin_message
from roxy.abuse.verdict import MessageSource
from roxy.rules.models import EndpointBlockRow
from roxy.rules.store import RulesSnapshot


def match_block(snapshot: RulesSnapshot, target: str) -> EndpointBlockRow | None:
    """The block that covers `target` (`host/path`), or None (v1 `match_endpoint_block`)."""
    return snapshot.endpoint_block_for(target)


def block_message(rule: EndpointBlockRow) -> tuple[str, MessageSource]:
    """`(text, message_source)`: the block's message, or `This endpoint is currently blocked.`"""
    text = clean_admin_message(rule.message)
    return (text, "custom") if text else (ENDPOINT_BLOCKED, "default")


__all__ = ["block_message", "match_block"]
