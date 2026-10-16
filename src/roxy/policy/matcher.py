"""Path template matching for the endpoint policy: one request path to the one seed row it belongs to.

What this is
    `TemplateIndex`, built once from the seed rows, and `split_path`, the normalization every lookup uses.
    `index.find(host, method, path)` returns the most specific row whose template matches, or None.

Why it exists
    Every bypass of a blocklist is a matching bug (BRIEF.md section 4). Roblox's legacy hosts are ASP.NET and treat
    paths without regard to letter case, so `/V1/Logout` must find the `/v1/logout` row; Open Cloud paths carry
    `:verb` inside the last segment (`assets:search`, `{assetId}:archive`), and a known `:verb` operation must win
    over the plain `{assetId}` template next to it.

How it works
    - The request path arrives already decoded and checked by `proxy/validate.py` (no encoded slashes, `%`, dot
      segments or empty segments). `split_path` lowercases it, drops one trailing slash and splits on `/`.
    - A template segment is a literal (`users`), a whole parameter (`{userId}`, any one non-empty segment), or
      mixed (`{assetId}:archive`, compiled to an anchored regex).
    - Rows are grouped by (host, method, segment count). Within a group the order is: more literal segments
      first, then, segment by segment, literal before mixed before parameter. The first template that matches
      wins, so `/v1/users/authenticated` beats `/v1/users/{userId}`.
    - HEAD looks up GET. Matching is a few dictionary lookups and string comparisons: no admin regex, so no
      regex budget is needed.

What to read next
    `roxy/policy/engine.py` (how a match becomes a decision).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from roxy.policy.seed import SeedRow

_PARAM: Final = re.compile(r"\{[^{}/]+\}")
LITERAL, MIXED, PARAM = 0, 1, 2


def split_path(path: str) -> tuple[str, ...]:
    """The lowercase segments of a decoded, validated path (`/v1/Users/` gives `("v1", "users")`)."""
    text = (path or "/").lower()
    if len(text) > 1 and text.endswith("/"):
        text = text[:-1]
    return tuple(segment for segment in text.split("/") if segment)


@dataclass(frozen=True, slots=True)
class _Segment:
    kind: int
    text: str = ""
    regex: re.Pattern[str] | None = None

    def matches(self, segment: str) -> bool:
        if self.kind == LITERAL:
            return segment == self.text
        if self.kind == PARAM:
            # Any value, a `:verb` form included: a mixed template (`{assetId}:archive`) sorts first, so a known
            # `:verb` operation still wins, and an unknown one falls back to its plain row instead of escaping
            # the policy as "unknown" (a `{userId}` of `1:2` must not slip past a BLOCK row).
            return True
        assert self.regex is not None
        return self.regex.fullmatch(segment) is not None


def _compile_segment(raw: str) -> _Segment:
    text = raw.lower()
    if _PARAM.fullmatch(text):
        return _Segment(PARAM)
    if "{" not in text:
        return _Segment(LITERAL, text)
    pieces: list[str] = []
    position = 0
    for found in _PARAM.finditer(text):
        pieces.append(re.escape(text[position : found.start()]))
        pieces.append(r"[^/:]+")
        position = found.end()
    pieces.append(re.escape(text[position:]))
    return _Segment(MIXED, text, re.compile("".join(pieces)))


@dataclass(frozen=True, slots=True)
class _Template:
    row: SeedRow
    segments: tuple[_Segment, ...]

    @property
    def order(self) -> tuple[int, tuple[int, ...]]:
        kinds = tuple(segment.kind for segment in self.segments)
        return (-sum(1 for kind in kinds if kind == LITERAL), kinds)

    def matches(self, parts: tuple[str, ...]) -> bool:
        return all(segment.matches(part) for segment, part in zip(self.segments, parts, strict=True))


class TemplateIndex:
    """Seed rows grouped for lookup by host, method and segment count (module docstring)."""

    __slots__ = ("_groups", "_hosts")

    def __init__(self, rows: Iterable[SeedRow]) -> None:
        groups: dict[tuple[str, str, int], list[_Template]] = {}
        hosts: set[str] = set()
        for row in rows:
            segments = tuple(_compile_segment(part) for part in row.path.split("/") if part)
            groups.setdefault((row.host, row.method, len(segments)), []).append(_Template(row, segments))
            hosts.add(row.host)
        self._groups = {key: tuple(sorted(items, key=lambda t: (t.order, t.row.id))) for key, items in groups.items()}
        self._hosts = frozenset(hosts)

    @property
    def hosts(self) -> frozenset[str]:
        """Every host with at least one documented operation."""
        return self._hosts

    def find(self, host: str, method: str, path: str) -> SeedRow | None:
        """The most specific row for this request, or None when no documented operation matches."""
        verb = method.upper()
        if verb == "HEAD":
            verb = "GET"
        parts = split_path(path)
        for template in self._groups.get((host.lower(), verb, len(parts)), ()):
            if template.matches(parts):
                return template.row
        return None

    def ties(self) -> list[tuple[str, str]]:
        """Pairs of rows with identical templates but different verdicts (a seed bug; the seed test checks it)."""
        out: list[tuple[str, str]] = []
        for items in self._groups.values():
            seen: dict[tuple[tuple[int, str], ...], SeedRow] = {}
            for template in items:
                shape = tuple((s.kind, s.text) for s in template.segments)
                other = seen.get(shape)
                if other is not None and other.verdict != template.row.verdict:
                    out.append((other.id, template.row.id))
                seen.setdefault(shape, template.row)
        return out


__all__ = ["TemplateIndex", "split_path"]
