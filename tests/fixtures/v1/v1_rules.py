# Frozen v1 reference for parity tests. DO NOT EDIT, DO NOT IMPORT FROM PRODUCTION CODE.
#
# What this is: a verbatim copy of the v1 rule matching functions from `app/runtime.py` (branch remake/v2,
# before the v2 rewrite): `_norm`, `_norm_regex`, `normalize_pattern`, `valid_regex`, `_compile_pattern`,
# `_matches`, `_specificity`, `path_matches`, `_header_rule_id`, `_compile_header_regex`,
# `_header_field_matches` and `_user_agent_matches`.
#
# Why it exists: plan 4.8 row 111 pins v1 matching semantics, and `tests/unit/rules/test_match.py`
# (`test_v1_rule_match_parity`) replays generated patterns and paths through both this copy and
# `roxy.rules.match`, asserting identical answers. Keeping the v1 code frozen here means the parity test keeps
# working after `app/` is deleted at cutover.
#
# Edits made to the copied code, and nothing else:
#   1. One em dash in the `_norm_regex` docstring became a semicolon (plan C5 bans the character everywhere).
#   2. `match_best` at the bottom is NOT a v1 function: it is the selection loop shared by v1
#      `match_endpoint_block`, `match_endpoint_rule` and `match_cache_rule`, with the module-level rule dict
#      passed in as `rules` and the `_maybe_reload()` call dropped. The loop body is copied unchanged.
#   3. `match_first_user_agent` is likewise the loop of v1 `match_user_agent_rule` with the rule dict passed in
#      and the reload and master-switch checks dropped.
import re
from functools import lru_cache


# --- Endpoint pattern helpers -----------------------------------------------
def _norm(pattern: str) -> str:
    """Normalize a GLOB pattern: trim, drop leading slashes, lowercase."""
    return (pattern or "").strip().lstrip("/").lower()


def _norm_regex(pattern: str) -> str:
    """Normalize a REGEX pattern: trim and drop leading slashes only.

    Crucially does NOT lowercase; lowercasing would corrupt regex escapes like
    \\D, \\W, \\S, \\B into their opposites. Case-insensitivity is handled by the
    re.IGNORECASE flag at compile time instead.
    """
    return (pattern or "").strip().lstrip("/")


def normalize_pattern(pattern: str, kind: str) -> str:
    return _norm_regex(pattern) if kind == "regex" else _norm(pattern)


def valid_regex(pattern: str) -> bool:
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


@lru_cache(maxsize=2048)
def _compile_pattern(pattern: str, kind: str):
    """Compile an endpoint pattern into a regex.

    kind == "glob" (default):
      - `*` is a wildcard for a run of characters WITHIN one path segment; it
        never spans a `/`. So `games.roblox.com/v1/games/*/servers` matches
        `games.roblox.com/v1/games/694768217/servers`.
      - A trailing path is always allowed: a pattern matches the path it names
        and everything nested under it.
      - A host-only pattern (no slash) matches that whole service.

    kind == "regex":
      - The pattern is a raw Python regex, matched with re.search (so the admin
        anchors it themselves with ^ / $). No implied trailing wildcard.

    Both are case-insensitive. Cached because patterns are few and reused.
    """
    if kind == "regex":
        return re.compile(pattern, re.IGNORECASE)
    base = pattern.rstrip("/")
    # Escape everything literally, then turn the escaped '*' back into a
    # single-segment wildcard. re.escape turns '*' into r'\*'.
    escaped = re.escape(base).replace(r"\*", r"[^/]*")
    return re.compile(rf"^{escaped}(?:/.*)?$", re.IGNORECASE)


def _matches(pattern: str, path: str, kind: str = "glob") -> bool:
    """Whether a normalized request path is covered by an endpoint pattern."""
    if not pattern:
        return False
    try:
        rx = _compile_pattern(pattern, kind)
    except re.error:
        return False
    return (rx.search(path) if kind == "regex" else rx.match(path)) is not None


def _specificity(pattern: str, kind: str = "glob"):
    """Sort key for "most specific match wins". More path segments rank higher;
    among equals, more literal (non-wildcard) characters rank higher, so a
    concrete rule beats a wildcard one covering the same path. Regex patterns
    sort by length only (they have no clean segment notion)."""
    if kind == "regex":
        return (pattern.count("/"), len(pattern))
    return (pattern.count("/"), len(pattern) - pattern.count("*"))


def path_matches(pattern: str, path: str, kind: str = "glob") -> bool:
    """Public form of the endpoint-pattern matcher, so other modules (cache
    purges) can reuse the exact glob/regex semantics the rules are written in
    rather than approximating them with a second implementation."""
    return _matches(pattern, _norm(path) if kind != "regex" else _norm_regex(path), kind)


# --- Header block rules -----------------------------------------------------
def _header_rule_id(scope: str, mode: str, needle: str, header: str = "") -> str:
    """Canonical id so the same rule can't be added twice and is easy to remove."""
    return f"{header.lower()}|{scope}|{mode}|{needle.lower()}"


@lru_cache(maxsize=512)
def _compile_header_regex(needle: str):
    return re.compile(needle, re.IGNORECASE)


def _header_field_matches(mode: str, needle: str, target: str) -> bool:
    target = target or ""
    if mode == "regex":
        try:
            return _compile_header_regex(needle).search(target) is not None
        except re.error:
            return False
    target_lower = target.lower()
    needle_lower = needle.lower()
    if mode == "exact":
        return target_lower == needle_lower
    return needle_lower in target_lower  # contains


# --- Per-User-Agent throttle rules ------------------------------------------
def _user_agent_matches(rule: dict, user_agent: str) -> bool:
    needle = str(rule.get("Needle", ""))
    if not needle:
        return False
    mode = rule.get("Mode", "contains")
    if mode == "regex":
        try:
            return _compile_header_regex(needle).search(user_agent or "") is not None
        except re.error:
            return False
    target = (user_agent or "").lower()
    if mode == "exact":
        return target == needle.lower()
    return needle.lower() in target


# --- Selection loops (see edit 2 and 3 in the header) -------------------------
def match_best(rules: dict, path: str):
    p = _norm(path)
    best = None
    best_score = None
    for pattern, rule in rules.items():
        kind = rule.get("Type", "glob")
        if _matches(pattern, p, kind):
            score = _specificity(pattern, kind)
            if best_score is None or score > best_score:
                best = dict(rule, Pattern=pattern)
                best_score = score
    return best


def match_first_user_agent(rules: dict, user_agent: str):
    for rule_id, rule in rules.items():
        if not rule.get("Enabled", True):
            continue
        if _user_agent_matches(rule, user_agent):
            return dict(rule, Id=rule_id)
    return None
