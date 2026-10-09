"""Read model for the Protection > Spam detectors card: detector states and the FILTER-COLLATERAL preview.

What this is
    `detector_states(values)` (each detector of plan 10.3 with its live settings, its unit and whether it can only
    recommend), `collateral(...)` (which clients the detectors would have banned during the dry run that look
    legitimate) and `collateral_token(...)` (a digest of that list, which arming must repeat).

Why it exists
    Plan 10.3: "Detectors start in dry-run (`spam_dry_run` = 1). Before the admin can switch dry-run off, the UI runs
    FILTER-COLLATERAL against the last 7 days ... and shows which legitimate-looking clients would have been banned;
    arming requires confirming that list." Roblox game servers share addresses, so one bad script behind an address
    could otherwise cut off every experience behind it.

How it works
    - While in dry run a detector whose action is `ban` records a `spam_would_ban` event instead of banning
      (`abuse/spam.py`). Those events are exactly "who would have been banned", per subject (`ip:<client key>`).
    - A subject counts as legitimate-looking when its traffic over the same 7 days was mostly served (served share
      at or above `insight_filter_collateral_served_pct`, the FILTER-COLLATERAL rule's own threshold, default 95%),
      or when a detector saw the trusted Roblox game server signature (`game_server`). The served share comes from
      the client activity tables (exact counts per minute, hour and day; plan 6.10); an IPv6 network key has no
      per-address row, so its share is unknown and it is listed for review rather than silently passed.
    - `collateral_token` hashes the sorted subjects of the legitimate-looking list, so "I confirm this list" means
      this exact list: a list that changed since the preview needs a new preview.
    The request samples the plan names hold neither refusals nor raw addresses (only a keyed hash of the client),
    so the replay is built on the detectors' own dry-run decisions instead; CHANGES.md records the deviation.

What to read next
    `roxy/abuse/spam.py` (the detectors), `roxy/metrics/read_protection.py` (`would_ban_subjects`), then
    `roxy/admin/api/protection.py` (`/spam/collateral` and `/spam/arm`).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Final

from roxy.abuse.spam import DETECTORS, RECOMMEND_ONLY
from roxy.core.scope import catalog_default

COLLATERAL_WINDOW_S: Final = 7 * 86_400
"""Plan 10.3: the preview looks at the last 7 days."""
SERVED_PCT_SETTING: Final = "insight_filter_collateral_served_pct"
UNITS: Final[dict[str, str]] = {
    "rate": "times the per-IP limit rate",
    "refused": "refused requests",
    "probe": "probe requests",
    "auth": "auth smuggling attempts",
    "enum": "distinct numeric ids on one endpoint",
    "bust": "share of requests with a never-seen query",
    "dist": "distinct IP addresses with one User-Agent on one endpoint",
}
"""What each detector's threshold counts (the unit `abuse/spam.py evaluate_row` compares with)."""
SETTING_NAMES: Final[tuple[str, ...]] = ("enabled", "threshold", "window_s", "action", "ban_minutes", "ban_max_minutes")


def _value(values: Mapping[str, Any], key: str) -> Any:
    return values[key] if key in values else catalog_default(key)


def detector_states(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Each detector with its live settings (`spam_<id>_<name>`), unit and effective action."""
    master = bool(_value(values, "spam_enabled"))
    dry_run = bool(_value(values, "spam_dry_run"))
    out = []
    for detector in DETECTORS:
        settings = {name: _value(values, f"spam_{detector}_{name}") for name in SETTING_NAMES}
        action = str(settings["action"])
        recommend_only = detector in RECOMMEND_ONLY
        effective = "recommend" if recommend_only else action
        if effective == "ban" and dry_run:
            effective = "would_ban"
        out.append(
            {
                "id": detector,
                "label": f"SPAM-{detector.upper()}",
                "enabled": bool(settings["enabled"]) and master,
                "settings": settings,
                "unit": UNITS[detector],
                "recommend_only": recommend_only,
                "effective_action": effective if bool(settings["enabled"]) and master else "off",
            }
        )
    return out


def client_key_of(subject: str) -> str | None:
    """The client key of a detector subject (`ip:203.0.113.9` gives `203.0.113.9`), None for other subjects."""
    return subject[3:] if subject.startswith("ip:") else None


def collateral(
    would_ban: Sequence[Mapping[str, Any]],
    totals: Mapping[str, Mapping[str, int]],
    *,
    served_pct: float,
) -> list[dict[str, Any]]:
    """Every would-be-banned client with its served share and whether it looks legitimate (module docstring)."""
    out = []
    for item in would_ban:
        subject = str(item.get("subject") or "")
        key = client_key_of(subject)
        if key is None:
            continue
        counts = totals.get(key)
        requests = int(counts["requests"]) if counts else 0
        served = int(counts["served"]) if counts else 0
        share = round(served * 100.0 / requests, 2) if requests else None
        reasons = []
        if item.get("game_server"):
            reasons.append("looked like a trusted Roblox game server")
        if share is not None and share >= served_pct:
            reasons.append(f"{share:g}% of its requests were served (threshold {served_pct:g}%)")
        unknown = share is None
        if unknown:
            reasons.append("no per-address activity rows for this key (an IPv6 network, or activity tracking off)")
        out.append(
            {
                "subject": subject,
                "client": key,
                "detectors": list(item.get("detectors") or []),
                "would_ban_count": int(item.get("count") or 0),
                "first_ms": item.get("first_ms"),
                "last_ms": item.get("last_ms"),
                "evidence": item.get("evidence"),
                "requests": requests,
                "served": served,
                "refused": int(counts["refused"]) if counts else 0,
                "served_pct": share,
                "game_server": bool(item.get("game_server")),
                "legitimate_looking": bool(reasons),
                "why": reasons,
            }
        )
    return out


def collateral_token(entries: Sequence[Mapping[str, Any]]) -> str:
    """A digest of the legitimate-looking subjects (what arming must confirm).

    The window is not part of it (it moves with the clock): a confirmation stays good while the list is the same.
    """
    subjects = sorted(str(entry["subject"]) for entry in entries if entry.get("legitimate_looking"))
    text = "collateral/1\n" + "\n".join(subjects)
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:32]


__all__ = [
    "COLLATERAL_WINDOW_S",
    "SERVED_PCT_SETTING",
    "UNITS",
    "client_key_of",
    "collateral",
    "collateral_token",
    "detector_states",
]
