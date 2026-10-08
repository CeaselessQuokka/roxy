"""The import ledger: what earlier migrator runs placed in v2, so a rerun never places it again.

What this is
    `ImportLedger`, stored inside the `service_state.v1_import` marker: the v1 setting keys, the hosts, a short hash
    of each rule's v1 key per table, whether the ladder and the pause and throttle-all state were imported, the
    admin usernames, and the credential file names per credentials directory that a finished step handled.

Why it exists
    Plan 18.3 says the migrator is safe to rerun. After the cutover the owner changes v2: deletes a rule, resets a
    setting, removes a host, flattens the ladder, switches the pause off, deletes an account, removes the bootstrap
    cookie as the C1 runbook says. A rerun that only asked "is it in v2 now?" would put each of those back, and
    would pause production again. With the ledger, a rerun adds only v1 items no earlier run handled (new in v1
    since then) and reports the others as v2 has them now (review findings 1 and 2).

How it works
    Each step returns the part of the ledger it handled; the runner merges a part only when its step finished
    without an exception, so a failed step is done in full by the next run. Rule keys are stored as a 16 hex
    character SHA-256 of table and key: the ledger stays small, and it never holds the text of a v1 rule (a rule
    whose pattern held a secret is refused, but its key is that same text). Sets are written as sorted lists, so
    an unchanged rerun computes exactly the stored JSON and writes nothing. The size is bounded by the v2 rule caps,
    the 71 v1 settings and the 200 item host list.

What to read next
    `roxy/migration/runner.py` (`_write_marker` and the steps), then `rules_import.apply_rule_table`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

RULE_KEY_CHARS: Final = 16


def rule_key(table: str, v1_key: str) -> str:
    """The ledger form of one v1 rule: a short hash of its table and v1 key (never the key text itself)."""
    raw = f"{table}\0{v1_key}".encode("utf-8", "surrogatepass")  # a JSON file can hold a lone surrogate
    return hashlib.sha256(raw).hexdigest()[:RULE_KEY_CHARS]


def _strings(value: Any) -> set[str]:
    if not isinstance(value, list | tuple):
        return set()
    return {item for item in value if isinstance(item, str)}


@dataclass
class ImportLedger:
    """What earlier runs handled (see the module docstring). Empty for a first run."""

    settings: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    rules: dict[str, set[str]] = field(default_factory=dict)
    ladder: bool = False
    service_state: bool = False
    admin: set[str] = field(default_factory=set)
    credentials: dict[str, set[str]] = field(default_factory=dict)

    def has_rule(self, table: str, v1_key: str) -> bool:
        return rule_key(table, v1_key) in self.rules.get(table, set())

    def add_rules(self, table: str, v1_keys: Iterable[str]) -> None:
        self.rules.setdefault(table, set()).update(rule_key(table, key) for key in v1_keys)

    def credential_files(self, directory: str) -> set[str]:
        return self.credentials.get(directory, set())

    def merge(self, other: ImportLedger) -> None:
        """Add everything `other` handled to this ledger."""
        self.settings |= other.settings
        self.hosts |= other.hosts
        for table, keys in other.rules.items():
            self.rules.setdefault(table, set()).update(keys)
        self.ladder = self.ladder or other.ladder
        self.service_state = self.service_state or other.service_state
        self.admin |= other.admin
        for directory, names in other.credentials.items():
            self.credentials.setdefault(directory, set()).update(names)

    def to_json(self) -> dict[str, Any]:
        return {
            "settings": sorted(self.settings),
            "hosts": sorted(self.hosts),
            "rules": {table: sorted(keys) for table, keys in sorted(self.rules.items()) if keys},
            "ladder": self.ladder,
            "service_state": self.service_state,
            "admin": sorted(self.admin),
            "credentials": {path: sorted(names) for path, names in sorted(self.credentials.items()) if names},
        }

    @classmethod
    def from_json(cls, value: Any) -> ImportLedger:
        """The ledger stored in a marker; anything malformed counts as "nothing handled" for that part."""
        if not isinstance(value, Mapping):
            return cls()
        rules = value.get("rules")
        credentials = value.get("credentials")
        return cls(
            settings=_strings(value.get("settings")),
            hosts=_strings(value.get("hosts")),
            rules={str(t): _strings(k) for t, k in rules.items()} if isinstance(rules, Mapping) else {},
            ladder=value.get("ladder") is True,
            service_state=value.get("service_state") is True,
            admin=_strings(value.get("admin")),
            credentials=(
                {str(p): _strings(n) for p, n in credentials.items()} if isinstance(credentials, Mapping) else {}
            ),
        )


__all__ = ["ImportLedger", "rule_key"]
