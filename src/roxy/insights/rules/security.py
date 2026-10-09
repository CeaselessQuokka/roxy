"""The security rules of plan 11.5: SEC-ADMIN-ALLOWLIST, SEC-BYPASS-FOREVER and SEC-DEFAULTS.

What this is
    Three recommendation rules that shrink the attack surface: an admin allowlist when every login comes from a few
    networks, an expiry for every bypass entry, and safer values for settings sitting at a high-risk value. Each class
    docstring is the rule's help text on the Recommendations page.

Why it exists
    Plan 9 hardens Roxy, but some protections depend on choices only the admin can make (which networks may reach the
    dashboard, how long a load test may skip the limits). These rules point at the choice with the evidence and the
    exact change. Security changes are never auto-applied (plan 11.4).

How it works
    - Admin logins are the `login` events of the metrics database (successful ones only: a failed attempt says
      nothing about the admin's own networks). Addresses are grouped into networks: IPv4 /24, IPv6 /64.
    - Bypass entries come from the access list; their last use from the rule hit history.
    - High-risk values are the catalog's `high_risk_if` conditions (`config/spec.py RiskCondition`), the same ones the
      settings editor marks; the safer value is the catalog default (no default is a high-risk value).

What to read next
    `roxy/insights/rules/base.py` (the authoring guide), `roxy/config/spec.py` (risk conditions),
    `roxy/metrics/security_events.py` (login events), `tests/insights/test_rules_abuse_system.py`.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any, Final

from roxy.config import catalog
from roxy.insights.context import InsightContext
from roxy.insights.models import Evidence, ProposedChange, Recommendation, iso
from roxy.insights.rules.abuse import BYPASS_EXPIRY_S, access_match, bypass_rows
from roxy.insights.rules.base import Rule, register

DAY_S: Final = 86_400
IPV4_NETWORK: Final = 24
"""An admin "network" for IPv4: the /24 the address is in (a home or office line keeps its /24 across reconnects)."""
IPV6_NETWORK: Final = 64
"""An admin "network" for IPv6: the /64 (one LAN; providers hand out a stable /64 or wider)."""
SECURITY_LINK: Final = "/admin/security"


def network_of(address: str) -> str | None:
    """The /24 (IPv4) or /64 (IPv6) network of an address, None for anything that is not an address."""
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    prefix = IPV4_NETWORK if isinstance(ip, ipaddress.IPv4Address) else IPV6_NETWORK
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def covered(network: str, cidrs: list[str]) -> bool:
    """Whether an existing allowlist entry already covers the whole network."""
    net = ipaddress.ip_network(network)
    for cidr in cidrs:
        try:
            entry = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and isinstance(entry, ipaddress.IPv4Network):
            if net.subnet_of(entry):
                return True
        elif (
            isinstance(net, ipaddress.IPv6Network) and isinstance(entry, ipaddress.IPv6Network) and net.subnet_of(entry)
        ):
            return True
    return False


# ------------------------------------------------------------------------------------------------ SEC-ADMIN-ALLOWLIST


@register
class SecAdminAllowlist(Rule):
    """Admin logins always come from a few networks; an admin allowlist would help.

    Fires while `admin_allowlist_enabled` is off when every successful admin login of the last `days` days came from
    at most `max_networks` networks (IPv4 /24, IPv6 /64). Failed attempts are ignored: they are not the admin's
    networks. The change adds an admin allowlist entry per network and then turns the allowlist on, so the dashboard
    answers only those networks. Low confidence: a network you use rarely may be missing, so check the list (the
    break-glass command line can turn the allowlist off again).
    """

    id = "SEC-ADMIN-ALLOWLIST"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        if ctx.flag("admin_allowlist_enabled"):
            return []
        days = self.param(ctx, "days")
        window = ctx.window(days=days)
        networks: dict[str, dict[str, Any]] = {}
        logins = 0
        for event in await ctx.events(("login",), window):
            detail = event.get("detail") or {}
            if not detail.get("successful"):
                continue
            network = network_of(str(detail.get("ip") or ""))
            if network is None:
                continue
            logins += 1
            entry = networks.setdefault(network, {"network": network, "logins": 0, "addresses": set(), "last": 0})
            entry["logins"] += 1
            entry["addresses"].add(str(detail.get("ip")))
            entry["last"] = max(entry["last"], int(event["at_ms"]) // 1000)
        if not networks or len(networks) > self.param(ctx, "max_networks"):
            return []
        existing = [str(r["cidr"]) for r in await ctx.rule_rows("access_list") if r.get("kind") == "allow_admin"]
        changes = [
            ProposedChange(
                "rule_upsert",
                table="access_list",
                match={"kind": "allow_admin", "cidr": network},
                current=None,
                proposed={
                    "kind": "allow_admin",
                    "cidr": network,
                    "note": "SEC-ADMIN-ALLOWLIST: admin logins seen here",
                    "expires_at": None,
                },
            )
            for network in sorted(networks)
            if not covered(network, existing)
        ]
        # Entries first, the switch last: the allowlist never goes on before the admin's networks are on it.
        changes.append(
            ProposedChange(
                "setting", key="admin_allowlist_enabled", current=ctx.setting("admin_allowlist_enabled"), proposed=1
            )
        )
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=logins)
        evidence.add("successful_logins", logins, "logins")
        evidence.add("networks", len(networks), "networks")
        evidence.details["networks"] = [
            {
                "network": n["network"],
                "logins": n["logins"],
                "addresses": sorted(n["addresses"])[:10],
                "last": iso(n["last"]),
            }
            for n in sorted(networks.values(), key=lambda n: -int(n["logins"]))
        ]
        evidence.links.append(f"{SECURITY_LINK}#admin-access")
        listing = ", ".join(sorted(networks))
        return [
            self.recommendation(
                ctx,
                subject="admin_allowlist",
                title=f"All admin logins in {days:g} days came from {len(networks)} network(s): allowlist them",
                severity="info",
                confidence="low",
                explanation=(
                    f"Every one of the {logins} successful admin logins in the last {days:g} days came from {listing}. "
                    "With the admin allowlist on, the dashboard and admin API answer only those networks, so a stolen "
                    "password is useless elsewhere. Check that the list holds every place you log in from."
                ),
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    f"The admin surface answers {len(networks)} network(s) instead of the whole internet; the "
                    f"{logins} logins of the last {days:g} days would all still have worked."
                ),
                risk="medium",
            )
        ]


# ------------------------------------------------------------------------------------------------ SEC-BYPASS-FOREVER


@register
class SecBypassForever(Rule):
    """A bypass entry never expires.

    Fires for every bypass entry without an expiry. A bypass entry lets an address skip the per-IP limit, the place
    limit and the tarpit, so one forgotten after a load test is an unlimited client for anyone who gets that address.
    The change gives the entry an expiry 30 days from now (renew it if it is still needed then).
    """

    id = "SEC-BYPASS-FOREVER"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        hits = await ctx.rule_hits("access_list")
        out: list[Recommendation] = []
        for row in bypass_rows(await ctx.rule_rows("access_list"), ctx.now):
            if row.get("expires_at") is not None:
                continue
            out.append(self._recommend(ctx, row, (hits.get(("access_list", str(row["id"]))) or {}).get("last_hit_at")))
        return out

    def _recommend(self, ctx: InsightContext, row: Mapping[str, Any], last_hit: Any) -> Recommendation:
        cidr = str(row["cidr"])
        created = float(row.get("created_at") or ctx.now)
        expires_at = int(ctx.now) + BYPASS_EXPIRY_S
        evidence = Evidence(window_to=ctx.now, sample_size=1)
        evidence.add("age_days", round((ctx.now - created) / DAY_S, 1), "days")
        if last_hit is not None:
            evidence.add("days_since_last_hit", round((ctx.now - float(last_hit)) / DAY_S, 2), "days")
        evidence.details.update({"note": row.get("note"), "created_at": iso(created), "last_hit_at": iso(last_hit)})
        evidence.links.append("/admin/protection#bypass")
        used = f"last used {iso(last_hit)}" if last_hit is not None else "no recorded use"
        return self.recommendation(
            ctx,
            subject=f"bypass:{cidr}",
            title=f"The bypass entry {cidr} never expires",
            severity="warn",
            confidence="high",
            explanation=(
                f"{cidr} ({row.get('note') or 'no note'}) has been on the bypass list since {iso(created)} with no "
                f"expiry ({used}). Every request from it skips the per-IP limit, the place limit and the tarpit. The "
                f"change sets it to expire on {iso(expires_at)}."
            ),
            evidence=evidence,
            changes=[
                ProposedChange(
                    "rule_upsert",
                    table="access_list",
                    match=access_match(row),
                    current=dict(row),
                    proposed={"expires_at": expires_at},
                )
            ],
            expected_impact="No unlimited client can be forgotten on the bypass list.",
            risk="low",
        )


# ------------------------------------------------------------------------------------------------ SEC-DEFAULTS


def safer_value(key: str, value: Any) -> Any | None:
    """A value of `key` outside its high-risk range: the catalog default when that is safe (it always is today)."""
    spec = catalog.CATALOG[key]
    if spec.is_high_risk_value(spec.default) is None and spec.default != value:
        return spec.default
    return None


@register
class SecDefaults(Rule):
    """A setting sits at a high-risk value.

    Fires once per setting whose current value matches one of its catalog high-risk conditions (the values the
    settings editor marks in red and asks a reason for), including the generated per-rule settings of this engine.
    The change restores the catalog default. Settings holding secrets are never shown here.
    """

    id = "SEC-DEFAULTS"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        out: list[Recommendation] = []
        for key, spec in sorted(catalog.CATALOG.items()):
            if not spec.high_risk_if or spec.sensitive or key not in ctx.settings:
                continue
            value = ctx.setting(key)
            why = spec.is_high_risk_value(value)
            if why is None:
                continue
            safer = safer_value(key, value)
            evidence = Evidence(window_to=ctx.now, sample_size=1)
            evidence.add("value", value)
            evidence.add("default", spec.default)
            evidence.details["risk"] = why
            evidence.details["label"] = spec.label
            evidence.links.append(f"/admin/settings#{key}")
            if safer is None:
                changes = [ProposedChange("manual", text=f"Choose a value of {key} outside its high-risk range.")]
            else:
                changes = [ProposedChange("setting", key=key, current=value, proposed=safer)]
            out.append(
                self.recommendation(
                    ctx,
                    subject=key,
                    title=f"{spec.label} ({key}) is at a high-risk value",
                    severity="warn",
                    confidence="high",
                    explanation=(
                        f"{key} is {value!r}. {why} The change restores the default, {spec.default!r}, which is not a "
                        "high-risk value."
                    ),
                    evidence=evidence,
                    changes=changes,
                    expected_impact=f"{spec.label} back to its safer default.",
                    risk="low",
                )
            )
        return out


__all__ = ["SecAdminAllowlist", "SecBypassForever", "SecDefaults", "covered", "network_of", "safer_value"]
