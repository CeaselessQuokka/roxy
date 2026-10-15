# Roxy v2.x roadmap

This is the list of everything you asked for on 2026-10-14 that does not ship with v2.0, the version that replaces
v1 at the cutover. Nothing on it is forgotten: each item has your own words, how the lead read them, a rough size,
what it is made of, what you have until it ships, and the questions only you can answer. Answer those when its update
starts, not now.

After your answers you said:

> "For anything that adds a lot of time, we can save that for later once I get my hands on V2 and it can be part of
> V2.x.y + big patch. I want to get my hands on this ASAP, I'm excited. Please keep track of the new tasks that will
> take too long to do"

So v2.0 ships the answers that are settings, texts and server steps (`CHANGES.md`, "Pre-cutover round
(2026-10-14)"; `MIGRATION.md` has the steps you take at the cutover), and everything below comes as v2.x updates.
Each update is tested like v2.0 (the whole test suite, plus the load replay when it changes the path a caller's
request takes), merged into `main`, and then deploys itself with no outage. A bad update is undone with
`deploy_rollback.sh` (`deploy/README.md`, "How a deploy runs").

## How to read the sizes

The sizes come from the lead's seven design notes of 2026-10-14 (one per topic, each with a work breakdown in agent
hours, tests included). **They are rough estimates:** each update is planned again against the code as it is when it
starts, and the earlier updates change some of the same files.

| Size | Agent hours |
|---|---|
| S | under 10 |
| M | 10 to 40 |
| L | 40 to 100 |
| XL | over 100 |

Agent hours are not calendar time: several agents work at once, each on its own files. All of it together is about
520 agent hours. (The chat summary of 2026-10-14 called the narrator XL and the setup guide L; by the design
estimates they are L and M.) The design notes are working files of the build and are not in the repository; the
parts and questions below are taken from them.

## The order the lead suggests

| Update | Items | Sizes | Why in this place |
|---|---|---|---|
| v2.1 | [1](#1-d1-the-private-endpoint-guard-probably-private-info) the private endpoint guard (D1), [2](#2-d12-the-prepaid-dataimpulse-balance) the prepaid balance (D12), [3](#3-two-small-safety-checks-moved-from-the-cutover) two small safety checks, [12](#12-swap-and-kernel-settings-in-the-install-script) swap and kernel settings in the install script | L, L, S, S | You asked for the guard as a safety item, and the prepaid balance replaces a stand-in you would otherwise redo by hand every month. Both can be built while v2.0 settles. |
| v2.2 | [4](#4-a9-your-account-name-password-email) your account page (A9), [5](#5-a10-how-roxy-is-doing-in-plain-words) "How Roxy is doing" (A10), [6](#6-a4-and-a6-follow-ups-the-digest-preview-and-the-user-agent-experiment) the digest preview and the User-Agent experiment's counter (A4, A6), [7](#7-b17-roblox-game-server-ranges-an-optional-preset) Roblox game server ranges (B17) | L, L, M, M | What you will use every day. The narrator reads the prepaid balance and the private guard's flags, so it comes after them. |
| v2.3 | [8](#8-d17-clear-any-card-start-fresh-the-v1-snapshot-and-windows-of-changes) Clear any card, Start fresh and the v1 snapshot (D17), [9](#9-a3-times-in-your-devices-time-zone) your device's time zone (A3), [10](#10-b17-the-first-run-setup-guide) the setup guide (B17) | L, M, M | These change the shared page frame and every chart. The setup guide walks through settings that exist only once v2.1 and v2.2 shipped. |
| v2.4 | [11](#11-d11-rules-at-every-depth-everywhere) rules at every depth (D11) | XL | The largest change, and it is on the request path. Coming last, it extends every rule family at once, including the private list and the clears that exist by then. You may swap v2.3 and v2.4 if you want the rules first. |
| any time | [13](#13-performance-items-still-open) performance items, [14](#14-the-docs-screenshots) the docs screenshots | S to M each | As each one is understood and measured. |

[15](#15-your-own-to-dos-for-later) lists what you said you would do yourself later, and
[16](#16-other-known-follow-ups) points to the follow-ups that were known before your answers.

## 1. D1: the private endpoint guard ("probably private info")

**You said (D1):**

> "No, calling traffic (`from` source (calling traffic) `to` Roxy) carry credentials. They should also be barred from
> making requests to anything that needs credentials to view it. For example anything that has to do with viewing
> sensitive information about an authenticated users stuff. Basically we only use our token for harmless requests,
> and if one gets used I get a little ping on the dashboard saying "probably private info" and it'll give me an
> option to view the headers, return value, etc., and then an option to ban it from being used or allow it, or
> ignore for x minutes"

**And your clarification, when asked whether the lead read it right:**

> "Basically yes. I see what the endpoint is, what it returns, what they passed, the type of requests it was, etc.,
> and see if we want to block this request, or throttle it, or whatever it may be"

**The lead's reading.** D1 stays as built: callers never carry your cookie. New work on top: callers are refused,
before Roxy calls Roblox, for Roblox endpoints that need a signed-in account (private data). Roxy flags such
endpoints on the dashboard ("probably private info") with what the endpoint is, the kind of request (GET, POST and
so on), what the caller sent (headers, query and body, private values masked), what Roblox answered (masked), when
and how often. From the flag you decide: block it, throttle it, allow it, make any other rule Roxy has from it, or
ignore the flag for N minutes. Your account is used only for harmless requests; if an answer to your account ever
looks private, the same flag comes up and that answer is never passed on to a caller.

**Size:** L, about 80 agent hours (76 in the design, plus "throttle it" and "whatever it may be" from your
clarification).

**Main parts:**

- A built-in list of endpoints that need a signed-in account: 71 rows (63 that refuse, and 8 narrower ones that keep
  the public endpoints under them open), each with the public Roblox document it came from. It covers account
  settings, email, phone, birthdate, Robux and transactions, trades, private messages, friend requests,
  notifications, two-step verification, logins and passwords, billing, chat, group admin pages, your own avatar and
  favorites, and creator settings.
- The check: a caller asking for one of them gets Roxy's refusal at once (403 with a clear message) instead of
  Roblox's 401, and no call reaches Roblox.
- Learning: when Roblox keeps answering 401 ("Authorization has been denied for this request.") on an endpoint that
  is not on the list yet, Roxy adds it as "learned, waiting for your review" and refuses it too. Several checks keep a
  Roblox hiccup from blocking a normal endpoint.
- Watching your account's answers (today only Roxy's own account check, every 30 minutes) for anything that looks
  private: an email address, a phone number, a birthdate, a Robux balance, recovery codes and similar.
- The ping: the bell counts "Probably private info" next to the recommendations, and a card on the Credential page
  shows each flag with the request and the answer (private values masked, secrets never stored). Buttons: Block it
  for callers, Throttle it (from your clarification), Allow it, Ignore for [60] minutes, Undo, and a link that starts
  any other rule from the flag. Every choice is written to the audit log and can be undone. You choose how wide each
  one is: the exact address, the endpoint for any id, a group of endpoints, or the whole Roblox service (D11).
- Protection > Private endpoints: the whole list, yours to edit (add, narrow, widen, switch off, delete), a "would
  Roxy refuse this address?" tester, and how often each row refused callers.
- A section in the migration report: what callers read through v1 with your cookie, from v1's own records. It reads
  the frozen copy of v1's files taken at the cutover (`MIGRATION.md` step 4.3), so keep that copy until this report
  has run, even past the 30 days of `MIGRATION.md` section 5.6.
- Optional, later: a daily re-test of learned rows (one call without an account) that lifts a learned block when
  Roblox answers without an account again.

**Until then:** your cookie never travels with callers' requests in v2. The credential allowlist ships empty, and only
Roxy's own account check uses the cookie (it reads your account's id, name and display name). A caller who asks for
an endpoint that needs a signed-in account is sent to Roblox without any account, and Roblox refuses it (401). You see
those refusals on the Overview ("4xx from Roblox") and on the Endpoints page. Optional: block `auth.roblox.com` on
Protection > Endpoint blocks (`MIGRATION.md`, step 5.1, "Owner choices after the first sign-in"), which stops login
and password reset attempts through your server's address from the first night.

**Questions for you:**

1. When Roxy learns a new endpoint that needs a sign-in, should it refuse callers at once and ask you (suggested), or
   only ask you?
2. "Ignore for N minutes" only hides the ping; what Roxy does with the endpoint stays as it is. Is that what you
   meant?
3. Endpoints that need a sign-in but return public data (for example `multiget-place-details`) are refused too, since
   Roblox refuses them without an account anyway. Fine?
4. Roxy's account check reads your account's id, name and display name every 30 minutes, to know the cookie still
   works and is the same account. Harmless to you?
5. Should the refusal text say "contact CeaselessQuokka on the DevForums or Twitter", or stay neutral? It is
   editable either way.
6. Should Roxy email you when your account reads something private-looking (suggested yes), or show it in the bell
   only?
7. When you block or allow a flagged endpoint, should Roxy offer "this endpoint, any id" first (suggested), or the
   exact address?
8. After the cutover, do you want to refresh your Roblox cookie (sign out of your other sessions on Roblox, then give
   v2 the new cookie on the Credential page), so that nothing v1 relayed with the old one stays usable?

## 2. D12: the prepaid DataImpulse balance

**You said (D12):**

> "I got the 5 GB plan. it is just 5 for now, but it is currently at 4775.43 MB as of writing"

**And (B11):**

> "No per month, have a solid 4775.43 MB atm, that is down from like 5000 MB from at least 3 months ago"

**The lead's reading.** The DataImpulse plan is a prepaid pool, not a monthly allowance: 5 GB bought, 4,775.43 MB
left on 2026-10-14 (down from about 5,000 MB over at least 3 months). Roxy needs a prepaid balance mode.

**Size:** L, about 44 agent hours.

**Main parts:**

- A balance you enter: the figure DataImpulse shows and when you read it, or a top-up when you buy more. Roxy
  subtracts every rotator byte it measures from that moment on.
- A stop at a small reserve (50 MB suggested), so that Roxy's own rotator checks still work. Callers are then served
  direct only; nobody is refused because of it.
- An email when the estimate falls below 1,000, 500, 250 and 100 MB left (one email per level for each balance you
  enter).
- "Lasts until": the date the balance reaches the reserve at the current pace, with a range.
- The Egress page's Budget card in prepaid words: balance left, used since your reading, lasts until, value left; two
  small forms ("DataImpulse shows ... MB" and "I bought ... more"); the history of what you entered; and how far
  DataImpulse's count and Roxy's differ between two readings.
- The health check, the recommendations, the daily digest and the export all use the same numbers.
- The monthly mode stays for other plans. When this ships it takes over from the stand-in below: you enter a fresh
  reading, and `rotator_quota_gb_per_month` goes back to 0 (the update must not mistake the stand-in for a monthly
  plan; the Budget card will say what to do).

**Until then (the stand-in):** at the first sign-in you set `rotator_quota_gb_per_month` to the balance left at the
cutover and `rotator_billing_day` to the cutover day (`MIGRATION.md`, step 5.1, "Owner choices after the first
sign-in"), so the alerts at 50, 80 and 95 percent and the hard stop at 100 percent guard against a runaway. That
model starts again from zero every month, which is wrong for a prepaid pool, so on each billing day you enter the
balance DataImpulse shows again. At the default `rotator_weight` of 0 (D13) the rotator carries traffic only while
the direct path cools down, so v2 should use far less than v1's 225 MB in about 3 months.

**Questions for you:**

1. Does DataImpulse show MB or MiB (or GB)? A steady 4.9 percent gap between its count and Roxy's would mean MiB.
2. What did the 5 GB cost? With the price, Roxy shows what the balance left is worth.
3. Does DataImpulse data expire after some time? If it does, Roxy should also warn before that date.
4. Is automatic top-up off on DataImpulse? If it is on, running out costs money, and the stop becomes a money
   safeguard.
5. Does anything besides Roxy use the same DataImpulse account? Roxy cannot see that traffic.
6. Are a 50 MB reserve and alerts at 1,000, 500, 250 and 100 MB left right for you?
7. Roughly when did it show about 5,000 MB (the month is enough)?

## 3. Two small safety checks moved from the cutover

These were planned for the cutover and were left out to get v2 to you sooner. Both matter only once a list has
entries, and both lists ship empty.

- **A credential allowlist row names exactly one endpoint** (D1, plan rule C1): one literal Roblox host and a literal
  path, never a wildcard host or a pattern, so a row can never put your account on a whole service by accident.
- **The game server ranges refuse unsafe entries** (B17): nothing wider than a /16 (IPv6: /32), and no private,
  loopback, link-local, shared or multicast range. The top search result for Roblox's addresses lists exactly such
  ranges.

**Size:** S, about 3.5 agent hours.

**Until then:** leave both lists empty: the Allowlist card of the Credential page (adding a row asks for a fresh
second factor anyway) and the setting `roblox_egress_cidrs`.

## 4. A9: your account (name, password, email)

**You said (A9):**

> "Please port over, but provide a way for me to change name, password, and email like an actual account would be
> able to"

**The lead's reading.** Import the v1 password at the cutover (v2.0 does: `MIGRATION.md`, steps 3.1 and 4.4), and
add account management: change the sign-in name, the password and the email in the dashboard.

**Size:** L, about 41 agent hours.

**Main parts:**

- A "Your account" page in the user menu (top right): your sign-in name, a display name, your password and your
  email.
- Changing the password asks for your current password and a fresh authenticator code, signs out every other device,
  forgets trusted devices, and emails you with a "this was not me" link.
- Changing the email sends a code to the new address first, and tells the old address afterwards.
- Every change is written to the audit log and alerts the alert address.
- The console script learns the same: list the accounts, rename, a display name, a new email on its own, and "end
  every session" (for a lost laptop).

**Until then:** the console script `scripts/create_admin.py` on the server. `MIGRATION.md`, step 5.1, "Your admin
account until the account page ships", says exactly what it can do: a new password, and a new email together with a
reset, but no new sign-in name.

**Questions for you:**

1. After a password change, should Roxy also forget your trusted devices (suggested)?
2. Sign-in codes and account notices go to your account's email, and alerts keep going to v1's alert address. Right?
3. Do you want a display name apart from your sign-in name?
4. Should the sign-in emails show New York time next to UTC?

## 5. A10: "How Roxy is doing", in plain words

**You said (A10):**

> "Once we are sure everything is stable (hopefully Roxy V2's panel will have reactivity to state and let me know
> when things are wrong, going as expected, going better than expected, almost like a pocket LLM but obviously no
> where near that power, that'd be cool though)"

**The lead's reading.** Rule based, in plain words, with three moods: needs you, as expected, better than expected.
Deleting the old work folders waits for "stable" (item 15).

**Size:** L, about 57 agent hours (6 more for the optional parts).

**Main parts:**

- A small narrator on the leader, every 60 seconds. It reads numbers Roxy already keeps (nothing new on the request
  path), judges each against a stated window, a stated source, Roxy's own usual level and a written goal, and writes a
  few short sentences: what needs you, what is as expected, what is better than expected.
- The Overview opens with it, the bell counts what needs you, and the daily digest starts with the day's version.
- Every sentence has a "How we know" line: the window, the source, the usual level, the goal, and how many calls it
  rests on. It never says "better" unless the difference is larger than random ups and downs, the data is complete,
  and no data reset sits inside the comparison.
- The first week after the cutover as a report card ("Day 3 of 7") against the plan's goals (Roblox 429s under 0.5
  percent of calls, no 429 on the account's calls, fewer 429s per 10,000 requests than v1's own figure), and a
  "Settled in" milestone: the honest signal for "once we are sure everything is stable".
- Memory problems made visible: today a worker stopped for memory leaves no trace on the dashboard.
- It is not a language model and never pretends to be one: the same numbers always give the same sentence. It costs
  about 0.1 s of database reads a minute and under 1 MiB of memory.

**Until then:** the Recommendations page (50 rules that speak when something should change), Check Proxy Health, the
alerts, and the daily digest (on from v2.0).

**Questions for you:**

1. Should "better than expected" lines be on from the start (suggested yes)?
2. Should it say "Roxy" (suggested, like the rest of the dashboard) or "I"?
3. Should it email you when Linux stops a worker for memory (no alert covers that today; off until you say yes)?
4. Any first-week goal to add, such as a cache share of at least 40 percent?

## 6. A4 and A6 follow-ups: the digest preview and the User-Agent experiment

**You said (A4, the daily digest):**

> "On, but please ensure it is easily editable"

**And (A6, the User-Agent experiment):**

> "Keep it on, that's a fun experiment, thank you"

**The lead's reading.** A4: the digest is on by default and sent whatever the alert level filter says, and it is
easy to edit. v2.0 ships that part (`alert_digest_enabled` and `alert_digest_hour` on Settings > Alerts). A6: the
experiment is on; you switch it on at the first sign-in (`MIGRATION.md`, step 5.1), which starts its 7-day run.

**Size:** M, about 17 agent hours (5 more for the optional digest sections).

**Main parts:**

- The digest: a preview on Settings > Alerts and a "Send a sample now" button; optional, a choice of what the digest
  includes. The Alerts card also gets a "Daily digest" heading over its two settings and a line such as "Next
  digest: Thursday, 9:00 New York time (in 14 hours)", and the setup guide (item 10) a digest step.
- The experiment: its state on Upstream > Routing ("Running, ends Oct 21" or "Ended"), and a counter of calls and
  Roblox 429s for each side, so a 7-day run ends with an answer.

**Until then:** the digest is on and edited on Settings > Alerts. The experiment's recommendation (UP-UA-EXPERIMENT)
estimates each side from the request samples of the last 24 hours, so the first run may end without a clear answer;
switching the experiment off and on again starts a new run.

**Questions for you:**

1. Is 9:00 in the morning, New York time, a good hour for the digest (the default)?
2. If the first run ends without a clear answer, should it run again once the counter ships?

## 7. B17: Roblox game server ranges (an optional preset)

**You said (B17):**

> "Can you actually do that research for me please and add that as an optional option and default in the dashboard
> and let me see if I want it then? It'd be nice for the dashboard to have an onboarding experience like you're
> opening the iPhone for the first time"

**The lead's reading.** Research the address ranges Roblox's game servers call from (done, below), and ship them as
an optional preset, off by default, that you can turn on. The setup guide is item 10.

**Size:** M, about 25 agent hours (27 in the design; its safety check is item 3).

**What the research found (2026-10-14).** Only public records were read: RIPEstat (the RIPE NCC's routing data), the
ARIN and APNIC registries, PeeringDB, ipinfo, Roblox's annual report (Form 10-K for 2025, on sec.gov), a Roblox
newsroom post of June 2025, Roblox's documentation and DevForum threads. The last three were read through search
engine summaries: no Roblox site was contacted.

- Roblox has three networks (autonomous systems): AS22697 (production, where the game servers run), AS11281 (offices)
  and AS139229 (announces nothing).
- Roblox publishes no list of the addresses its game servers call from. Community answers point at AS22697, and
  DevForum observations put HttpService calls in the same address block as the game server itself. Calls from Roblox
  Studio come from the developer's own computer.
- **Roblox's own network:** six address blocks registered to Roblox and announced by AS22697 (about 33,800 IPv4
  addresses plus two IPv6 blocks), unchanged for years (registered 2017 to 2019). Three independent records agree for
  each: the registry names Roblox, the routing table shows Roblox's own network announcing it, and the main block is
  signed (RPKI).
- **Roblox's cloud addresses:** two blocks Roblox owns inside Amazon's cloud (about 2,560 addresses, registered in
  2024 and November 2025), announced by Amazon for Roblox and usable only by Roblox. Roblox says it adds cloud
  capacity at busy times; that game servers call from these blocks then is likely but not confirmed.
- **Left out on purpose:** the other half of a block a popular blog post calls "Roblox's" (it belongs to an Italian
  internet provider), the private ranges the same post lists, Roblox's office networks, blocks registered to Roblox
  but not routed, blocks a carrier lent Roblox, and any cloud provider's shared ranges (anyone can rent an address
  there).
- **How sure:** that the blocks are Roblox's, very high; that game servers call from the own network in normal times,
  high, but Roblox does not document it; at peaks some may call from the cloud blocks, so expect a little under 100
  percent at weekend peaks. Your own traffic gives the real answer, so the preset ships off, and a recommendation
  first measures what share of the callers that send a `Roblox-Id` header come from each group.
- **How it changes:** the blocks are old and stable, and new space arrived about once a year. Refresh before each
  release and at least every 3 months.
- **What trust gives a caller there** (with Roblox's headers too): a lower bot score, and a strike instead of an
  automatic ban once spam detection is armed. Never a way around the per-address limit, the place limits, filters,
  blocks or bans. "Trusted" means a real Roblox server, not a friendly game: anyone can publish a Roblox game.
- **Terms of use:** the blocks are facts. Shipping a short summary of them with a source note and the credit line
  "Routing data: RIPE NCC RIS via RIPEstat. Registration data: ARIN and APNIC." is a small risk under RIPEstat's and
  ARIN's terms of use, not zero and not legal advice. The alternative is a paste box with links.

The exact blocks are in the design note. They go into the code only with your yes (question 2), because the build's
rules otherwise keep real network addresses out of the code and the docs.

**Main parts:** a setting with three choices (Off, Roblox's own network, its own network and its cloud addresses); a
fast matcher that costs a microsecond or two a request whatever the list size; a Protection card "Roblox game server
ranges" with what your traffic says, one-click buttons, the list with its sources and date, and the hand-added
ranges; a "Network" line on each address in Clients; the ROBLOX-RANGES recommendation (suggest, outside, none
inside, old list); the maintainer's refresh script; optional, a "compare with a fresh copy" box.

**Until then:** `roblox_egress_cidrs` stays empty, the safe default: no caller gets game server credit, because the
`Roblox-Id` header and the User-Agent alone are easy to fake. Do not paste ranges from a blog post.

**Questions for you:**

1. When you turn it on: Roblox's own network only (suggested), or its cloud addresses too?
2. Ship the list inside Roxy (suggested), or ship none and paste it yourself from the links?
3. Is the GitHub repository public? It decides whether the list counts as "made publicly available" under ARIN's
   terms.
4. Do you or your developers call Roxy from Roblox Studio? Those calls show as "outside the ranges", which is
   expected.
5. Refresh the list by hand (suggested), or a weekly automatic check from the server?

## 8. D17: Clear any card, Start fresh, the v1 snapshot, and windows of changes

**You said (D17):**

> "Please migrate, but also please ensure that every part of the dashboard can have clearable data just pertaining to
> that section, and a way to clear all data to start fresh. It would also be nice to be able nice to have the graphs
> be able to view a window of changes, so if you don't want to data, but have a snapshot of data (i.e. this migrated
> data) you can view it, or hide the results later when you have more, accurate data (hopefully the internal logical
> for diagnostics is solid and provide the ability to provide an astronomical amount of insight)"

**The lead's reading.** Migrate as built (v2.0 does), plus: every dashboard section can clear its own data; one
"clear everything, start fresh"; charts can show a window of changes; and the migrated v1 snapshot can be shown or
hidden.

**Size:** L, about 72 agent hours.

**Main parts:**

- A Clear button on every card that shows stored numbers. Its drawer shows exactly what goes, which other cards lose
  the same numbers, and what is never touched. Clear all of it, or only the time range picked at the top of the page.
  A copy of the database is saved first where there is room, the clear goes to the audit log, and every chart shows
  a marker where it happened.
- Cards that cannot be cleared on their own today get their own clear: recent notable events, spam detector history,
  rule hit counts, CSP reports, dry-run samples, disk and pipeline history.
- Clears as fine as the rules (D11): one endpoint, a group, a whole service, one rule, one client.
- A Start fresh card that deletes every statistic at once. Your settings, rules, bans, account, the credential, the
  audit log, the rotator's billing count and your DataImpulse balance always stay; the v1 snapshot stays too unless
  you tick "also delete the v1 snapshot".
- An "Imported from v1" card with every v1 number (today only one of 19 is shown anywhere), and a "Show v1 numbers on
  other cards" switch to hide them once v2 has enough of its own.
- Charts: markers for resets, setting and rule changes, deploys and the v1 import (each kind can be shown or hidden),
  "Before and after" from a marker, "Compare with a range starting at ...", quick ranges such as "Since the last
  reset", and "Show this range on every card" after zooming in.

**What waiting costs.** v1's counts of header names, header values, User-Agents and errors are merged into v2's own
rows from the first day, and v2.0 does not write down the v1 part of each row (that small step was left out to ship
sooner). So for those four lists the v1 part can never be hidden or cleared on its own: they show v1 and v2 together.
The v1 headline numbers (requests, Roblox 429s and the "per 10,000 requests" baseline) are kept apart and are not
affected.

**Until then:** the Data page's resets (one family at a time, with a preview, a reason and, for a whole family, a
typed phrase). Today the "everything" reset also deletes the v1 snapshot: do not use it before this update if you
want to keep the v1 numbers. (A reset saves a copy of the database on the server first when there is room.)

**Questions for you:**

1. Start fresh keeps the v1 snapshot unless you tick the box. Right?
2. Should Start fresh also reset callers' limits, the Roblox cooldowns and the bans the detectors made? (The design
   leaves them unless you tick those boxes.)
3. Hiding the v1 numbers is your own choice, like the theme. Should Roxy ever hide them by itself after some days?
4. Setting and rule changes as chart markers: on by default (each chart can hide them). Keep it?
5. The audit log, the settings history and your sign-in records can never be cleared, and the DataImpulse figures you
   type in are cleared only on their own, with a typed phrase. Agreed?

## 9. A3: times in your device's time zone

**You said (A3):**

> "Local timezone, but default to New York timezone"

**The lead's reading.** Show times in the viewer's own (browser's) time zone, with America/New_York as the default.

**Size:** M, about 12 agent hours.

**Main parts:**

- Every page shows times in the time zone of the device you look from (your phone and your laptop each use their own).
- New York stays the server's zone: where a day and a month start in long charts, and the hour of the daily digest.
- Preferences: "This device's time zone", "The dashboard time zone", or another zone you pick.
- Day charts say "Days start at midnight New York time"; a custom range is typed in your own zone.

**Until then:** New York time everywhere (`ui_timezone` is America/New_York). On a device that is not on New York
time, pick a zone in the user menu's Preferences ("Show times in this time zone").

**Question for you:** do you usually look at the dashboard from New York time? If not, this moves to v2.2.

## 10. B17: the first-run setup guide

**You said (B17):**

> "It'd be nice for the dashboard to have an onboarding experience like you're opening the iPhone for the first time"

**The lead's reading.** A wish: a first-run onboarding experience on the dashboard.

**Size:** M, about 36 agent hours.

**Main parts:** the first time you open the dashboard it greets you, then walks you through about ten short screens:
your account, your sign-in, the time zone, the Roblox credential, the rotator and your prepaid balance, alerts (with a
real test alert), the digest, the public site texts, and the optional game server ranges. Each screen can be skipped,
"Finish later" keeps your place on any device, it works one-handed on a phone, and a card on the Overview brings you
back to it.

**Until then:** `MIGRATION.md`, step 5.1, and the admin guide's "Getting started" (the first-hour steps).

**Question for you:** should the guide open by itself right after your first sign-in, or only from a card on the
Overview?

## 11. D11: rules at every depth, everywhere

**You said (D11):**

> "I am fine with this, but please add the ability to do per specific endpoint, per endpoint "group" (like
> games.roblox.com or some subset more general that games.roblox.com/games/votes). I want to have that insane
> flexibility on everything that can support it, where you can provide multiple rules to follow like this but even
> deeper. Please ensure this for all applicable areas of the dashboard"

**The lead's reading.** D11's own value stays (place limits observe and recommend; 600 a minute ready). New work:
every rule-like feature can be aimed at any depth, from one exact endpoint through an endpoint with any id and a
group of endpoints to a whole service, with several rules stacked at different depths, in every part of the dashboard
where it applies.

**Size:** XL, about 130 agent hours (10 of them optional).

**Main parts:**

- The depths: all of Roblox; one service (`games.roblox.com`); an endpoint group (`games.roblox.com/v1/games/votes`
  and everything under it); one endpoint for any id (`games.roblox.com/v1/games/{gameId}/votes`); one exact address.
- One "Applies to" box on every rule form, the same everywhere: paste any address (even a full Roxy link) and choose
  the depth from buttons.
- While you type, the box shows what the rule matches: requests a day, the endpoints, real examples from the last 15
  minutes, and which of your other rules are deeper (they win there) or wider (this one wins over them).
- A clear order when several rules cover a request: the deeper rule wins. For limits you choose per rule whether the
  wider limits still apply too ("stacking"), so a service-wide limit and a tighter endpoint limit can both hold.
- Exceptions (block a whole service but let one endpoint through), and rules that end by themselves ("for 30
  minutes").
- Per-experience limits by endpoint (D11): for every experience or for one, at any depth, and a total budget for one
  experience.
- A "Which rules apply to this address?" box (Endpoints page and the command palette) listing every rule of every kind
  in the order Roxy applies them, and which one decides.
- Every family: endpoint blocks and rate rules, filters, User-Agent rules, cache rules and cache parameters, upstream
  pacing groups, bans, bypass, body capture, spam detector exclusions, recommendation quiet scopes, data clears and
  page filters.
- Where Roxy will not go wider, and why: the credential allowlist stays one exact endpoint at a time (rule C1 and your
  D1 answer), and the safety checks against login token smuggling, bad addresses and floods always cover everything
  (rule C2).

**Until then:** today's patterns already reach most depths. A host alone covers the whole service, a path covers it
and everything under it, `*` stands for one part of the path (an id), and a regular expression can name one exact
endpoint; the most specific row wins.

**Questions for you:**

1. When a limit for one endpoint and a limit for its whole service both exist, should both apply (stacking,
   suggested, with a switch on every rule), or should the endpoint's own limit replace the wider one?
2. Rules on the part of an address after "?" (for example only `?limit=100`): not for now (suggested)?
3. Should some endpoints "count more" toward a caller's per-minute allowance (for example a heavy search counts as 3
   requests)? It is optional work.

## 12. Swap and kernel settings in the install script

**You said (A7, the kernel setting `tcp_migrate_req`):**

> "Whatever you think is best for this type of server with this type of processing of processing power for this type
> of workload. What do you think?"

**And (A8, a swap file):**

> "Yes? I am unsure what that is, but do the safest option possible please"

**The lead's answer.** Set `net.ipv4.tcp_migrate_req` to 1, and add a 1 GiB swap file used only as a last resort
(`vm.swappiness` 10), with Roxy's colors kept out of swap (`MemorySwapMax=0`). v2.0 does all of it by hand at the
cutover; this item puts it in `deploy/install-system.sh`.

**Size:** S, about 6 agent hours (about 5 more to measure a worker restart with the setting on, and to show swap and
the two settings on the System page).

**Main parts:** `install-system.sh` creates the swap file (with `--no-swap` to skip it and `--swap-mb` for another
size), installs the kernel settings file, and the unit file itself carries `MemorySwapMax=0`; gunicorn logs the value
of `tcp_migrate_req` when it starts; a test shows a worker restart resets no waiting connection with the setting on;
the System page shows swap and the two settings, and warns when a color uses swap.

**Until then:** the manual steps of `MIGRATION.md`, step 2.10, and `deploy/README.md`, "Memory, swap and kernel
settings". They use the same file names, so the install script later replaces them with its own copies, and the
hand-made unit drop-in can then be deleted.

## 13. Performance items still open

These are not requests of yours: they come from the release measurements of 2026-10-14 (`docs/PERFORMANCE.md`).
Most of them change nothing callers get; they make some pages slower, or make Roxy try an endpoint again later than
Roblox allowed. The host breaker item is the exception: it can refuse callers of a whole host for 30 to 60 s.

- **The first proxy request after a worker starts: fixed before the cutover** (`docs/PERFORMANCE.md`, "Startup
  warm-up (2026-10-14)"). FastAPI prepared all 385 dashboard routes on a worker's first proxy request, which stopped
  that worker for 0.25 to 0.37 s after every start, deploy and restart (about every 20,000 requests); requests queued
  meanwhile and then left together. The worker now prepares them before it serves. In the 429 test: 1 call before
  Roblox's first 429 came back (was 7), then one try at 30 s and one at 60 s, as Roblox asked (was 71.5 s), and no
  caller was told "busy" there (was 731).
  **Left:** when 7 or more calls to one endpoint are already on their way as Roblox's first 429 comes back (possible
  within its burst of 10), Roxy still waits 71 to 87 s instead of the 30 s Roblox asked for before trying that
  endpoint again (safe for Roblox, slower to recover; changing how the adaptive cut counts is a plan 7.3 decision).
- **One endpoint's 429s can pause its whole host for 30 to 60 s** (found by the skeptic of that fix; it predates the
  final review). Every counted 429 also records a failure on the host's breaker (`src/roxy/upstream/effects.py`), and
  that breaker opens at 5 failures, so 5 or more calls to ONE endpoint that go out together and all get 429 open the
  breaker for every endpoint of the host for 30 to 60 s, while plan 7.5 lets a whole host cool down only when 3
  different endpoints of it do. Whether a 429 should count on the host breaker at all needs a plan 7.10 / 7.5
  decision.
- **Event loop stalls: fixed before the cutover** (same section). The soak's worst heartbeat (105 and 136 ms) was
  one-time startup work in each worker's first minute, not a steady stall: the route build above and two full
  garbage collections with the listeners open. The worker now does that work before it accepts: the worst heartbeat
  of a 200 s replay was 18.3 and 14.1 ms (was 26 to 316 ms). Each worker starts about 0.5 s later and about 13 MiB
  higher (the same peak), so the "fresh color" memory figures of the sizing docs are a little low at start.
  **"Degraded" answers under overload: no change.** Past the write lock ceiling (about 325 answered requests a
  second) more callers got HTTP 503 "degraded" (a median of 139 a run against 40). Traced: not from the final review;
  the perf lane's faster write path moved the overruns from the abuse check (which lets the request through) to the
  upstream reservation (which answers 503, the plan's C7 rule), about the same total. The lever is the ceiling itself.
- **The quiet-machine misses** (`docs/PERFORMANCE.md`, "Quiet run: every target not met"): the proxy's own time on a
  cache hit and on a miss (p99 above plan 6.7's 8 and 15 ms); the abuse check's database write in the running system
  (p99 above 3 ms); the slowest metrics flush (above 50 ms); the upstream transaction, still not measured on its own;
  the Overview's first load after a start; under a flood while hot.db is degraded, one address got 1 or 2 requests past
  its limit; hourly points over 90 days (an option the dashboard never uses); pages above about 150 KiB.
- **Three dashboard fixes to confirm on the pages.** Clients > IP addresses, Protection > Refusal reasons with the
  attempts tabs, and the Overview were traced and fixed in the pre-cutover round, measured on their database reads;
  the next page scenario run confirms them on the pages.
- **Left after those fixes** (`docs/PERFORMANCE.md`, "Left after the third pass"): the page scenario's test data
  should carry the metrics 0010 stamp (or record the Roblox answers while it fills), so the Overview's answer cards
  are measured as in production; a page that lands on the leader while the recommendations engine runs (0.6 to
  0.9 s every 30 s) can still push one sample in 20 over 300 ms, fixed by letting the engine yield between rules;
  and the other dashboard reads should be checked for plans that turn slow once SQLite has its statistics (fast on a
  fresh copy, slow after `PRAGMA optimize`), each pinned with `INDEXED BY` and a query plan test.
- **A machine the size of the server** (2 vCPU, 909 MB): every figure so far comes from the development machine.
- **The replay's margin:** Roblox 429s in the v1-like replay were 0.097 percent against the 0.1 percent bar, so one
  more 429 in a run would miss it. The route fix above does not change it: the one 429 is the discovery 429 on avatar
  outfits at the plan default of 120 a minute (`docs/PERFORMANCE.md`, "Finding LOAD-1" lists the remedies, each a
  plan decision).

**Size:** S to M each.

## 14. The docs screenshots

- The System page picture in `docs/screenshots/` shows the development machine's host name in the leader id, and its
  Environment card shows temporary paths and a local port. These are not secrets, but they are details of the build
  machine in the repository. Fix: take the pictures with a neutral host name.
- From the same review: the open recommendation count differs between pictures (the recommendations engine ran
  while they were taken), and one phone picture shows "1 requests refused so far", a plural slip in the app's text
  worth fixing at the same time.

**Size:** S.

## 15. Your own to-dos for later

Nothing to build; listed so they are not lost.

- **A5, the alert webhook:** "Yes, but I'll do that later" (a webhook address in the `alert_webhook_url` credential
  file, then `alert_webhook_enabled` on).
- **B18, the Luau examples:** "I can do a review of that later" (paste one home page example into Roblox Studio).
- **A10, deleting the old work folders on the development PC:** "Once we are sure everything is stable". The
  narrator's "Settled in" milestone (item 5) is meant as that signal.
- **C20 to C27 of the to-do list:** "20-27... I'll reply to later". Encrypted and off-site backups, the SSH key for
  GitHub Actions, the authenticator app and recovery codes, the cutover window, the go-ahead for SSH, the merge and
  push, the GitHub settings, and the date to delete v1's files. `MIGRATION.md` walks through each one.
- **The public site:** should "DevForums" and "Twitter" link to your profiles? If so, send the two links.

## 16. Other known follow-ups

Known before your answers, and recorded in `CHANGES.md`, "Known limitations and follow-ups": roles for several
admins (D22), Open Cloud API keys (D19), a written procedure to replace the encryption keys, and a source of
"anonymous against account" comparisons for the shadow report.
