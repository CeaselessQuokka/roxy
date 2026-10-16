# Endpoint policy: implementation brief

Status: implemented on 2026-10-16 with the recommended answers to section 11 (CHANGES.md, "After the cutover";
the code is `src/roxy/policy/`). Written 2026-10-16 for the LLM (or person) who builds this feature. It
replaces owner decision D1 ("callers never get the credential") with the owner's new design. Read all of it before
writing code. Section 11 lists the questions the owner must answer first, each with a recommended default you may use
if the owner says "use your defaults".

## 0. What is in this folder

| File | What it is | Who edits it |
|---|---|---|
| `BRIEF.md` | This document: the design, where it touches the code, the admin page, the tests, the open questions. | People |
| `endpoint_policy_seed.json` | One reviewed row for each of the 992 operations Roblox documents on 35 hosts, plus host-level defaults for the 6 hosts Roxy allows that Roblox does not document. This becomes the data Roxy ships. | People, then regenerate the catalog |
| `CATALOG.md` | Every row of the seed as tables per host, with links to Roblox's docs. Generated. | `scripts/gen_endpoint_catalog.py` only |
| `DOMAIN_ANALYSIS.md` | What each domain does, its default policy, and the endpoints that look harmless but are not. Read this before changing any verdict. | People |
| `scripts/endpoint_policy_inventory.py` | Rebuilds the inventory from Roblox's OpenAPI file and lists drift against the seed. | People |
| `scripts/gen_endpoint_catalog.py` | Renders `CATALOG.md` from the seed. | People |

Source of the data: Roblox's Creator Hub "Cloud API reference" (https://create.roblox.com/docs/cloud) is rendered
from `content/en-us/reference/cloud/openapi.json` in the public repository https://github.com/Roblox/creator-docs.
The seed was built from commit `710b20a5f4f1` (2026-10-16). That file covers every domain in the docs sidebar
(accountinformation through users, plus apis.roblox.com) and every feature page (Accounts, Assets, Avatars, Badges,
Groups, and so on). Each row carries `feature_doc` (the feature page anchor, from Roblox's own `externalDocs`) and
`domain_doc` (the domain page, same anchor). Both anchors were checked on the live site.

## 1. What the owner asked for

The owner's words (2026-10-16), condensed. "Roxy is not for authenticated requests" was misread. What it means:

1. Roxy sends **its own** Roblox credential with every request, except blocklisted endpoints.
2. Blocklisted endpoints are the ones that act on the signed-in account or need a sign-in to act on any account
   (example: everything on accountinformation.roblox.com such as `/v1/phone`, `/v1/email/verify`), plus "sneaky"
   ones that leak identifying or security-relevant information. Read endpoints like catalog search are fine to send
   the credential to.
3. Blocklisted endpoints are **blocked entirely**: nothing is routed to Roblox; the caller gets an error ("a 500 or
   something", see Q1).
4. Any request where the **caller** attaches their own cookie or any other sign-in is refused, and logged so the owner
   can see who is sending their own secrets by mistake.
5. A page in the admin dashboard to add or remove whole categories or single endpoints, with sensible defaults and a
   link to the Roblox docs for each endpoint.
6. Remove every note on the homepage saying authenticated requests are not allowed.

This reverses D1 (`DECISIONS_REVIEW.md` line 56 and the D1 row near line 91, `REMAKE_PLAN.md` line 61) and
supersedes `ROADMAP.md` item 1 ("the private endpoint guard"), whose built-in list of 71 sign-in endpoints this seed
replaces with 992 reviewed rows. Record the change as a new decision row, do not edit history away.

## 2. Before and after

| | Today (D1) | After |
|---|---|---|
| Which caller requests carry Roxy's credential | Only rows in `credential_allowlist` (ships empty), GET and HEAD only | Every request whose policy verdict is `ALLOW_TOKEN` (161 documented operations by default), including the few POST batch reads |
| Endpoints that act on the account | Forwarded anonymously; Roblox answers 401 | Refused by Roxy before Roblox (`BLOCK`, 779 documented operations by default) |
| Endpoints where the credential would leak account data | Not an issue (no credential) | Forwarded without the credential (`ALLOW_ANON`, 52 by default) |
| Caller sends their own `.ROBLOSECURITY` | Refused 400, probe log | Same, plus a dedicated "Caller sign-in attempts" log, and `Authorization` / `X-Api-Key` are refused too |
| Admin control | Credential page, Allowlist card | New "Endpoint policy" page: categories, every endpoint, tester, attempts log, drift |

## 3. The policy model

### 3.1 Verdicts

Each operation (host + method + path template) has exactly one verdict:

* `ALLOW_TOKEN`: forward with the credential. Public data, or data that needs a sign-in to read but is about other
  users or public things (catalog search, followers lists, badges of a user, POST username lookups).
* `ALLOW_ANON`: forward, never with the credential. Useful anonymously, but the credential would make the answer
  describe Roxy's account (ownership flags, "has voted", viewer-relative friend states, the account's locale,
  private assets it can see) or would send the session to a host it has no business on (auth.roblox.com metadata).
  The owner did not ask for this tier; it is the safe way to keep 52 useful endpoints open. See Q4.
* `BLOCK`: refuse before Roblox, whatever the caller sends. Never forwarded, with or without the credential.

### 3.2 Categories (the toggle groups on the admin page)

Every row has one primary `category`. Defaults by category (counts from the seed):

| Category | Default | Rows | What it covers |
|---|---|---|---|
| `login-session-security` | BLOCK | 110 | login, logout, signup, sessions, tickets, passwords, 2-step, passkeys, PINs, recovery, email and phone verification |
| `account-identity` | BLOCK | 9 | who the account is: `/v1/users/authenticated`, `/v1/avatar`, group `membership` |
| `account-private-data` | BLOCK | 63 | email, phone, birthdate, settings, inbox, notifications, favorites, follows |
| `account-settings-write` | BLOCK | 17 | any change to the account's settings or profile |
| `social-actions` | BLOCK | 27 | friend, follow, block, message, push registration |
| `group-actions` | BLOCK | 57 | join, leave, roles, payouts, wall, admin-only reads |
| `economy-spend` | BLOCK | 49 | purchases, Robux, trades, private servers, premium, sales and revenue |
| `inventory-private` | BLOCK | 5 | the account's own inventory views and inventory writes |
| `avatar-write` | BLOCK | 15 | wearing items, outfits, body settings, thumbnail redraws |
| `creator-management` | BLOCK | 121 | develop, publish, configure, localization writes, uploads, permissions, server restarts |
| `creator-private-data` | BLOCK | 82 | analytics, stats, logs, creator-only views of owned things |
| `ads` | BLOCK | 24 | ad campaigns, sponsored items, click tracking |
| `open-cloud-key-only` | BLOCK | 199 | Open Cloud routes that take only an API key or OAuth (Roxy has neither; callers may not send theirs) |
| `platform-misc` | BLOCK | 1 | `/matchmaking-api/v1/client-status` (undocumented) |
| `public-read` | ALLOW_TOKEN 161, ALLOW_ANON 52 | 213 | everything callers should be able to use |

A category toggle has three states: **Defaults** (each row's own verdict), **Block all**, and for `public-read` only,
**Strip credential** (every row in it becomes ALLOW_ANON, a panic switch if the account gets throttled). There is no
"allow all" toggle for a blocked category: loosening is per endpoint, with a reason (section 8).

### 3.3 Risk

`risk` 1 to 4 is what a stranger could do with Roxy's account through that endpoint: 1 harmless, 2 low, 3 meaningful
(private data, a state change, a reason for Roblox to flag the account), 4 critical (session takeover, money, logout,
irreversible). The admin page sorts and colors by it, and loosening a risk 4 row needs an extra typed confirmation.

### 3.4 Precedence (how one request gets one verdict)

1. Caller sign-in attempt (section 6): refused, whatever the policy says.
2. Admin override for that exact operation (`endpoint_policy_override`).
3. Category toggle "Block all" (or "Strip credential" for `public-read`).
4. The shipped row's verdict.
5. Host default (`host_defaults` in the seed, for hosts Roblox does not document: `gamejoin`, `billing`,
   `engagementpayouts` and `voice` BLOCK; `search` and `translations` ALLOW_ANON).
6. Unknown operation on a known host: see 3.5.

Then the query guards (3.6) can turn an ALLOW into BLOCK for one request.

### 3.5 Unknown operations (not in the seed)

Roblox ships undocumented endpoints and adds new ones. This is where "sneaky" bites hardest. Recommended default (Q2):

* Non-GET/HEAD unknown operation: **BLOCK**. Writes are where the damage is, and every documented read-POST is
  already in the seed.
* GET/HEAD unknown operation: **BLOCK** if the path matches a danger pattern, otherwise **ALLOW_ANON** (forwarded,
  but never with the credential) and recorded in "Unknown endpoints seen" for review. Danger patterns, all matched
  case-insensitively on the normalized path: `/my/`, `/me/`, `/authenticated`, `/user/` (singular segment),
  `/users/me`, `logout`, `login`, `session`, `ticket`, `token`, `password`, `twostep`, `2sv`, `recovery`, `email`,
  `phone`, `birthdate`, `currency`, `robux`, `transaction`, `payout`, `billing`, `payment`, `purchase`, `trade`,
  `message`, `notification`, `settings`, `permission`, `audit`, `join-request`, `private-server`, `vip-server`.
* An admin can promote an unknown operation to any verdict from the review list. Promoting to ALLOW_TOKEN needs the
  same fresh second factor as any loosening.

Why not ALLOW_TOKEN for unknown GETs, as "token with everything" would suggest: a GET with no ids, like
`clientsettings /v2/user-channel` (returns a channel token) or `followings /v1/users/{userId}/universes` (only answers
for the account), looks exactly like a public read. The research found dozens of these among documented endpoints
alone. Undocumented ones are no safer.

### 3.6 Query and header guards

Some verdicts depend on a parameter, not just the path. Ship these as built-in guards (matched after
normalization, case-insensitive names and values):

| Operation | Guard | Why |
|---|---|---|
| `games GET /v1/games/{placeId}/servers/{serverType}`, `/v2/...`, `apis /public-server-browser-service/...` | Refuse `serverType` 1 or `Friend` | Friend servers list where the account's friends play |
| `groups GET /v1/groups/{groupId}/roles`, `GET /v1/roles` | Drop `includePrivate` (or refuse when true) | Private roles show only to members |
| `games GET /v2/groups/{groupId}/games`, `gamesV2`, `/v2/users/{userId}/games`, `develop GET /v1/groups/{groupId}/universes` | If ever changed to ALLOW_TOKEN: force `accessFilter=2` (Public) | Otherwise private games the account can see may be listed |
| `auth GET or POST /v1|v2/usernames/validate` | ALLOW_ANON already; never ALLOW_TOKEN with `context=UsernameChange` | The check becomes relative to the account's own username |
| `assetdelivery` (all) | If ever ALLOW_TOKEN: refuse `permissionContext`, `accessContext`, and headers `Roblox-Place-Id`, `serverplaceid`, `modulePlaceId` | They widen access to private assets |
| `auth GET /v1|v2/passwords/validate` | BLOCK already; also never log or cache-key the query | The password is in the query string |
| `locale GET /v1/locales/user-locale`, `/user-localization-locus-supported-locales` | Cache key must include `Accept-Language`, or do not cache | The answer varies by it |

Note: `scrub.FORWARDED_REQUEST_HEADERS` (`src/roxy/proxy/scrub.py` line 39) forwards only `accept`, `content-type`
and `content-length`, so caller headers like `X-HTTP-Method-Override`, `Roblox-Place-Id` and `Accept-Language` never
reach Roblox today. Keep it that way; any guard above that mentions a header is a second layer.

## 4. Matching rules (get these exactly right)

Every bypass of a blocklist is a matching bug. Rules:

1. Match on `(host, method, path)` after the same normalization `validate.parse_target` already does
   (`src/roxy/proxy/validate.py`), and refuse anything it would refuse. Then additionally:
   * Lowercase the path for matching. Roblox's legacy hosts are ASP.NET and treat paths case-insensitively, so
     `/V1/Logout` reaches the same code as `/v1/logout`.
   * Collapse duplicate slashes, drop one trailing slash, resolve no `.` or `..` segments (refuse them, as today).
   * Refuse an encoded slash (`%2F`, `%5C`) or backslash anywhere in the path: it could split a segment differently
     here than upstream.
   * Percent-decode unreserved characters once before matching; refuse a path that still contains `%` after that
     unless it is a valid encoding inside a single segment.
2. Path templates: `{name}` matches exactly one non-empty segment (`[^/]+`). Literal segments match literally.
3. Colon verbs: Open Cloud paths like `/toolbox-service/v2/assets:search` carry `:verb` as part of the last segment.
   Treat `assets:search` as one literal segment. A template `/v2/assets/{id}` must not match `/v2/assets:search` and
   the reverse; a template segment `{id}:start` matches `<value>:start` only.
4. Most specific wins: more literal segments beats fewer; on a tie, a literal beats a parameter at the first
   difference. Two different verdicts that tie exactly are a seed bug; the seed test (section 12) must catch it.
5. Spec keys with a `#host` suffix (15 rows, for example `/v1/metadata#auth.roblox.com`) are already cleaned in the
   seed: `path` has no suffix, `spec_key` keeps the original. Never match on `spec_key`.
6. `HEAD` uses the `GET` row. `OPTIONS` is refused as today.
7. Fail closed: a regex timeout (`rules/match.py` budget), a seed that did not load, or a policy table that cannot be
   read means BLOCK for every request and a critical health result. Never "allow because we could not tell".
8. Matching must be fast: about 1,000 templates, looked up per request. Index by host, then by method, then by
   segment count; compile templates once per config version, like `rules/store.py` does with its indexes.

## 5. Where it plugs into the request flow

All paths are relative to the repository root. Line numbers are from 2026-10-16.

### 5.1 The new check (refusal before Roblox)

* Add `EndpointPolicyCheck` in `src/roxy/abuse/checks/endpoint_policy.py`, position **145** (after
  `auth_smuggling` 140, before `header_rule` 150 and `endpoint_blocked` 160). Register it in `PIPELINE_ORDER`
  (`src/roxy/abuse/checks/__init__.py` lines 43 to 62) and update `tests/unit/abuse/test_abuse_pipeline_order.py`
  and `tests/integration/admin_api/test_api_protection.py`, which assert the order.
* On BLOCK return a `Refuse` like `checks/blocks.py` lines 38 to 55 do, with a new `ReasonCode.ENDPOINT_POLICY`,
  tarpit category `policy_blocked` (no tarpit by default: these are often honest mistakes), header
  `Roxy-Blocked: policy`, and `detail` naming the matched row id and category. Bypass entries do not skip it.
* Body (editable setting `endpoint_policy_block_message`): "Roxy does not forward this Roblox endpoint because it
  acts on a signed-in account or returns private account data. See <site>/docs#blocked-endpoints." Status: Q1.
* Compute the verdict once and store it on the request (`ProxyRequest`), so the cache and upstream read the same
  answer instead of matching again. Today they each call `rules.credential_rule_for` separately (5.2); keep a single
  decision point.

### 5.2 The credential decision (replacing the allowlist)

Today the "use the credential" decision is made in several places, all through `RulesSnapshot.credential_rule_for`
(`src/roxy/rules/store.py` lines 351 to 361):

* `UpstreamService._run` and `_credential_row` (`src/roxy/upstream/service.py` lines 907 to 968)
* `_candidates` (`service.py` lines 1050 to 1056)
* `availability()` (`service.py` lines 735 to 746)
* `request_policy` (`src/roxy/cache/policy.py` lines 228 to 254), which also picks the cache auth class
* `_redirect_url` (`service.py` lines 1629 to 1665), which re-checks every redirect hop on the credential egress

Replace all of them with the verdict from 5.1: `ALLOW_TOKEN` gives a `CredentialRule`, anything else gives None.
Keep the redirect re-check: a redirect hop must have its own verdict, and the credential goes only to a hop whose
verdict is `ALLOW_TOKEN`.

### 5.3 Lifting GET/HEAD only, carefully

The credential is hard-limited to GET and HEAD in at least six places. Lift it **only** for operations whose shipped
or overridden verdict is `ALLOW_TOKEN` (today 7 POSTs: `users POST /v1/usernames/users`, `users POST /v1/users`,
`presence POST /v1/presence/users`, `thumbnails POST /v1/batch`, `catalog POST /v1/catalog/items/details`,
`catalog POST /v1/topic/get-topics`, `groups POST /v1/groups/policies`). Never for an unknown operation. Places:

* `CREDENTIAL_METHODS` in `src/roxy/upstream/routing.py` line 50 (used at 139 and 218)
* `CREDENTIAL_METHODS` in `src/roxy/egress/clients.py` line 136, and the raise at lines 800 to 802
* `internal_fetch` in `service.py` lines 710 to 711 (keep GET only for Roxy's own probes)
* the SQL CHECK on `credential_allowlist.methods` and `models._methods(value, ("GET","HEAD"))`, which go away with
  the table (5.6)

Replace the method test with "the request's verdict is ALLOW_TOKEN and the verdict row lists this method". The CSRF
machinery already supports the credential identity (`src/roxy/upstream/csrf.py`, `egress_identity` gives
`credential`), so credential POSTs get Roblox's `x-csrf-token` dance for free. Redirects after a credential POST are
not followed (`clients._next_hop` lines 875 to 899 already turns them into a body-less GET; refuse instead).

### 5.4 Capacity: one account carries the traffic now

This is the biggest operational change. Facts:

* The credential bucket is `credential_bucket_per_min` (default 20, max 120) and `credential_bucket_burst` (3)
  (`src/roxy/config/settings/credential.py` lines 81 to 150). Their descriptions assume an empty allowlist.
* The credential goes only from the server IP (never the rotator), by design (C1, C2). So every ALLOW_TOKEN request
  is a direct request with the account.
* Roxy has served well over 50,000 requests in a stretch (see the `.todo` note about 579 rate limits). 20 per minute
  is 1,200 per hour.

So "send the token with everything" cannot mean "every ALLOW_TOKEN request waits for the credential". Recommended
(Q3):

1. ALLOW_TOKEN with Roblox sign-in `cookie-optional` or `none` (135 of the 161): use the credential when the bucket has
   a token and the credential is `active`; otherwise fall back to the normal anonymous pool (direct or rotator) at
   once. This is what the existing `identical_anonymous` flag does (`upstream/routing.py` lines 187 to 188); make it
   the default for these rows.
2. ALLOW_TOKEN with sign-in `cookie-required` (26 rows, flag `requires_login` in the seed, for example followers
   lists, `users/{userId}/badges`, `multiget-place-details`): no anonymous fallback (Roblox would answer 401). Wait in
   the bucket queue up to the deadline, then 429 "busy" with `Retry-After`, as `_credential_decision` does today.
3. Raise the bucket defaults only after measuring: `credential_bucket_per_min` 60 is a reasonable first step.
   Watch UP-429-CREDENTIAL (`insights/rules/upstream.py` lines 751 to 830); its advice must change from "remove the
   allowlist row" to "lower the bucket or strip the credential from the busiest endpoint".
4. A 429 on the credential sets the fleet-wide cooldown as today; during it, rule 1 rows go anonymous and rule 2 rows
   get 429.

### 5.5 Cache

* The cache key carries the auth class (`src/roxy/cache/keys.py` lines 108, 131, 279: suffix `:{auth_class}`). Keep
  it. Rows that fall back (5.4 rule 1) produce both CRED and ANON entries; that is fine.
* `cache_private` stays as a per-row flag, default **false** for ALLOW_TOKEN rows: the answers are Roxy's view of
  public data, identical for every caller. The research flagged no ALLOW_TOKEN row whose answer is private. Viewer-
  relative fields that remain (catalog `owned` flags on bundled items, `isFavoritedByUser` in game details) are
  constant for one account and harmless (`DOMAIN_ANALYSIS.md`, catalog and games sections).
* Short TTLs where the seed notes say so: presence, server lists, ownership checks, badge awarded dates.
* `cache/service.py` `_row_now_private` (lines 831 to 843) treats a missing allowlist row as private. Port that to
  "verdict is no longer ALLOW_TOKEN, so purge or bypass the CRED entries for it", so a row an admin blocks stops
  being served from cache at once.

### 5.6 The credential allowlist goes away

Replace `credential_allowlist` with the policy tables (section 9). Steps: new migration `control/0002` (`-- kind:
expand`) adds the policy tables; import any existing allowlist rows as `ALLOW_TOKEN` overrides with reason "imported
from credential allowlist"; a later `contract` migration drops the old table once both colors run the new code
(`src/roxy/storage/migrate.py` docstring lines 1 to 25 has the blue/green rules; `REQUIRED_SCHEMA` at line 56).
Remove or rewrite everything section 12 lists. The CRED-UNUSED insight (`insights/rules/credential.py` lines 190 to
300) becomes "ALLOW_TOKEN row never used in 30 days" with the action "strip the credential (ALLOW_ANON)".

### 5.7 What does not change

* `CredentialManager.authorize` (`src/roxy/egress/credential.py` lines 1175 to 1199) stays the only place the cookie
  is attached, with every check it does today. The AST test that only `credential.py` reads the secret stays.
* The credential never goes through the rotator. `make_credential_client` (`egress/clients.py` lines 293 to 318)
  stays proxy-free.
* `Set-Cookie` is stripped from every upstream answer (`DROPPED_RESPONSE_HEADERS`, `clients.py` lines 131 to 133) and
  a rotated cookie is caught by `observe_set_cookie` (`credential.py` lines 1231 to 1284). This is what stops the
  session refresh endpoints from handing callers a fresh cookie. Those endpoints are also BLOCK. Keep both layers.
* Caller headers are reduced to `accept`, `content-type`, `content-length` (`scrub.py` line 39); answers relay only
  `Retry-After` and `x-ratelimit-*` (`scrub.py` lines 50 to 55). `x-csrf-token` never reaches callers.
* The leak guard (`egress/guard.py`) still inspects every direct and rotator request for the credential's value.

## 6. Caller sign-in attempts: refuse and log

### 6.1 What to refuse

`detect_auth_attempt` (`src/roxy/abuse/checks/auth_smuggling.py` lines 62 to 94) catches `X-Roblox-Token`, a
`.ROBLOSECURITY` cookie, and the warning prefix or cookie name anywhere in headers, query or body. It does **not**
catch `Authorization` or `X-Api-Key`, which `scrub.py` silently drops. Extend it, in this order:

1. Any `X-Roblox-Token` header (as today).
2. Any `Authorization` header (Bearer, Basic, anything), and `X-Api-Key`, `X-Api-Token`, `Api-Key`: an Open Cloud
   key or OAuth token. Reason `api_key` or `authorization`.
3. A `Cookie` header containing `.ROBLOSECURITY` (as today) or `.RBXID` (Roblox's other sign-in cookie). Any other
   cookie: drop silently as today (browsers add their own).
4. `Proxy-Authorization`: nginx normally strips it as a hop-by-hop header; if it ever arrives, treat it like
   `Authorization`.
5. The markers in header values, query, and body, raw and percent-decoded (as today).
6. A `.ROBLOSECURITY`-shaped value: the `_|WARNING:-DO-NOT-SHARE-THIS.` prefix in any spelling (as today).

Refusal: 400 as today, with a clearer body (setting `auth_attempt_message`): "Roxy refused this request because it
carried a Roblox login cookie or API key. Never send yours: Roxy uses its own account. If you sent a real
.ROBLOSECURITY cookie, sign out of all sessions on roblox.com now to invalidate it. Roxy did not store it."

### 6.2 What to log (new "Caller sign-in attempts" record)

Today a hit becomes a `probe` event (`pipeline._probe` lines 1173 to 1189, Security > Probes), feeds SPAM-AUTH
(`pipeline.py` lines 1106 to 1119) and the tarpit category `auth_attempt`, and loses the header name (bug B19,
`probe_log_reason` lines 388 to 405). Add a dedicated event type `auth_attempt` with:

* time, caller IP hash and masked IP (existing helpers in `core/iphash.py` and `core/ipmask.py`), user agent,
  Roblox place id and job id headers if present, target host, method and path template (not the full query);
* where it was found: header name, cookie name, query parameter name, or "body";
* the kind: `roblosecurity` (with or without the warning prefix), `api_key`, `bearer`, `x-roblox-token`, `other`;
* **never the value.** A keyed fingerprint (HMAC, the same construction the credential uses) only, so repeated sends
  of the same secret can be grouped without storing it. The fingerprint key must differ from the credential's.
* `looks_real`: true when the value has the warning prefix and a plausible length, which means a real person just
  leaked their live cookie;
* the request's endpoint verdict, so the owner sees whether people try to use blocked features.

Show it as a card on the new page (section 8) and as a filter on Security > Probes. Group by fingerprint and by place
id: "place 123 sent a real cookie 40 times" is the actionable line (the owner can contact that developer). Keep rows
for `max_exploit_records` like other security events. SPAM-AUTH and the tarpit stay as they are.

## 7. Response safety (defense in depth)

The blocklist is the main control. These catch what it misses:

1. Keep stripping `Set-Cookie` and never relaying `x-csrf-token` (5.7).
2. Identity tripwire: after a credential request, if the answer contains the account's own email, phone number, or
   the literal strings `"isEmailVerified"`, `"phoneNumber"`, `"robux":`, `"recoveryCodes"`, `"twoStepVerification`,
   do not relay or cache it; answer 502 and raise a "probably private info" flag for that operation. This is the
   cheap first half of the ROADMAP item 1 flag. Do not trip on the account's user id or name: they appear in
   legitimate public data.
3. Learning from 401s: when Roblox answers 401 to an ALLOW_ANON or unknown GET repeatedly, record it on the review
   list as "needs sign-in"; do not promote it to ALLOW_TOKEN automatically.
4. Account check: the existing probe (`users.roblox.com/v1/users/authenticated`, internal only) keeps running. Its
   endpoint is BLOCK for callers; internal probes bypass the caller policy by design and must stay internal.

## 8. The admin page ("Endpoint policy")

### 8.1 Placement

A new page in the `defense` nav group: add a `PageSpec` to `_PAGES` in `src/roxy/admin/pages/registry.py` (lines 109
to 616), module `src/roxy/admin/pages/endpoint_policy.py` with `page = kit.Page("endpoint_policy")`, templates under
`templates/admin/pages/endpoint_policy/`, assets `static/css/pages/endpoint_policy.css` and
`static/js/pages/endpoint_policy.js` (picked up automatically, `kit.py` docstring). Changes go through a new admin API
area `src/roxy/admin/api/endpoint_policy.py` (`common.area_router("endpoint-policy")`, registered in
`admin/api/__init__.py` near line 97), never through page routes. Update `tests/integration/pages/test_pages_core.py`
line 94 (`len(PAGES) == 18` becomes 19), the ADMIN_GUIDE chapter test (`tests/unit/test_help_guide_chapters.py`) and
remove the Credential page's Allowlist card (registry lines 503 to 523, V1 section row 19 at 994 to 1001,
`admin/pages/credential.py` lines 280 to 371, `templates/admin/pages/credential/allowlist.html` and friends).

### 8.2 Cards

1. **Summary.** Counts per verdict (documented and unknown), last seed version and date, changes from defaults, the
   credential bucket fill (5.4), refusals in the last hour and day, a "use shipped defaults" button.
2. **Categories.** One row per category: name, plain description, default, current state (Defaults, Block all,
   Strip credential), counts, highest risk, refusals in 24 hours, and the toggle. Expanding a row lists its endpoints.
3. **Endpoints.** A table of every operation with filters (host, Roblox feature page, category, verdict, risk, method,
   Roblox sign-in kind, "changed from default", "seen in traffic") and a search box over path and summary. Columns:
   method, host, path, Roblox summary, verdict (a select), default verdict, risk, category, requests in 24 hours, and
   two links: Roblox feature doc and Roblox domain doc (`feature_doc`, `domain_doc` from the seed). The row drawer
   shows the rationale and notes from the seed, the Roblox sign-in kind, recent refusals and the audit history. Bulk
   select for "block selected" and "reset selected to default".
4. **Tester.** Paste a URL (Roxy form or roblox.com form) and pick a method; shows the normalized target, the
   matched row (or "unknown"), each precedence step from 3.4 and the final verdict, and the query guards that fired.
   Same idea as the existing `/credential-allowlist/test`.
5. **Unknown endpoints seen.** Operations not in the seed that callers asked for: first and last seen, count, verdict
   given (3.5), Roblox status codes seen. Actions: set a verdict, ignore.
6. **Caller sign-in attempts.** Section 6.2, newest first, grouped by fingerprint and place id, with `looks_real`
   highlighted.
7. **Drift.** The result of the last seed refresh (section 9.3): new, removed, and sign-in-changed operations waiting
   for review.

Every card needs the page's usual help texts (`about`, `purpose`, `how_to_read`), US spelling and no em or en dash
characters (`scripts/check_style.py`, `core/style_guard.py`).

### 8.3 Who may do what (match existing precedents)

| Action | Guard |
|---|---|
| Tighten (ALLOW to BLOCK, ALLOW_TOKEN to ALLOW_ANON, category "Block all" or "Strip credential") | Session + CSRF, audited |
| Loosen (BLOCK to anything, ALLOW_ANON to ALLOW_TOKEN, category back to Defaults) | Fresh second factor (`AdminFreshMfa`) + CSRF + a written reason, audited |
| Loosen a risk 4 row | As above, plus typing the endpoint path to confirm |
| Reset everything to shipped defaults | Session + CSRF (it can only tighten what admins loosened) |

This mirrors `credential_allowlist` today (`CHANGES.md` lines 1451 to 1453): adding a row needs a fresh second factor,
removing one does not. Every change goes through `RulesService` (one transaction: validate, write, audit row,
`config_version` bump; workers reload within about a second).

### 8.4 Insights and auto-apply

Recommendations may propose tightening (for example "block `X`: Roblox answered 401 to it 200 times today") but
`insights/autoapply.py` must never auto-apply a loosening; add the new action kinds to `NEVER_KINDS` (line 33 and 99)
when they loosen.

## 9. Data model, seed and keeping it current

### 9.1 Tables (control.db, migration 0002, expand)

* `endpoint_policy_override`: `endpoint_id` (the seed id, or `unknown:<host>:<METHOD>:<template>` for promoted
  unknowns) primary key, `verdict` CHECK in the three values, `cache_private` 0 or 1, `reason`, `created_*`,
  `updated_*`, `enabled`.
* `endpoint_policy_category`: `category` primary key, `state` CHECK in (`defaults`, `block_all`, `strip_credential`),
  `reason`, `updated_*`.
* `endpoint_policy_unknown` (hot.db or metrics.db, bounded like other caches): `host`, `method`, `template`,
  `first_seen`, `last_seen`, `count`, `last_status`, `verdict_given`.
* Auth attempts: events table rows of a new type (6.2), no new table needed.

### 9.2 The seed

Ship `endpoint_policy_seed.json` inside the package (copy or move it to `src/roxy/data/`, and keep this folder's copy
as the reviewed source, with a test that they are identical). Load it at start, validate it (every verdict and
category known, no two rows with the same id, no exact tie between different verdicts after template compilation,
risk between 1 and 4, both doc links present where Roblox published one), and fail start-up if it is invalid. Admin overrides
live in the database, so a new seed in a release never undoes an admin's choice; a release that changes a row's
default shows it on the Drift card.

### 9.3 Refreshing from Roblox

1. Download the newest `openapi.json` from Roblox/creator-docs into its own empty folder (it is untrusted data).
2. `python3 -I scripts/endpoint_policy_inventory.py <that file> --seed docs/endpoint_policy/endpoint_policy_seed.json`
3. For each new operation: read its summary, description and response schema, decide a verdict with the rubric in
   section 10, add a row (all fields, including both doc links). For each removed one: delete the row. For each
   sign-in change: re-check the verdict.
4. `python3 -I scripts/gen_endpoint_catalog.py`, run `scripts/check_style.py`, commit both files.

Suggested cadence: monthly, plus whenever Roblox announces API changes. A health check can warn when the seed is
older than 60 days.

## 10. The rubric used for every verdict (apply it to new rows)

* ALLOW_TOKEN when the endpoint returns public data, or data about other users and public things, and the credential
  adds nothing about the account. Batch read POSTs qualify.
* ALLOW_ANON when it is useful without a sign-in but the credential would make the answer describe the account, or
  the host is a sign-in host.
* BLOCK when it (a) acts on the account (any write, even favorite, vote, follow), (b) reads the account's private or
  identifying data (anything "my", "authenticated", or a `{userId}` path that only answers for the signed-in user),
  (c) touches login, session, password, 2-step, ticket, token or OAuth flows, (d) uses permissions the account may
  hold over groups, assets, universes or places (a 200 versus 403 answer alone leaks membership), (e) could get the
  account flagged (spam, reports, uploads, click tracking), or (f) is Open Cloud key-only.
* Distrust Roblox's sign-in labels: `none` and `cookie-optional` do not mean safe. 135 BLOCK rows are labeled that
  way, including `auth POST /v3/logout` (labeled `none`) and `matchmaking-api POST /v1/game-instances/launch-update`
  (labeled `none`, restarts live servers).

The most important individual findings, all reflected in the seed:

* `auth /v1|v2/session/refresh` and `logoutfromallsessionsandreauthenticate` rotate the session and return a new
  `.ROBLOSECURITY` in `Set-Cookie`: one request takes over the account if Set-Cookie is ever relayed.
* `twostepverification POST /v1/users/{userId}/recovery-codes/regenerate` returns working recovery codes in the body.
* `accountsettings PATCH|POST /v1/email` and `accountinformation POST /v1/phone` enable password-reset takeover.
* `groups GET /v1/groups/{groupId}/membership` looks like a group read, returns the account's own membership.
* `friends GET /v1/users/{userId}/friends/online` and `followings` GETs take a userId but answer only for the account.
* `games GET /v1/games/{placeId}/private-servers` lists private servers with access codes.
* `clientsettings GET /v2/user-channel` returns the account's release channel and a channel token.
* `locale POST /v1/locales/set-user-supported-locale` would change the language every cached answer is localized in.
* `assetdelivery` with a credential serves private assets the account can access (see Q5).
* `apis /service-efficiency-api/v1/payments/...` submits real-money payments.
* `gamejoin.roblox.com` (allowed today, undocumented) issues join tickets for the account.

## 11. Questions for the owner (with recommended defaults)

* **Q1. Status code for blocked endpoints.** The owner said "a 500 or something". Recommended: **403** with
  `Roxy-Blocked: policy` and a clear body. Reasons: D4 says callers see real statuses; a 500 makes Roblox games and
  HTTP libraries retry, which turns one mistake into a loop; and 500s would count as server errors on the Health and
  Overview pages. Make the status a setting (`endpoint_policy_block_status`, allowed 403, 404, 500) if the owner
  still wants 500.
* **Q2. Unknown operations.** Recommended: section 3.5 (unknown writes blocked, unknown reads forwarded without the
  credential unless they match a danger pattern, all listed for review). Alternative: unknown reads with the
  credential, which follows "token with everything" literally but trusts undocumented endpoints.
* **Q3. Credential capacity.** Recommended: section 5.4 (fall back to anonymous when the bucket is empty for rows that
  do not require sign-in; raise the bucket to 60 per minute after a week of measurements). Without a fallback, Roxy
  is limited to 20 credential requests per minute.
* **Q4. Keep the ALLOW_ANON tier?** Recommended: yes (52 rows). Removing it means each of those becomes either
  ALLOW_TOKEN (leaks account-relative data into a shared cache) or BLOCK (loses useful endpoints such as
  `catalog POST /v1/catalog/items/details/complete` and Creator Store search).
* **Q5. Asset delivery.** Seeded ALLOW_ANON because a credential lets callers download private assets the account can
  access. Roblox announced in 2025 that asset delivery would need a sign-in for many requests; if anonymous requests
  now fail, the choice is ALLOW_TOKEN, which is safe only while the account owns, edits and is shared on nothing
  private. Must be tested live before shipping (with and without the credential, on a public model, audio and image).
* **Q6. Hosts.** Six allowed hosts are undocumented. Recommended: keep `search` and `translations` (ALLOW_ANON),
  block `gamejoin`, `billing`, `engagementpayouts` and `voice` at host level (or remove them from
  `allowed_roblox_hosts`). Nine documented hosts are not allowed today (`adconfiguration`, `ads`,
  `economycreatorstats`, `gameinternationalization`, `localizationtables`, `publish`, `thumbnailsresizer`,
  `translationroles`, `twostepverification`). Recommended: add only `gameinternationalization` and
  `thumbnailsresizer`, which have useful public reads; leave the rest out.
* **Q7. Open Cloud with a Roxy key, later?** Not part of this work. If ever wanted, read-only data store and ordered
  data store reads for named universes are the only reasonable candidates (`DOMAIN_ANALYSIS.md`, Open Cloud section).
* **Q8. The account.** The policy assumes the account owns nothing, is in no groups, has no friends, and has no
  Premium. Confirm, and keep it that way: several ALLOW_TOKEN rows (group roles with `includePrivate`, friend
  statuses, catalog ownership flags) are safe only because of it. A health check could verify it (group count 0,
  friend count 0, no owned universes) through the internal probe.

## 12. Tests

Rewrite (they assert the old D1 model):

* `tests/security/test_confinement_routing.py` (`test_caller_traffic_never_carries_the_credential` at line 195 and
  tests at 287, 307, 363) becomes "caller traffic carries the credential only for ALLOW_TOKEN verdicts".
* `tests/unit/upstream/test_upstream_routing.py` line 233 (`test_routing_never_selects_credential_for_non_allowlisted`,
  a property test): same change, keep it a property test.
* Everything under the `credential_allowlist` list in the code map: `tests/unit/rules/test_store.py`,
  `tests/unit/rules/test_service.py`, `tests/unit/upstream/test_upstream_service.py`, `upstream_fakes.py`,
  `tests/unit/cache/test_cache_policy.py`, `test_cache_service.py`, `test_cache_flights.py`,
  `tests/security/test_confinement_upstream.py`, `_cache.py`, `_records.py`, `_markers.py`,
  `test_rr_cred_private_flip.py`, `test_rr_cred_redirect_hops.py`, `test_rr_cred_cache_key_text.py`,
  `tests/integration/admin_api/test_api_credential.py`, `test_r3_apisec_bounds.py`,
  `tests/integration/pages/test_page_credential.py`, `tests/e2e/test_page_credential.py`,
  `tests/integration/test_pipeline_e2e.py`, `test_cache_workers.py`, `test_upstream_egress_contract.py`,
  `test_review_c7_failure_modes.py`, `tests/multiprocess/test_review_failure_modes_mp.py`,
  `tests/unit/storage/test_storage_migrate.py` (lines 83, 623 to 632), insight fixtures
  `tests/fixtures/insights/cred_unused__*.yaml`, `up_429_credential__*.yaml`,
  `up_4xx_spike__credential_endpoint_401.yaml`.

Add:

* Seed validation (9.2), and that `docs/endpoint_policy/endpoint_policy_seed.json` equals the packaged copy.
* A golden table test: at least these must be BLOCK: every row in categories `login-session-security`,
  `account-identity`, `economy-spend`; `auth POST /v1/logout`, `/v2/logout`, `/v3/logout`; `auth POST
  /v1/session/refresh`; `users GET /v1/users/authenticated`; `groups GET /v1/groups/{groupId}/membership`;
  `games GET /v1/games/{placeId}/private-servers`; `clientsettings GET /v2/user-channel`; any `gamejoin` request.
  And these must be ALLOW_TOKEN: `users POST /v1/usernames/users`, `catalog GET /v2/search/items/details`,
  `thumbnails GET /v1/users/avatar-headshot`, `presence POST /v1/presence/users`, `games GET /v1/games`.
* Matching bypass tests (section 4): mixed case, `//`, trailing slash, `%2F`, `%2e`, `:verb` collisions, `HEAD`,
  every `{param}` filled with `..`, `%00`, a 2,000 character segment, and a request for `/v1/metadata#x`.
* Precedence tests for every step of 3.4, and fail-closed tests (seed missing, regex timeout, unreadable table).
* Auth attempt tests for every kind in 6.1, that the value is never stored or logged (grep the database and log
  output for the test value), and that `looks_real` is right.
* A multi-worker test that an admin change applies fleet-wide within the reload interval.
* Page and API tests like the other areas, including the fresh-second-factor rule for loosening.

Run `scripts/check_style.py` and `tests/unit/test_docstrings.py` (every new module under `src/roxy` needs the four
docstring sections "What this is", "Why it exists", "How it works", "What to read next").

## 13. Text and documentation to change

### 13.1 Public pages (the owner asked for this explicitly)

Remove every statement that Roxy does not support authenticated requests. Keep, and strengthen, "never send your own
cookie or API key". Places:

* `src/roxy/templates/public/home.html`: meta descriptions and JSON-LD at lines 19, 34, 42, 53 ("no login or
  ROBLOSECURITY token required" can stay: callers still need none); keywords line 23 (fine); tagline line 67 (fine);
  the General Tips note at lines 175 to 180 ("Roxy is for public, unauthenticated Roblox web API calls only; it does
  not support requests that need you to be logged in"): rewrite; the POST/PATCH/PUT/DELETE note at lines 205 to 212
  ("Roxy does not support authenticated requests, so these methods only work against ... public, unauthenticated
  endpoints"): rewrite; the section heading "No Login Required & White Hats" at lines 222 to 226: keep the heading,
  its text comes from the setting below.
* Setting `site_white_hats_text` (`src/roxy/config/settings/public_site.py`, default at lines 65 to 73, spec at 353 to
  372): new default. The production database holds a saved value, so also change the live value (audited, with a
  reason) or the old text stays up.
* `docs/USER_GUIDE.md` (served at `/docs`): line 20, line 611 (the 400 row: "you sent your own login or API key"),
  line 637, lines 644 to 646 ("No authenticated requests on your behalf" becomes the opposite: Roxy signs requests
  with its own account), lines 701 to 703 (FAQ). Add a "Blocked endpoints" section with the anchor the block message
  links to, a short list of what is blocked and why, and the status code from Q1.

Suggested replacement text for the tips note: "Roxy sends your request to Roblox signed in with Roxy's own Roblox
account, so endpoints that only answer signed-in users (like followers lists and some catalog details) work. It
never acts on an account: endpoints that change, buy, message, or read private account data are blocked and answer
403. Never send your own .ROBLOSECURITY cookie or Open Cloud API key; Roxy refuses any request that carries one."

### 13.2 Caller-facing messages

"Requests requiring authentication are not allowed with this proxy." exists three times
(`src/roxy/abuse/messages.py` line 50, `src/roxy/proxy/respond.py` line 91, `src/roxy/upstream/messages.py` line 44).
Replace it with the 6.1 text in one place and import it in the other two. `auth_smuggling.py` line 8 says "Roxy is an
anonymous proxy": update the docstring.

### 13.3 Records

* `DECISIONS_REVIEW.md`: new row "D1 revised (2026-10-16)" with the owner's words from section 1; leave the old row.
* `CHANGES.md`: an entry for the feature.
* `ROADMAP.md` item 1: mark superseded by this feature (the "probably private info" flag survives as 7.2).
* `docs/SECURITY.md` (lines 142, 153, 166, 174, 220, 350), `docs/ADMIN_GUIDE.md` (lines 154, 437 to 438, 1188 to 1208,
  1313, 1802, 2014, 2027, 2282, 2438, 3162, 3355 to 3363, 4886 to 4887, plus a new chapter for the page),
  `docs/ARCHITECTURE.md`, `docs/glossary.yml` line 91, `docs/SETTINGS.md` (regenerate with
  `scripts/gen_settings_docs.py`), and the credential settings' descriptions ("empty by default, so public traffic
  never carries it").

## 14. Suggested order of work

1. Owner answers section 11 (or says "use the defaults").
2. Matcher, seed loader and validation, with the bypass and golden tests (no behavior change yet).
3. The check at position 145, behind a setting `endpoint_policy_enabled` (default off), plus the auth attempt
   extension and log. Ship and watch the refusal counts in "shadow" mode first: log what would be blocked without
   blocking, for a day.
4. Turn blocking on. Credential stays off for callers.
5. Credential for ALLOW_TOKEN rows with the fallback (5.4) and the bucket at 20; lift GET/HEAD for listed POSTs.
   Watch UP-429-CREDENTIAL and the credential status for a week.
6. Admin page and API, drift card, unknown endpoints list.
7. Remove the allowlist (contract migration), update texts and docs (section 13).

Definition of done: every test in section 12 passes; `check_style.py` passes; the Tester gives the expected verdict
for every row in the golden table against the running server; a request with a real-looking cookie produces one
auth attempt row and no stored value; the homepage no longer says authenticated requests are unsupported.

## 15. Limits of this research

* Verdicts come from Roblox's reference (summaries, descriptions, response schemas), not from live calls. Rows the
  reviewers were unsure about say so in their `notes` (search the seed for "doubt", "assume", "may", "unclear").
  The main ones: asset delivery (Q5), `premiumfeatures validate-membership`, `trades GET /v2/users/{userId}/tradableItems`,
  group payout reads, friends `multiget-are-friends` and `friends/search`, and whether group and user game lists
  include private games with a credential.
* Undocumented endpoints are covered only by host defaults and section 3.5.
* Roblox changes these APIs often. The seed is a snapshot of 2026-10-16; section 9.3 keeps it current.
