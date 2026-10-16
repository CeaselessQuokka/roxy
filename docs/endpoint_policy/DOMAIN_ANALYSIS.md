# Domain analysis

What each Roblox web API domain does, the default policy for it, and the endpoints that look harmless but are not.
Written while classifying every operation in `endpoint_policy_seed.json` (2026-10-16). Read it together with
`CATALOG.md` (every row) and `BRIEF.md` (how to build the feature). When this file and the seed disagree, the seed
wins; fix this file.

Sections: auth and account hosts, social hosts, economy and avatar hosts, creator and games hosts, apis.roblox.com
(cookie routes), apis.roblox.com (Open Cloud key-only routes).


## Auth and account hosts: auth, twostepverification, accountinformation, accountsettings, contacts

159 endpoints. 139 BLOCK, 18 ALLOW_ANON, 2 ALLOW_TOKEN.

This is the most dangerous group of hosts. Most endpoints here act on "whoever owns the cookie", and Roxy attaches its cookie by default. The safest rule is: block these hosts by default, then allow the short list below.

### auth.roblox.com

What it does: login, logout, signup, sessions, tickets, passwords, passkeys, SSO/OAuth, account PIN, username changes, Xbox and social login links, plus a few validators and metadata endpoints.

Default policy: BLOCK the whole host, then allow a small set of anonymous utilities.

Sneaky and critical endpoints:
* `POST /v1/logout`, `/v2/logout`, `/v3/logout`: marked auth "none" or "cookie-optional", but with Roxy's cookie attached any stranger can log Roxy out. v3 is labeled "none" in the spec, which is exactly the trap.
* `POST /v1|v2/session/refresh` and `/v1|v2/logoutfromallsessionsandreauthenticate`: rotate the session. The stored cookie dies, and the brand new `.ROBLOSECURITY` comes back in `Set-Cookie` to the caller. That is a full account takeover through one request. Roxy should also strip `Set-Cookie` from every upstream response as a second layer.
* `GET /v1/client-assertion`: a GET that mints material for an auth ticket. Looks like a read, is a credential step.
* `POST /v1/account/upgrade` and passkey `StartRegistration` / `FinishRegistration`: let a caller attach their own sign-in method to Roxy's account.
* `/v1/account/pin` (create, change, delete, lock, unlock): a stranger could lock the owner out or brute force the PIN.
* `POST /v1/external/unlink`, `/v1/social/{provider}/disconnect`, `/v1/xbox/disconnect`: account writes, the first one labeled auth "none".
* `POST /v1|v2/login`, external/SSO/SAML/OAuth callbacks, identity-verification login, `/v3/users/{userId}/two-step-verification/login`: login flows. Proxying them makes Roxy a credential-stuffing relay and may overwrite or disturb Roxy's session.
* `POST /v1|v2/user/passwords/change`, `/v2/passwords/reset*`, `/v1|v2/revert/*`, `/v1|v2/usernames/recover`: password and recovery flows; reset/send and usernames/recover are also email and SMS spam vectors from Roxy's IP.
* `POST /v1|v2/username`: changes the username and spends Robux.
* `GET /v1|v2/passwords/validate`: takes the password in the query string, so it would end up in Roxy's logs and cache keys.
* `GET /v1/validators/email`: email-in-use enumeration.
* `GET /v1/social/connected-providers`, `/v1/xbox/connection`: reveal linked external accounts (gamertag etc.) of Roxy's account.

Allowed, and why it is safe (all ALLOW_ANON, cookie stripped):
* `GET /v1|v2/usernames?username=`: says whether a username exists. Public, and useful. users.roblox.com is the better lookup but this is harmless.
* `GET|POST /v1|v2/usernames/validate`: username availability check. Must be anonymous: with the cookie and `Context=UsernameChange` the check is relative to Roxy's own username, which can confirm Roxy's identity.
* `GET|POST /v1/validators/username` and `/v1/validators/recommendedUsernameFromDisplayName`: username suggestion utilities.
* `GET /v1|v2/auth/metadata`, `/v1/metadata`, `/v2/metadata`, `/v1|v2/recovery/metadata`: static feature flags and config. Low value; allowing them is fine, blocking them is also fine. The cookie is stripped because some flags can be account-relative and there is no reason to send Roxy's session to the login host.

Note on ALLOW_ANON here: the reason is less "the cookie reveals data" and more "keep Roxy's session away from auth.roblox.com entirely". If the admin prefers, the whole host can simply be BLOCK.

### twostepverification.roblox.com

What it does: 2SV challenges (send codes, verify codes), 2SV configuration (enable/disable each method), recovery codes, metadata.

Default policy: BLOCK everything.

Sneaky and critical endpoints:
* `GET /v1/metadata`: looks like harmless config, but with a cookie or a `userId` it adds `maskedUserEmail`, `isUserU13` and whether 2SV is on.
* `POST /v1/users/{userId}/recovery-codes/regenerate`: returns fresh working recovery codes in the response body. A caller would get permanent 2SV bypass codes for Roxy's account.
* `configuration/*/enable` and `enable-verify`: a caller could install their own authenticator or security key on Roxy's account and lock the owner out. `disable` weakens the account.
* `challenges/*/send-code`: send email or SMS codes to any userId, a harassment and spam vector that runs from Roxy's IP.
* `challenges/*/verify`: finishing challenges through Roxy could complete logins or unlock sensitive actions, and allows code guessing.

Nothing allowed.

### accountinformation.roblox.com

What it does: the account's own profile fields (birthdate, gender, description, phone, social links, email verification) plus two by-userId public reads.

Default policy: BLOCK, with two ALLOW_TOKEN and one ALLOW_ANON.

Sneaky and critical endpoints:
* `GET /v1/description`, `/v1/promotion-channels`, `/v1/birthdate`, `/v1/gender`, `/v1/phone`: "my" endpoints with no userId. They return Roxy's own data and reveal which account Roxy uses. Several are deprecated and replaced by users.roblox.com equivalents, which should be blocked there too (they are).
* `POST /v1/phone` + `/v1/phone/verify`: attach a caller's phone to Roxy's account, usable for recovery and takeover.
* `POST /v1/description`, `/v1/promotion-channels`: profile writes, a spam or phishing link vector that would get the account banned.

Allowed, and why it is safe:
* `GET /v1/users/{userId}/promotion-channels` (ALLOW_TOKEN): public social links of any user. Responses can vary by viewer because users can limit link visibility to friends or followers; Roxy's throwaway account is a stranger so it sees the public set. Asking for Roxy's own id only shows its already-public links.
* `GET /v1/users/{userId}/roblox-badges` (ALLOW_TOKEN): platform badges on a public profile. Not viewer-relative.
* `GET /v1/metadata` (ALLOW_ANON): page feature flags, low value.

### accountsettings.roblox.com

What it does: the account's email, country, trade settings, theme, and settings page metadata.

Default policy: BLOCK, with one ALLOW_ANON.

Sneaky and critical endpoints:
* `PATCH|POST /v1/email`: change Roxy's email, then reset the password. Critical takeover vector.
* `GET /v1/email`, `/v1/emails`: return the account email.
* `POST /v1/trade-privacy`: opening trades invites scam and spam trade requests at the account.
* `GET /v1/themes/{consumerType}/{consumerId}`: looks like it takes any id, but only works for the authenticated account, so it reads Roxy's settings.
* `GET /v1/account/settings/metadata`: mostly flags but computed per account (parental spend limits), cookie-required.

Allowed: `GET /v1/themes/types` (ALLOW_ANON), a constant list of theme names. Very low value.

### contacts.roblox.com

What it does: private nicknames ("tags") the account sets on other users.

Default policy: BLOCK all three.

Sneaky: `POST /v1/user/get-tags` is a POST batch read, which the rubric usually allows, but it reads the account's own private notes about other users, so it is account-private data.

### Cross-cutting advice for Roxy

* Strip `Set-Cookie` from all upstream responses, regardless of the blocklist. Session refresh and reauthenticate endpoints return a new valid cookie there.
* Never cache any response from these hosts that was made with the cookie.
* Treat any endpoint without a `userId` that says "the user's" or "authenticated user" as Roxy's own data.


## Social hosts: groups, friends, followings, users, presence, privatemessages, notifications

167 endpoints. BLOCK 121, ALLOW_TOKEN 38, ALLOW_ANON 8.

One global caveat for all of these: Roxy caches responses and shares them. Every allowed endpoint below must be cached by the full URL including the query string (and the request body for POST batch reads). Several responses vary by viewer; because only one viewer (Roxy's account) is ever used, that is safe, but never mix in results from another cookie.

### groups.roblox.com (95 endpoints)

**What it does:** group details, members, roles, search, plus everything a group owner or admin does (payouts, bans, join requests, roles, settings, relationships, invitations, social links).

**Default policy:** reads of public group data get ALLOW_TOKEN. Every write gets BLOCK. Reads that only answer for members or admins also get BLOCK, because they could only ever return data through the account's own group permissions (goal d).

**Allowed (ALLOW_TOKEN):** GET /v1/groups/{groupId}, /v2/groups (batch), /v1/groups/{groupId}/users, /roles, /roles/{id}/users, /roles/guest/permissions, /v1/roles (batch), /v1/users/{userId}/groups/roles (v1 and v2), /primary/role, /friends/groups/roles, search and lookup, name-history, relationships (public allies/enemies), featured event, feature freeze/status flags, configuration (emblem ids), configuration/metadata, social-links (public on the site, but the API wants a login), and POST /v1/groups/policies (batch canViewGroup lookup).

**ALLOW_ANON:** GET /v1/groups/metadata (includes currentGroupCount for the viewer), and the three cookie-optional payout reads: /payouts/latest, /payouts/suggested, /payouts/universes. They use "Public" response models, so the public view is served, but the cookie is stripped so the account's permissions can never widen what comes back. BLOCK is a fair alternative for the payout reads if the owner prefers.

**Sneaky endpoints:**
- GET /v1/groups/{groupId}/membership: looks like a group read, but returns the viewer's own membership, role and user id. BLOCK (account-identity).
- GET /v1/groups/{groupId}/users/{userId}/permissions: cookie-optional, but only answers for the group owner or for the account's own id. BLOCK.
- GET /v1/groups/{groupId}/roles and GET /v1/roles take `includePrivate`. Private roles are only shown to members. Allowed because Roxy's account is not in any group and cannot join one through Roxy (join, invite-accept and claim-ownership are all blocked). If the account ever joins a group by hand, these and the shout in GET /v1/groups/{groupId} become a membership leak. Optional hardening: strip `includePrivate`.
- POST /v1/featured-content/event is listed as cookie-optional but is a write. BLOCK.
- Money: POST /v1/groups/create and PATCH /name charge Robux; POST /payouts, /payouts/recurring and PATCH /v1/universes/{universeId}/payouts move Robux. All BLOCK risk 4.
- Admin-only reads: audit-log, bans, blocked-keywords, join-requests, settings, roles/permissions, relationship requests, payouts, payout-restriction, v2 invitations. All BLOCK.
- POST /v1/groups/{groupId}/users (join) is the key write to keep blocked: it is what keeps the group reads free of membership leaks.

**Caching caveats:** /v1/users/{userId}/groups/roles fills notification preference fields only for the viewer's own id. Group shouts and private roles vary by viewer membership. /v1/groups/policies varies by the account's region policy.

### friends.roblox.com (24 endpoints)

**What it does:** friend lists, follower/following lists and counts, friend requests, QR friend-add sessions, follow/unfollow.

**Default policy:** lists and counts for any user id are ALLOW_TOKEN. Anything under /my/ or /user/ (singular) is about the account and gets BLOCK. Follow, unfollow and QR session actions get BLOCK.

**Allowed (ALLOW_TOKEN):** /v1/users/{userId}/friends, /friends/count, /friends/find, /friends/search, /v1/users/{targetUserId}/followers, /followings and their counts. Followers and followings require login, so the cookie is what makes them work.

**ALLOW_ANON:** GET /v1/metadata (returns userName/displayName and per-account experiment flags), GET /v1/users/{userId}/friends/statuses (statuses include "request sent/received", which would describe the account's pending requests), POST /v1/user/{userId}/multiget-are-friends (summary says it checks the requesting user).

**Sneaky endpoints:**
- /v1/users/{userId}/friends/online and /friends/inactive take a userId but only answer for the authenticated user. BLOCK.
- POST /v1/user/following-exists is a batch read, but it answers "does the account follow these users", so it is purely about the viewer. BLOCK.
- /v1/my/friends/refresh-qr-session and /check-qr-session are the QR add-friend flow; someone could use them to get friended by the account. BLOCK risk 3.
- All request counts (/user/friend-requests/count, /my/new-friend-requests/count, trusted variants) and request lists. BLOCK.

**Caching caveats:** user items in friend/follower lists carry isOnline and presenceType, which depend on the viewer's relationship with each user. If userId is Roxy's own id, friend lists include friendFrequentScore fields (harmless while it has no friends).

### followings.roblox.com (5 endpoints)

**What it does:** which experiences (universes) a user follows.

**Default policy:** BLOCK everything. The GETs require login and only work for the account's own userId, so they would reveal what the account follows. POST and DELETE follow or unfollow an experience as the account.

### users.roblox.com (18 endpoints)

**What it does:** user lookups, username history, user search, and the account's own profile settings (birthdate, gender, description, display name).

**Default policy:** lookups of any user are ALLOW_TOKEN. Anything without a userId that reads or writes "the user" means the account itself and gets BLOCK.

**Allowed (ALLOW_TOKEN):** POST /v1/usernames/users and POST /v1/users (batch reads, no CSRF needed, very common in games), GET /v1/users/{userId}, /username-history, /v1/users/search.

**ALLOW_ANON:** GET /v1/display-names/validate (signup helper for new users; useful as a display name check but the cookie adds nothing).

**Sneaky endpoints:**
- GET /v1/birthdate, /v1/gender, /v1/description have no userId. They are always the account's own data. BLOCK.
- GET /v1/users/authenticated and its age-bracket, country-code and roles children reveal who the account is and where. BLOCK (account-identity / account-private-data).
- GET /v1/users/{userId}/display-names/validate requires login and only works when userId is the account (step one of a rename). BLOCK.

**Caching caveats:** user search may rank the viewer's friends first. Otherwise responses are the same for everyone.

### presence.roblox.com (1 endpoint)

**What it does:** POST /v1/presence/users, batch presence (online, in game, in Studio, place and universe ids) for a list of users.

**Default policy:** ALLOW_TOKEN. It is a batch read and one of the most common game calls.

**Caching caveats:** presence detail depends on each target's privacy settings relative to the viewer. Roxy's account has no friends, so it sees roughly the public view. Cache by request body only, and keep the TTL short since presence changes fast.

### privatemessages.roblox.com (9 endpoints)

**What it does:** the account's inbox: messages, unread count, archive and mark-read actions, and inbox announcements.

**Default policy:** BLOCK everything. Messages are private. Announcements and announcement metadata are low risk (probably the same for everyone), but have no use for game servers and sit in the inbox service, so they are blocked with risk 1.

### notifications.roblox.com (15 endpoints)

**What it does:** push notification device registration and the notification stream (recent entries, unread counts, game update notices).

**Default policy:** BLOCK everything.

**Sneaky endpoints:**
- The register-* POSTs would let a caller register their own device for the account's push notifications, which is a way to read the account's private notifications. BLOCK risk 3.
- deregister-all-devices changes account notification settings. BLOCK.
- GET /v2/stream-notifications/get-latest-game-updates looks like public game info but it is the account's own notification feed. BLOCK.
- GET /v2/push-notifications/chrome-manifest is a harmless static config read, but blocked since it is part of the push setup flow and has no caller use.


## Economy and avatar hosts: catalog, avatar, inventory, economy, trades, badges, thumbnails, assetdelivery and more

144 endpoints: 71 ALLOW_TOKEN, 13 ALLOW_ANON, 60 BLOCK.

### assetdelivery (10: all ALLOW_ANON)
What it does: hands out the actual files behind assets (models, meshes, audio, images, places), by id, version, or content hash. v2 returns JSON with locations and content representations; the batch routes are POST reads.

Default policy: allow, but without the cookie.

**Must verify before shipping (added during review):** Roblox announced in 2025 that asset delivery would require a sign-in (cookie or API key) for many requests. If anonymous downloads now fail with 401 or 403, ALLOW_ANON breaks every asset delivery call. In that case the choice is ALLOW_TOKEN, which is only safe while the account owns, edits and is shared on nothing private (see `BRIEF.md` section 11, question Q5). Test with and without the cookie on a public model, a public audio and a public image before choosing.

Sneaky: this is the biggest permissions leak in this group. With a cookie, Roblox serves any asset the logged-in account can access: private models and audio it owns, group assets, packages, assets shared to it through asset permissions, and copylocked places it can edit. Query params and headers like `permissionContext`, `accessContext`, `Roblox-Place-Id`, `serverplaceid` and `modulePlaceId` exist to widen access, which only matters if a cookie is attached. Roblox's reference lists all ten as cookie-optional (see the warning above about whether that still holds).

Doubt: if Roblox tightens anonymous downloads (401 for some asset types), the owner may want ALLOW_TOKEN. Only do that after confirming the account owns, edits and is shared on nothing private, and never let it join groups.

Caching: responses point at signed CDN URLs that expire, so cache by asset id plus version for minutes, not days.

### avatar (30: 12 ALLOW_TOKEN, 18 BLOCK)
What it does: avatar rules, a user's worn avatar and outfits, and avatar editing.

Default policy: allow `users/{userId}` reads, outfit details by id, avatar rules, metadata and `game-start-info`. Block everything that writes (set body colors, scales, avatar type, wearing assets, PATCH avatar, outfit create/update/delete, redraw thumbnail).

Sneaky: `GET /v1/avatar`, `/v2/avatar/avatar` and `/v4/avatar` look like harmless reads but always describe the logged-in account, so they are blocked as account identity. `redraw-thumbnail` is a write that is easy to spam. `checkAssetAvailability` is evaluated for the viewer (trivial).

Caching: per-userId avatar data changes when the user changes clothes; short TTL. Rules and metadata are global and cache well.

### badges (11: 7 ALLOW_TOKEN, 4 BLOCK)
What it does: badge info, a game's badge list, and which users earned which badges.

Default policy: allow reads, including the cookie-required `users/{userId}/badges` routes (they return third-party data and are heavily used for "has badge" checks). Block badge edits, icon uploads, badge creation (it charges Robux), and `DELETE /v1/user/badges/{badgeId}` (removes a badge from the account).

Caching: awarded-date answers flip when a player earns a badge, so keep TTL short; badge info caches well.

### catalog (25: 17 ALLOW_TOKEN, 2 ALLOW_ANON, 6 BLOCK)
What it does: marketplace search, item and bundle details, favorites, categories.

Default policy: allow with the cookie. Anonymous marketplace search is tightly rate limited, which is a main reason Roxy uses a cookie at all.

Sneaky:
* Item and bundle detail shapes (search, items/details, bundles details, assets/{id}/bundles) carry per-item `owned` flags computed for the viewer. With the cookie they say which of those items Roxy's account owns. Judged trivial for a throwaway account and kept ALLOW_TOKEN; the owner can flip these to ALLOW_ANON for zero leak at the cost of rate limits.
* `POST /v1/catalog/items/details/complete` is explicitly "complete with user ownership and economy information" (owned, isPurchasable, expiration). ALLOW_ANON.
* `bundles/{bundleId}/recommendations` may personalize for a logged-in viewer. ALLOW_ANON.
* `GET /v1/favorites/users/{userId}/{assets|bundles}/{id}/favorite` has a userId in the path but only answers for the logged-in user, so it reveals the account's favorites. Blocked, along with the POST/DELETE favorite writes.

Caching: viewer-relative fields are the same for every caller because Roxy has one account, so sharing the cache is fine. Prices and stock on limiteds move quickly; keep TTL short for details.

### economy (7: all BLOCK)
What it does: Robux balance, transactions, totals, group revenue, sales reports.

Default policy: block everything. `users/{userId}/transactions`, `transaction-totals` and `transaction-types` look like per-user reads but only work for the logged-in user. Group routes only work for members with finance rights, so they would expose any group the account can manage.

### economycreatorstats (1: BLOCK)
Universe revenue stats, only for people with analytics rights on that universe. Block.

### inventory (15: 11 ALLOW_TOKEN, 1 ALLOW_ANON, 3 BLOCK)
What it does: what a user owns, ownership checks, asset owners lists, profile collections.

Default policy: allow per-userId reads (`items/.../is-owned`, `items/{type}/{id}`, `v2/users/{userId}/inventory`, collectibles, owners lists). These are among the most used calls from game servers.

Sneaky:
* `places/inventory` has viewer-relative tabs (Created / MyGames / OtherGames) that could list private or unlisted places the account owns or edits. ALLOW_ANON.
* `DELETE /v2/inventory/asset/{assetId}` permanently gives up an item. Blocked, risk 4.
* Collections POST/DELETE edit the account's profile showcase. Blocked.
* `can-view-inventory` is computed for the viewer, but the account has no friends, so the answer equals the public answer.

Caching: ownership flips right after a purchase; game servers often poll right after a prompt, so keep ownership TTL short (seconds).

### itemconfiguration (6: all BLOCK)
What it does: the creator dashboard's list of the account's own creations and publishing preferences. Every route is scoped to the account or to a group where it has create rights. Block all, including the POST `get-asset-details`, which is a read but only of the account's creations.

### premiumfeatures (2: 1 ALLOW_TOKEN, 1 BLOCK)
`validate-membership` reports whether a given user has Premium and is allowed (doubt: if Roblox restricts it to the logged-in user it should be blocked). `premium-upsell-precheck` is a purchase-flow check about the account; blocked.

### thumbnails (19: all ALLOW_TOKEN) and thumbnailsresizer (2: ALLOW_TOKEN)
What it does: image URLs for avatars, assets, games, groups, badges, passes, plus 3D render data and the CDN resizer.

Default policy: allow. The 3D routes need login but return public render data.

Small note: with the cookie, an asset thumbnail for a private or unreviewed asset the account owns could render instead of a placeholder. Negligible.

Caching: results can be `Pending`; cache `Completed` results longer and retry Pending ones soon. Resizer responses are immutable per hash.

### trades (16: 2 ALLOW_TOKEN, 14 BLOCK)
What it does: send, accept, counter, decline and list trades.

Default policy: block. Every write moves items or Robux. Trade lists, trade details and counts are the account's private trades. `can-trade-with` and `users/me/can-trade` answer questions about the account's own eligibility.

Allowed: `trades/metadata` (global constants) and `v2/users/{userId}/tradableItems` (a third party's tradable limiteds). Doubt on the latter: it may only answer when the account itself can trade, in which case it simply fails.


## Creator and games hosts: games, develop, publish, localization, locale, clientsettings, ads

194 endpoints: 48 ALLOW_TOKEN, 10 ALLOW_ANON, 136 BLOCK.

### games.roblox.com
What it does: game details, server lists, votes, favorites, media, group and user game lists, private servers.

Default policy: ALLOW_TOKEN for public reads (details, product info, place details, votes counts, favorites count, media, recommendations, server lists). BLOCK every write and every "my" read.

Sneaky endpoints:
- `GET /v1/games/{placeId}/servers/{serverType}` and its two siblings (v2, public-server-browser-service): serverType is 0 (Public) or 1 (Friend). Friend lists servers where the account's friends play. Allowed, but add a path rule that refuses serverType 1 or "Friend".
- `GET /v1/games/{placeId}/private-servers`: looks like a server list, but lists private servers the account can join, with access codes. BLOCK.
- `GET /v1/vip-servers/{id}`: plain GET by id, but the owner view includes the join code. BLOCK.
- `GET /v1/games/{universeId}/votes/user` and `GET /v1/games/{universeId}/favorites`: the account's own vote and favorite. BLOCK.
- `POST /v1/games/vip-servers/{universeId}` buys a private server, `PATCH /v1/vip-servers/{id}/subscription` changes a Robux subscription. Both risk 4.
- `GET /v1/games/multiget-playability-status` is "for the authenticated user" and can reveal the account's age or verification limits. ALLOW_ANON.
- `GET /v2/groups/{groupId}/games`, `gamesV2`, `GET /v2/users/{userId}/games`: with the cookie and accessFilter All, private games visible to the account could show up. ALLOW_ANON. ALLOW_TOKEN with accessFilter forced to 2 would also work.

Caching: `GET /v1/games` has `isFavoritedByUser`, which reflects Roxy's account. With one account and favorite writes blocked it is always the same value, so a shared cache is fine. Server lists change by the second: short TTL only.

### develop.roblox.com
What it does: universe and place configuration, Team Create, playtesters, plugins, the "my universes" and "groups I can manage" lists.

Default policy: BLOCK. Only these are allowed: universe info (`/v1/universes/{id}`, `/v1/universes/multiget`), universe places, plugin details, game templates (ALLOW_TOKEN), group universes and the deprecated asset voting (ALLOW_ANON).

Sneaky endpoints:
- `/v1/universes/multiget/permissions` and `/v1/universes/{id}/permissions`: harmless-looking reads that only describe what the account can manage.
- `/v1/user/groups/canmanage`, `/v1/user/groups/canmanagegamesoritems`, `/v1/user/universes`, `/v1/universes/user-public-publish-eligibility`: "my" endpoints with no ids. They reveal the account's groups, games and verification status.
- `/v2/assets/{id}/versions` is marked cookie-optional but only answers for managers.
- `/v1/groups/{groupId}/universes` may include private universes when the account has group rights, so the cookie is stripped.
- `/v1/assets/voting` adds hasUserVoted and canUserVote with the cookie, so the cookie is stripped.

### publish.roblox.com
What it does: uploads (audio, badge, plugin and game icons, game thumbnails) and upload quotas.

Default policy: BLOCK everything. Uploads put arbitrary content under the account, which is a moderation ban risk. The audio path is a paid flow. `asset-quotas` is the account's own usage.

### gameinternationalization.roblox.com
What it does: localized names, descriptions and icons for games, badges, passes and developer products; supported and source languages; automatic translation; translation analytics; the account's own language per game.

Default policy: BLOCK all writes and creator-dashboard reads. ALLOW_TOKEN for public game data (name-description of a game, source language, supported languages, localized thumbnails, the in-experience language list, the player-choice flag, target languages) and static UI and rollout metadata.

Sneaky endpoints:
- The cookie-required GETs for badge, game pass, developer product and game icons and name-descriptions look like public reads, but they are creator UI views (moderation state, all drafts) and need edit rights. Blocked. Public versions come from thumbnails and item endpoints.
- `GET /v1/user-localization-settings/universe/{universeId}` is the account's own setting. `POST` on the same path writes it.
- `POST /v1/name-description/games/translation-history` is a read, but it is creator data with translator identities.
- Metadata and ui-configurations endpoints may vary by the account's rollout bucket. Trivial.

### localizationtables.roblox.com
What it does: localization table assets (create, read, update entries) and auto-localization ingestion.

Default policy: BLOCK, except three static metadata and limits endpoints. Table reads need access to the table and may expose unreleased game text. Games read their translations in-engine through LocalizationService, not this API.

### translationroles.roblox.com
What it does: translator role assignment on games.

Default policy: BLOCK everything. The "current-user" endpoints reveal what the account collaborates on. Assignees are owner-only. PATCH changes permissions.

### locale.roblox.com
What it does: supported locales, country list, the account's language.

Default policy: ALLOW_TOKEN for reference lists. BLOCK the two set-* writes.

Sneaky endpoints:
- `POST /v1/locales/set-user-supported-locale` changes the account's language. Other endpoints localize text by the account locale, so one caller could change what every caller sees in cached responses.
- `GET /v1/locales/user-locale` and `/user-localization-locus-supported-locales` return the account's saved language with the cookie, or the request's language without it. ALLOW_ANON. They vary by Accept-Language, so key the cache on it or do not cache.

### clientsettings.roblox.com
What it does: client version, installer CDNs, OTA info, compression dictionaries, the account's release channel.

Default policy: ALLOW_TOKEN for static version and CDN info (no auth needed, cookie adds nothing). ALLOW_ANON for channel-aware version and OTA endpoints, so answers stay generic.

Sneaky endpoint: `GET /v2/user-channel` takes no ids. It returns the account's channel, beta program and a channel token. BLOCK.

Caching: dictionary files are immutable per hash and can be large. Cache long.

### ads.roblox.com and adconfiguration.roblox.com
What they do: ad click tracking, sponsored pages, and the ad manager (create, stop and list campaigns, eligibility).

Default policy: BLOCK everything in category `ads`. Click endpoints are a click-fraud vector. `create` endpoints escrow Robux (risk 4). List endpoints show spend and stats. `sponsored-games/universes` and eligibility endpoints reveal what the account owns. `eligible-asset-type-ids` and `sponsored-pages` are harmless but useless to callers.


## apis.roblox.com: cookie and no-sign-in routes

129 endpoints. Almost all of them are Creator Hub tooling: they act on, or read private data about, universes, places, products and billing accounts the logged-in user owns or collaborates on. Roxy's account should own nothing, but the policy must hold even if it someday does (rubric goal d), and a 200 versus 403 answer alone leaks which universes the account manages. Result: 124 BLOCK, 3 ALLOW_ANON, 2 ALLOW_TOKEN.

Simplest rule for the admin list: block every prefix below except `/toolbox-service/v2/assets` (allow, strip cookie) and, optionally, the two static matchmaking helpers.

### /ads-management (10)
Roblox's ad campaign manager: billing accounts, campaigns, creatives.
Default: BLOCK all.
Notable: `GET /advertisable-universes` is a harmless-looking GET that lists the universes the account may advertise, which means the ones it owns or manages. `POST /campaigns:batchGetStatus` is a read in POST form, but only over the account's own campaigns, so it stays blocked. `POST /campaigns` and `PATCH /campaigns/{id}` set budgets and can spend money (risk 4).
Caveats: writes need a CSRF token. `campaign-options` without `universeId` is mostly static, but there is no public use for it.

### /analytics-alert-control-plane (5)
Analytics alert rules and incidents for a universe.
Default: BLOCK all.
Notable: listed as cookie-optional, which just means "cookie or API key". Anonymously it fails, so ALLOW_ANON is pointless. DELETE is irreversible.

### /asset-permissions-api (1)
`PATCH /v1/assets/permissions` grants a user, group or universe the right to use many assets at once.
Default: BLOCK (risk 4). It would let a stranger hand out access to anything the account controls.

### /creator-configs-public-api (20)
Two features: live config repositories (draft, publish, revisions, restore) and A/B experiments (create, start, schedule, complete, stats).
Default: BLOCK all.
Notable: `POST .../experiments:calculateMde` is a read-scoped POST but still runs on private universe traffic. Publish, restore, start and complete change live game behavior for real players (risk 4).

### /developer-products and /game-passes (8)
Creator views and writes for developer products and game passes. The `/creator` suffix GETs return configuration details only for universes the account manages.
Default: BLOCK all. Public product info lives on other hosts (economy, games) and is not affected.
Notable: the PATCH endpoints can change prices.

### /log-attribute-http-service (6)
Undocumented (no summaries) universe log attribution regex rules, scoped `universe.analytics`.
Default: BLOCK all.

### /matchmaking-api (33)
Custom matchmaking for a universe: player and server attributes, scoring configs and signals, start place override, plus game instance update rollouts and shutdowns.
Default: BLOCK, except two static helpers.
Notable:
- Most rows are listed as auth `none` in the spec, but they are clearly creator tools that authorize with whatever cookie is attached. Do not trust the `none` label here.
- `POST /game-instances/launch-update` (auth none) and `POST /game-instances/shutdown` / `shutdown-all` (cookie) restart or kill live servers: risk 4.
- `GET/POST /client-status` is undocumented; it looks like per-session state, so both are blocked.
- `GET /start-place/test?userId=` tests another user's saved start place: third-party data.
- `GET /scoring-configuration/{id}` is summarized as "Updates" in the spec but is a read.
- `GET /scoring-configuration/default-weights` and `GET /scoring-configuration/generate-mock-servers` hold no user or universe data: ALLOW_TOKEN, risk 1. Blocking the whole prefix is also fine; nobody needs them through a proxy.

### /place-version-history-api (3)
Place version history, contributor list, version notes.
Default: BLOCK. Contributor lists and save notes are private to editors.

### /server-management (6)
Live server lists, server logs, universe restarts and restart forecasts.
Default: BLOCK. `POST /restarts` disconnects players (risk 4). Server logs can contain player and script data.

### /service-efficiency-api (23)
Extended Services billing: accounts, bills, billing activity, payment profiles, payment methods, manual payments, universe consumer config, eligibility.
Default: BLOCK all. This is the most dangerous group here.
Notable:
- `POST /payments/users/{userId}` and `/payments/groups/{groupId}` submit real-money payments; payment profile create, delete and set are risk 4.
- `{userId}` paths only resolve for the authenticated user, so any GET under them is the account's own billing data.
- `GET /is_allowed` answers "can the current user use this", which is about Roxy's account itself.

### /thumbnail-personalization-api (8)
Homepage thumbnail uploads and personalization configs for a universe.
Default: BLOCK. Image uploads are also an abuse path: moderation strikes would land on Roxy's account.

### /toolbox-service (7)
- `/v1/saves` (4): the account's own Creator Store "saves" collections. Default: BLOCK (private reads; bulkDelete can wipe up to 5000 saves).
- `/v2/assets/{id}` and `/v2/assets:search` (GET and POST): public Creator Store asset details and search. Verdict: ALLOW_ANON. The response's `voting` block carries `userVote`, `hasVoted` and `canVote`, which describe the viewer. With the cookie, those fields would show Roxy's own votes and would be cached and shared. Strip the cookie and the response is safe to cache. The POST search is a read.

### /universe-performance-raqi (1)
Universe game log details by message hash or keyword.
Default: BLOCK (private server logs).

### Cross-cutting caveats
- Every write here needs an `x-csrf-token` with a cookie. That is not a defense: a proxy can do the CSRF dance for the caller, so these must be blocked by path, not by trusting CSRF.
- Read endpoints here are permission-gated. Even when Roxy's account owns nothing, the 403 versus 200 difference is a membership oracle, which is why the GETs are blocked too.
- Many paths use colon suffixes (`:batchGetStatus`, `:start`, `:overwrite`, `:search`). The path matcher must treat `:verb` as part of the final segment and must not let `assets:search` fall into a rule meant for `assets/{id}` or the reverse.


## apis.roblox.com: Open Cloud key-only routes (199)

All 199 are BLOCK, category `open-cloud-key-only`. They accept only an `x-api-key` header or an OAuth bearer token and never a cookie. Roxy has no API key, and callers may not send their own, so none of these can ever succeed through Roxy. Blocking them also keeps a future code change from accidentally letting a caller smuggle in a key.

Risk counts: 1 harmless: 3, 2 low: 55, 3 meaningful: 114, 4 critical: 27.

### Feature areas

**Data stores (v2 and legacy v1, 26 rows)**: key/value save data for a universe: list stores, read, write, delete, increment, revisions, snapshot, undelete. Key-only. Roblox points every v1 path to the v2 path as the recommended alternative, and v2 is key-only too, so there is no cookie route. Later support: reading entries with a Roxy-owned key is the most plausible request (a game reading a shared global config or leaderboard). Risk: the key must be scoped to read on one universe the owner controls; any write scope lets a stranger corrupt or delete player saves, so writes should stay blocked.

**Ordered data stores (v2 and v1, 12 rows)**: numeric leaderboard data. Same story as data stores. Read-only support is plausible (global leaderboards); writes would let anyone forge scores.

**Memory stores (10 rows)**: short-lived queues and sorted maps used for live matchmaking and flush. Reading is not harmless for queues (reads lock items). Flush wipes everything. Unlikely to be wanted; if so, limit to sorted-map reads.

**Messaging (2 rows, v2 publishMessage and v1 topic publish)**: broadcast a message to all running servers of a universe. Games trust these messages. A public Roxy endpoint would let any stranger trigger game logic, so only allow it with a per-universe topic allow-list and a shared secret, if ever.

**Universes, places, instances, restart (about 20 rows)**: read universe and place settings, edit them, read or edit the data model (instances), publish a new place version, restart servers, activate or deactivate. Reads of public details are available on cookie hosts such as games.roblox.com. Writes and place publishing could overwrite or take down a whole game. Do not support.

**Luau execution (5 rows)**: run arbitrary code on Roblox servers inside a place, with logs and binary inputs. Critical risk (arbitrary code with the key owner's rights). Never support.

**Secrets (5 rows)**: store, replace, delete and list encrypted secrets (third-party API keys) for a universe. Critical. Never support.

**Assets (14 rows incl. delivery, speech, quotas)**: upload, update, version, archive, roll back, download and generate assets. Uploads can cost Robux and publish under the owner's name. Download of public assets is already available on assetdelivery.roblox.com with a cookie; the key-only copy adds nothing.

**Groups (13 v2 rows plus 8 legacy rows)**: reads (info, roles, members, forum) duplicate public cookie endpoints on groups.roblox.com. Join request handling, role assignment, settings, description, shout and audit log are admin actions and sensitive. Only the public reads could ever be worth serving, and they are served elsewhere.

**Users (about 8 rows)**: profile, inventory, asset quotas, subscription record, thumbnails, notifications. Public profile, inventory and thumbnails already exist on cookie hosts. Notifications are a spam vector.

**User restrictions (bans, 8 rows)**: list, read, create or change bans, and ban logs for a universe or place. Moderation power; never support.

**Analytics (4 rows)**: creator metrics for a universe. Private to the owner. A game might read its own metrics, but that is not a game-server use case.

**Badges, game passes, developer products, localization, game icons and thumbnails (about 55 rows, legacy-* services)**: creator-management writes (edit names, descriptions, icons, translations) plus a few harmless reads. Blocked as key-only; cookie twins on develop and other hosts are covered in their own sections.

**Team Create and universe permissions (about 10 rows)**: who is editing, what permissions the credential has, settings changes. Reveals what the credential can do.

**Following (5 rows)**: follow and unfollow a universe for a user, and read follow status.

**Game events and Creator Store products (about 8 rows)**: create, edit, delete events and store listings. Spam and money-adjacent.

### What the owner might plausibly support later with a Roxy-owned key

1. Data store reads and ordered data store reads for specific universes the owner controls (global configs, leaderboards). Lowest risk, highest game value. Needs a per-universe allow-list and a read-only key.
2. Messaging publish for the owner's own universes. Medium to high risk: needs a topic allow-list and caller authentication, otherwise any stranger can fire game events.
3. Public reads (group info, user profile, thumbnails) are already available through cookie hosts, so the Open Cloud copies add nothing.

Everything else (writes, secrets, Luau execution, bans, place publishing, asset upload, group admin) should stay blocked even if a key is ever added.

