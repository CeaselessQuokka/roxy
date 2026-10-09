# Roxy user guide

Roxy is a free proxy for public Roblox web APIs. This guide shows how to call it from a Roblox game, what the
limits are, what every response header and status code means, and what Roxy records about your requests.

When you read this guide at [roxytheproxy.com/docs](https://roxytheproxy.com/docs), the numbers in it (limits,
cache times, how long data is kept) are filled in from Roxy's live settings each time the page loads, so they are
always current. In the source file they appear as names in double braces.

## 1. What Roxy does

Roblox game servers cannot call `*.roblox.com` web APIs from `HttpService`: Roblox refuses requests from its own
game servers to its own web domains. Roxy is a relay on a different domain. Your game sends the request to Roxy,
Roxy forwards it to Roblox, and Roxy returns Roblox's answer.

Along the way Roxy:

- keeps copies of popular answers (a cache), so many requests are answered instantly without asking Roblox again;
- shares Roblox's rate limits fairly between every game that uses it, with a limit for each IP address;
- refuses requests that carry login cookies or tokens, because Roxy only handles public data.

Roxy is free and needs no account and no API key.

## 2. URL format

Take the Roblox URL and put `https://roxytheproxy.com/` in front of the host name:

```text
https://games.roblox.com/v1/games?universeIds=1
https://roxytheproxy.com/games.roblox.com/v1/games?universeIds=1
```

Rules:

- The host must be a supported Roblox subdomain, such as `games.roblox.com`, `users.roblox.com`,
  `thumbnails.roblox.com` or `avatar.roblox.com`. Any other host gets `404`.
- The path and the query string are passed to Roblox unchanged.
- Repeated parameters are kept, in order: `?ids=1&ids=2` reaches Roblox as `?ids=1&ids=2`.
- `?prettyprint=true` (or `&prettyprint=true` after other parameters) formats JSON with indentation, for reading
  in a browser. Roxy removes it before calling Roblox, so it changes how the answer looks, never what it says.
- `GET`, `HEAD`, `POST`, `PATCH`, `PUT` and `DELETE` are forwarded. `OPTIONS` is answered by Roxy itself.
- The part of the URL after `roxytheproxy.com` (the path and the query string together) may be up to
  {{ max_url_length }} long; a longer one is answered with `414`. Split a long list of ids over several
  requests, or use a POST batch endpoint (chapter 3).
- Request bodies may be up to {{ max_body_kib }} KiB. A request that takes longer than
  {{ request_deadline }} in total is answered with `504`.

## 3. Examples in Luau

All examples run in a server `Script` or `ModuleScript`. Turn on **Allow HTTP Requests** in Game Settings,
Security, first. `HttpService` cannot be used from a `LocalScript`.

Every example is complete and passes Luau's type checker in strict mode with no warnings. Each one starts with
`--!strict`, so Studio checks the types as you edit; gives every function typed parameters and a return type;
gives the parts of Roblox's JSON it reads a named type (`export type`) and checks them before using them, because
`JSONDecode` returns `any`, which the type checker cannot check for you; and wraps every `HttpService` call in
`pcall`, because those calls raise an error instead of returning one.

Names that are never assigned again are declared with `const` (Luau 0.711 and later), so Luau refuses any later
assignment to them: the services, the URLs and limits, the module table, the functions, and most values inside
functions. The few names that do change (a counter, the time to wait next) use `local`, so `local` tells you at a
glance what can change. True constants, such as URLs and limits, have UPPER_SNAKE_CASE
names; services, modules and types use PascalCase, and everything else camelCase. If your Studio does not accept
`const` yet, write `local` in its place (`local function` for `const function`); nothing else changes.

### Read the status code with RequestAsync

`RequestAsync` returns the status code and the headers, so your script can react to limits instead of failing.
When Roxy answers `429` or `503`, this one waits as long as `Retry-After` says, plus a little random jitter, and
gives up when the wait would be too long:

```luau
--!strict
-- Reads one experience's details through Roxy, and waits as long as Roxy asks whenever it says to slow down.
const HttpService = game:GetService("HttpService")

const ROXY_URL = "https://roxytheproxy.com/"
const UNIVERSE_ID = 1 -- replace with your experience's universe id
const MAX_ATTEMPTS = 3
const FALLBACK_WAIT_SECONDS = 30 -- used when a 429 or 503 has no usable Retry-After
const MAX_WAIT_SECONDS = 120 -- give up instead of waiting longer than this
const MAX_JITTER_SECONDS = 2

-- The fields of the games.roblox.com/v1/games answer that this script reads.
export type GameDetails = {
	id: number,
	rootPlaceId: number,
	name: string,
	playing: number,
	visits: number,
}

export type GamesResponse = {
	data: { GameDetails },
}

-- The parts of a RequestAsync answer that this script reads.
type HttpResponse = {
	StatusCode: number,
	Headers: { [string]: string },
	Body: string?,
}

-- Header names can arrive in any letter case, so compare them in lower case.
const function getHeader(headers: { [string]: string }, name: string): string?
	const wanted = string.lower(name)
	for key, value in headers do
		if string.lower(key) == wanted then
			return value
		end
	end
	return nil
end

-- Retry-After when it is a usable number, otherwise the fallback, plus random jitter, so that many
-- servers told to wait do not all come back at the same moment.
const function retryWaitSeconds(headers: { [string]: string }): number
	const retryAfter = tonumber(getHeader(headers, "Retry-After"))
	const seconds = if retryAfter and retryAfter >= 0 then retryAfter else FALLBACK_WAIT_SECONDS
	return seconds + math.random() * MAX_JITTER_SECONDS
end

const function fetchGame(universeId: number): GameDetails?
	const url = `{ROXY_URL}games.roblox.com/v1/games?universeIds={universeId}`
	for attempt = 1, MAX_ATTEMPTS do
		const sent, response = pcall(function(): HttpResponse
			return HttpService:RequestAsync({ Url = url, Method = "GET" })
		end)
		if not sent then
			-- HttpService raised before any answer: HTTP requests are off, or the network failed.
			warn("Request could not be sent:", response)
			return nil
		end

		if response.StatusCode == 200 then
			-- JSONDecode returns `any`: the return type names the shape, and the check confirms it before use.
			const decoded, games = pcall(function(): GamesResponse
				return HttpService:JSONDecode(response.Body or "")
			end)
			if not decoded or typeof(games) ~= "table" or typeof(games.data) ~= "table" then
				warn("The answer was not the JSON this script expects")
				return nil
			end
			return games.data[1] -- nil when no experience has this universe id
		elseif response.StatusCode == 429 or response.StatusCode == 503 then
			const waitSeconds = retryWaitSeconds(response.Headers)
			if attempt == MAX_ATTEMPTS or waitSeconds > MAX_WAIT_SECONDS then
				warn(`Roxy asked to wait {math.ceil(waitSeconds)} seconds; giving up for now`)
				return nil
			end
			task.wait(waitSeconds)
		else
			-- Other codes: fix the request (4xx), or try again later (5xx). The user guide lists them all.
			warn(`Roxy answered {response.StatusCode}:`, response.Body)
			return nil
		end
	end
	return nil
end

const details = fetchGame(UNIVERSE_ID)
if details then
	print(`{details.name}: {details.playing} playing, {details.visits} visits`)
end
```

### Quick reads with GetAsync

`GetAsync` returns only the body and raises an error for any status other than success, so wrap it in `pcall`:

```luau
--!strict
-- The quickest read: GetAsync returns the body, and raises an error for any status but success.
const HttpService = game:GetService("HttpService")

const OUTFITS_URL =
	"https://roxytheproxy.com/avatar.roblox.com/v2/avatar/users/29371917/outfits?outfitType=Avatar&page=1&itemsPerPage=100&isEditable=true"

-- The fields of the outfits answer that this script reads.
export type Outfit = {
	id: number,
	name: string,
}

export type OutfitsResponse = {
	data: { Outfit },
}

-- One pcall covers both ways this can fail: GetAsync raising, and JSONDecode meeting text that is not JSON.
-- JSONDecode returns `any`, so the function's return type names the shape, and the check below confirms it.
const ok, result = pcall(function(): OutfitsResponse
	return HttpService:JSONDecode(HttpService:GetAsync(OUTFITS_URL))
end)

if not ok then
	-- GetAsync cannot show the status code or Retry-After; RequestAsync can.
	warn("Roxy request failed:", result)
elseif typeof(result) ~= "table" or typeof(result.data) ~= "table" then
	warn("The answer was not the JSON this script expects")
else
	for _, outfit in result.data do
		print(outfit.id, outfit.name)
	end
end
```

### POST batch lookups

Some Roblox endpoints take a list in a POST body and answer for every item at once. Prefer them: one batch
request counts once against your limit, where twenty single lookups count twenty times.

```luau
--!strict
-- POST works like GET, with a Method and a JSON body. A batch endpoint like this one answers for many
-- items at once, and the whole batch counts as one request against your limit.
const HttpService = game:GetService("HttpService")

const USERNAMES_URL = "https://roxytheproxy.com/users.roblox.com/v1/usernames/users"
const MAX_ATTEMPTS = 3
const FALLBACK_WAIT_SECONDS = 30 -- used when a 429 or 503 has no usable Retry-After
const MAX_WAIT_SECONDS = 120 -- give up instead of waiting longer than this
const MAX_JITTER_SECONDS = 2

-- The body users.roblox.com/v1/usernames/users expects, and the fields of its answer.
export type UsernamesRequest = {
	usernames: { string },
	excludeBannedUsers: boolean,
}

export type UserByName = {
	requestedUsername: string,
	id: number,
	name: string,
	displayName: string,
}

export type UsernamesResponse = {
	data: { UserByName },
}

-- The parts of a RequestAsync answer that this script reads.
type HttpResponse = {
	StatusCode: number,
	Headers: { [string]: string },
	Body: string?,
}

-- Header names can arrive in any letter case, so compare them in lower case.
const function getHeader(headers: { [string]: string }, name: string): string?
	const wanted = string.lower(name)
	for key, value in headers do
		if string.lower(key) == wanted then
			return value
		end
	end
	return nil
end

-- Retry-After when it is a usable number, otherwise the fallback, plus random jitter.
const function retryWaitSeconds(headers: { [string]: string }): number
	const retryAfter = tonumber(getHeader(headers, "Retry-After"))
	const seconds = if retryAfter and retryAfter >= 0 then retryAfter else FALLBACK_WAIT_SECONDS
	return seconds + math.random() * MAX_JITTER_SECONDS
end

const function lookUpUsers(usernames: { string }): { UserByName }?
	const request: UsernamesRequest = { usernames = usernames, excludeBannedUsers = true }
	for attempt = 1, MAX_ATTEMPTS do
		const sent, response = pcall(function(): HttpResponse
			-- JSONEncode raises for a value JSON cannot hold, so it runs inside the pcall too.
			const body = HttpService:JSONEncode(request)
			return HttpService:RequestAsync({
				Url = USERNAMES_URL,
				Method = "POST", -- PATCH, PUT and DELETE work the same way
				Headers = { ["Content-Type"] = "application/json" },
				Body = body,
			})
		end)
		if not sent then
			warn("Request could not be sent:", response)
			return nil
		end

		if response.StatusCode == 200 then
			-- JSONDecode returns `any`: the return type names the shape, and the check confirms it before use.
			const decoded, result = pcall(function(): UsernamesResponse
				return HttpService:JSONDecode(response.Body or "")
			end)
			if not decoded or typeof(result) ~= "table" or typeof(result.data) ~= "table" then
				warn("The answer was not the JSON this script expects")
				return nil
			end
			return result.data
		elseif response.StatusCode == 429 or response.StatusCode == 503 then
			const waitSeconds = retryWaitSeconds(response.Headers)
			if attempt == MAX_ATTEMPTS or waitSeconds > MAX_WAIT_SECONDS then
				warn(`Roxy asked to wait {math.ceil(waitSeconds)} seconds; giving up for now`)
				return nil
			end
			task.wait(waitSeconds)
		else
			warn(`Roxy answered {response.StatusCode}:`, response.Body)
			return nil
		end
	end
	return nil
end

const users = lookUpUsers({ "Roblox", "builderman" })
if users then
	for _, user in users do
		print(`{user.requestedUsername} is user {user.id} ({user.displayName})`)
	end
end
```

`POST`, `PATCH`, `PUT` and `DELETE` work the same way, but most Roblox write endpoints need a signed-in account,
and Roxy never acts as a signed-in user (chapter 9).

### Reading Roxy headers

Roblox may give you header names in a different letter case than Roxy sent them, so look them up without caring
about case:

```luau
--!strict
-- Prints the Roxy headers that describe your limit and the cache, for one request.
const HttpService = game:GetService("HttpService")

const URL = "https://roxytheproxy.com/games.roblox.com/v1/games?universeIds=1"
const HEADER_NAMES = { "Roxy-Requests-Left", "Roxy-Throttle-Reset", "Roxy-Cache", "Roxy-Cache-Age", "Roxy-Request-Id" }

-- The parts of a RequestAsync answer that this script reads.
type HttpResponse = {
	StatusCode: number,
	Headers: { [string]: string },
}

-- Header names can arrive in any letter case, so compare them in lower case.
const function getHeader(headers: { [string]: string }, name: string): string?
	const wanted = string.lower(name)
	for key, value in headers do
		if string.lower(key) == wanted then
			return value
		end
	end
	return nil
end

const sent, response = pcall(function(): HttpResponse
	return HttpService:RequestAsync({ Url = URL, Method = "GET" })
end)

if not sent then
	warn("Request could not be sent:", response)
else
	print(`Status: {response.StatusCode}`)
	for _, name in HEADER_NAMES do
		print(`{name}: {getHeader(response.Headers, name) or "(not sent)"}`)
	end
	if response.StatusCode == 429 then
		print(`Throttled: wait {getHeader(response.Headers, "Retry-After") or "a while"} seconds before the next request`)
	end
end
```

### A reusable module with caching and backoff

Put this in a `ModuleScript` named `RoxyClient` in `ServerScriptService`. It keeps answers for a minute, waits
exactly as long as `Retry-After` says (and holds back every other call through the module meanwhile), and backs
off with random jitter after failures, so many servers do not retry at the same moment.

```luau
--!strict
-- RoxyClient: a typed HttpService wrapper for Roxy, with a small cache, Retry-After and backoff with jitter.
const HttpService = game:GetService("HttpService")

const BASE_URL = "https://roxytheproxy.com/"
const CACHE_SECONDS = 60
const MAX_CACHE_ENTRIES = 500
const MAX_ATTEMPTS = 4
const FALLBACK_WAIT_SECONDS = 30 -- used when a 429 or 503 has no usable Retry-After
const MAX_WAIT_SECONDS = 120 -- give up instead of waiting longer than this
const MAX_BACKOFF_SECONDS = 30
const MAX_JITTER_SECONDS = 2

-- What getJson returns: the decoded JSON, or the reason there is none. `value` is `any` on purpose: the
-- module cannot know each endpoint's shape, so the caller checks the parts it reads and names their type.
export type Result = { ok: true, value: any } | { ok: false, message: string }

type CacheEntry = {
	expiresAt: number,
	value: any,
}

-- The parts of a RequestAsync answer that this script reads.
type HttpResponse = {
	StatusCode: number,
	Headers: { [string]: string },
	Body: string?,
}

const RoxyClient = {}

const cache: { [string]: CacheEntry } = {}
local cacheSize = 0
local blockedUntil = 0 -- after Roxy asks every caller to wait, no request is sent before this os.time()

-- Header names can arrive in any letter case, so compare them in lower case.
const function getHeader(headers: { [string]: string }, name: string): string?
	const wanted = string.lower(name)
	for key, value in headers do
		if string.lower(key) == wanted then
			return value
		end
	end
	return nil
end

-- Retry-After when it is a usable number, otherwise the fallback, plus random jitter.
const function retryWaitSeconds(headers: { [string]: string }): number
	const retryAfter = tonumber(getHeader(headers, "Retry-After"))
	const seconds = if retryAfter and retryAfter >= 0 then retryAfter else FALLBACK_WAIT_SECONDS
	return seconds + math.random() * MAX_JITTER_SECONDS
end

-- Exponential backoff with full jitter: a random wait of up to 2, 4, 8... seconds, at most MAX_BACKOFF_SECONDS.
const function backoffSeconds(attempt: number): number
	return math.random() * math.min(MAX_BACKOFF_SECONDS, 2 ^ attempt)
end

const function remember(path: string, value: any): ()
	if cache[path] == nil then
		cacheSize += 1
		if cacheSize > MAX_CACHE_ENTRIES then
			table.clear(cache) -- the simplest bound: start over when full
			cacheSize = 1
		end
	end
	cache[path] = { expiresAt = os.time() + CACHE_SECONDS, value = value }
end

-- Fetches a Roblox path such as "games.roblox.com/v1/games?universeIds=1" through Roxy and decodes the JSON.
-- Waits while Roxy has asked to slow down, retries failures with backoff, and never retries other 4xx answers.
function RoxyClient.getJson(path: string): Result
	const cached = cache[path]
	if cached and cached.expiresAt > os.time() then
		return { ok = true, value = cached.value }
	end

	local lastError = "no attempt was made"
	local delaySeconds = 0
	for attempt = 1, MAX_ATTEMPTS do
		const waitSeconds = math.max(delaySeconds, blockedUntil - os.time())
		if waitSeconds > 0 then
			task.wait(waitSeconds)
		end

		const sent, response = pcall(function(): HttpResponse
			return HttpService:RequestAsync({ Url = BASE_URL .. path, Method = "GET" })
		end)
		if not sent then
			lastError = `the request could not be sent: {response}`
			delaySeconds = backoffSeconds(attempt)
		elseif response.StatusCode == 200 then
			const decoded, value = pcall(function(): any
				return HttpService:JSONDecode(response.Body or "")
			end)
			if not decoded then
				return { ok = false, message = "the answer was not valid JSON" }
			end
			remember(path, value)
			return { ok = true, value = value }
		elseif response.StatusCode == 429 or response.StatusCode == 503 then
			const retrySeconds = retryWaitSeconds(response.Headers)
			if retrySeconds > MAX_WAIT_SECONDS then
				return { ok = false, message = `Roxy asked to wait {math.ceil(retrySeconds)} seconds` }
			end
			blockedUntil = os.time() + retrySeconds
			delaySeconds = 0
			lastError = `HTTP {response.StatusCode}`
		elseif response.StatusCode >= 500 then
			-- Roblox or Roxy is failing: honor Retry-After when sent, and wait a little longer each time.
			const retryAfter = tonumber(getHeader(response.Headers, "Retry-After")) or 0
			delaySeconds = math.min(retryAfter, MAX_WAIT_SECONDS) + backoffSeconds(attempt)
			lastError = `HTTP {response.StatusCode}`
		else
			-- Any other code (400, 403, 404...): the request itself is wrong, and sending it again will not help.
			return { ok = false, message = `HTTP {response.StatusCode}: {response.Body or ""}` }
		end
	end
	return { ok = false, message = lastError }
end

return RoxyClient
```

Use it from any server script:

```luau
--!strict
-- A server Script that reads an experience's details through the RoxyClient module.
const ServerScriptService = game:GetService("ServerScriptService")
const RoxyClient = require(ServerScriptService.RoxyClient)

const UNIVERSE_ID = 1 -- replace with your experience's universe id

-- The fields of the games.roblox.com/v1/games answer that this script reads.
export type GameDetails = {
	id: number,
	name: string,
	playing: number,
}

export type GamesResponse = {
	data: { GameDetails },
}

const result = RoxyClient.getJson(`games.roblox.com/v1/games?universeIds={UNIVERSE_ID}`)
if not result.ok then
	warn("Roxy request failed:", result.message)
elseif typeof(result.value) ~= "table" or typeof(result.value.data) ~= "table" then
	warn("The answer was not the JSON this script expects")
else
	-- The check above confirmed the parts this script reads, so the `any` value can take its named type.
	const games: GamesResponse = result.value
	for _, details in games.data do
		print(`{details.name}: {details.playing} playing`)
	end
end
```

## 4. Limits

Each IP address may send **{{ window_requests }} every {{ window_length }}**.
{{ pacing_rule }} {{ cache_hits_rule }}

**Tip:** your own cache is the best way to stay under the limit. An answer your game already has costs no
request at all, so keep answers for as long as your game can use them (the `RoxyClient` module in chapter 3
keeps them for a minute) and use batch endpoints.

Separately, a **flood limit of {{ flood_requests }} per minute** per IP address counts every request,
cached or not. It is a safety net against floods; normal games never get near it.

{{ ipv6_rule }}

{{ place_limit_rule }} An experience is identified by the `Roblox-Id` header that Roblox adds to requests from its
game servers.

When you go over a limit, Roxy answers `429 Too Many Requests` with a `Retry-After` header.
{{ escalation_rule }}

During an incident the admin can switch on an emergency limit for everyone ({{ emergency_requests }} per
{{ emergency_period }} per IP address while it is on). Those refusals carry `Roxy-Global-Throttled`.

Roblox has rate limits of its own. When Roblox tells Roxy to slow down, Roxy waits for the time Roblox asks for
and tells you through `Roxy-Upstream-Cooldown` and `Retry-After`, serving a cached copy instead when it has one.

## 5. Caching

Caching is currently **{{ cache_state }}**. Roxy keeps copies of many answers. Most are kept for about
{{ cache_ttl }}; some endpoints have their own rules (data that never changes, such as the
experience a place belongs to, is kept much longer, and fast-changing data such as presence much shorter). So the
data you get can be up to that old.

The `Roxy-Cache` header says where an answer came from:

| Value | Meaning |
|---|---|
| `HIT` | Served from Roxy's cache. Roblox was not asked. |
| `MISS` | Not in the cache: Roxy asked Roblox, and may keep the answer for the next caller. |
| `REVALIDATING` | Served from the cache just after it expired, while Roxy fetches a fresh copy in the background. |
| `STALE` | An older copy, served because Roblox is rate limiting or failing right now. |
| `COALESCED` | Many callers asked for the same thing at once; Roxy asked Roblox once and gave everyone that answer. |
| `OFF` | Not cacheable (for example a write request, or caching is off). |

`Roxy-Cache-Age` is how many seconds ago Roxy stored the copy, and `Roxy-Cache-TTL` how long the copy counts as
fresh in total. When Roblox is in trouble, a copy can be served up to {{ cache_stale }} after it
stopped being fresh, marked `STALE`, instead of an error.

Adding a random parameter such as `t`, `_`, `ts`, `cb` or `cachebust` does not get you fresher data: by default
Roxy ignores those parameters when it looks up the cache. Ask less often instead, and keep your own cache in your
game.

## 6. Response headers reference

| Header | When | Meaning |
|---|---|---|
| `Roxy-Requests-Left` | Proxied answers | How many more requests you can send before you are throttled. |
| `Roxy-Throttle-Reset` | Proxied answers | Seconds until your allowance is refilled, or until you may send again when throttled. |
| `Roxy-Throttled` | Proxied answers | `True` while your IP address is throttled, otherwise `False`. |
| `Retry-After` | `429`, `503` and some `5xx` answers | Seconds to wait before sending again. Always respect it. |
| `Roxy-Paused` | `503` while paused | Present while Roxy is paused for maintenance. |
| `Roxy-Global-Throttled` | `429` | Present when the emergency limit for everyone refused the request. |
| `Roxy-Client-Limited` | `429` | Present when a limit for your User-Agent refused the request. |
| `Roxy-Blocked` | `403` | Present when the endpoint is blocked on Roxy. |
| `Roxy-Endpoint-Limited` | `429` | Present when a limit for that endpoint refused the request. |
| `Roxy-Refusal` | Most refusals | A short code naming why Roxy refused, such as `throttle`, `flood` or `paused`. |
| `Roxy-Cache` | Answers from Roblox or the cache | `HIT`, `MISS`, `REVALIDATING`, `STALE`, `COALESCED` or `OFF` (chapter 5). |
| `Roxy-Cache-Age` | Cached answers | Seconds since Roxy stored the copy. |
| `Roxy-Cache-TTL` | Cached answers | Seconds the copy counts as fresh in total. |
| `Roxy-Upstream-Status` | Answers that involved Roblox | The status code Roblox returned. |
| `Roxy-Upstream-Cooldown` | While Roblox is rate limiting | Seconds until Roxy asks Roblox again for this kind of request. |
| `Roxy-Request-Id` | Every answer | A unique id for this request. Include it when you report a problem. |

## 7. Status codes and what to do

| Code | Meaning | What to do |
|---|---|---|
| 200 to 299 | Success (from Roblox or cache) | Use the body |
| 400 | Bad request, or you sent authentication (not allowed) | Fix the request; never send cookies or tokens |
| 403 | Endpoint blocked by Roxy (`Roxy-Blocked`) or Roblox refused | Do not retry; check the message |
| 404 | Not found at Roblox, or not a supported Roblox URL | Check the URL format |
| 413, 431 | Request too large | Send smaller bodies or fewer headers |
| 414 | URL too long (chapter 2 gives the limit) | Send fewer ids per request, or use a POST batch endpoint |
| 429 | Rate limited by Roxy (your client) or Roblox is rate-limiting (`Roxy-Upstream-Cooldown`) | Wait `Retry-After` seconds; add your own caching |
| 500 | Unexpected Roxy error, or a Roblox 500 passed through (`Roxy-Upstream-Status: 500`) | Retry later with backoff |
| 502 | Roxy could not connect to Roblox, or a Roblox 502 passed through | Retry with backoff after `Retry-After` |
| 504 | Roblox timed out, or the request hit Roxy's overall deadline | Retry with backoff after `Retry-After` |
| 503 | Roxy paused (`Roxy-Paused`), all upstream paths disabled, or too many identical requests were waiting at once | Wait `Retry-After` |

Roxy's own refusals (such as your limit's `429`, or `404` for a URL that is not Roblox's) have a JSON string as
the body, such as `"Too many requests; please slow down."` followed by a line break, sent as `application/json`;
`HttpService:JSONDecode(response.Body)` gives you the message text. When Roxy could not get an answer from Roblox
(for example `502` or `504`), or refuses a request for its size (`413`, `414` or `431`), the body is a short
plain text message instead. Either way `print(response.Body)`
tells you what happened. Other codes from Roblox (for example `401` or `410`) are passed through with Roblox's own
body and the `Roxy-Upstream-Status` header.

## 8. Good citizen checklist

- Cache answers in your game. Most data does not change every second, and an answer you already have costs
  nothing.
- Batch requests: one request for 50 ids instead of 50 requests.
- {{ retry_tip }}
- Add random jitter to retries, so your servers do not all retry at the same moment.
- Never send cookies, tokens or passwords. Roxy refuses them, and no proxy should ever see them.
- Let Roblox identify your experience: Roblox adds the `Roblox-Id` header to game server requests on its own;
  do not remove it.
- {{ status_tip }}

## 9. What Roxy will not do

- **No authenticated requests on your behalf.** Roxy never sends anyone's login cookie for you, and it refuses
  requests that carry one (`400`).
- **No writes that need login**, such as changing a group or buying an item.
- **No hosts other than Roblox.** Roxy is not a general web proxy.
- {{ cors_rule_item }}

## 10. Privacy

For each request Roxy records your IP address, the experience id that Roblox sends (`Roblox-Id`), the endpoint,
the User-Agent, the status code and the timing. That is what it needs to enforce fair limits, spot abuse and
find problems.

How long it is kept:

- per-minute activity by IP address and experience: {{ client_minute_retention }};
- hourly summaries: {{ client_hour_retention }}, and daily summaries: {{ client_day_retention }};
- notable events, such as refusals, bans and probes: {{ events_retention }};
- a small sample of individual requests (no bodies), used to tune caching: {{ request_sample_retention }}.

{{ capture_rule }}

Only Roxy's admin can see this data, and it is used only to run and protect the service. Never put personal
data in a URL you send through Roxy.

## 11. Security reports and bug bounty

If you find a vulnerability, report it privately to {{ contact_name }} before telling anyone else. Include what
you did, what happened, and the `Roxy-Request-Id` of a request that shows it. Never include your own
`ROBLOSECURITY` cookie or anyone else's.

Please do not test against other people's data, and do not run floods or anything else that slows Roxy down for
everyone. Serious reports are rewarded; the current reward range is on the
[home page](/#tokenSafetyHeading).

## 12. FAQ

### Is Roxy free?

Yes. There is no account, key or payment.

### Why do I get 429 when I barely send anything?

{{ cache_hits_faq }} Your requests also share an IP address with everything else your server sends, and
possibly with other servers. Read `Roxy-Requests-Left` and `Retry-After`, keep answers in your own cache instead
of asking again (an answer your game already has costs no request at all), and use batch endpoints.

### Why is the data a little old?

It came from Roxy's cache (`Roxy-Cache: HIT` or `STALE`). See chapter 5 for how old it can be.

### Can I call Roxy from a website?

{{ cors_faq }}

### Can Roxy use my account?

No. Roxy only handles public data and refuses any request that carries a login cookie or token.

### Can I get a higher limit?

Ask {{ contact_name }}, and say what your experience needs and why caching on your side is not enough.

### How do I know whether Roxy is down?

{{ status_faq }}

### Roxy returned an error I do not understand.

Print `response.Body` and the `Roxy-Request-Id` header. Chapter 7 explains every status code; if that does not
help, send the request id to {{ contact_name }}.
