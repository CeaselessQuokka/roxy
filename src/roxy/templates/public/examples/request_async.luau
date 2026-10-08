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
		const sent, response = pcall(function()
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
