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
