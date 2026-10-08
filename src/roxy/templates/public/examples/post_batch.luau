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

-- Header names can arrive in any letter case, so compare them in lower case.
local function getHeader(headers: { [string]: string }, name: string): string?
	local wanted = string.lower(name)
	for key, value in headers do
		if string.lower(key) == wanted then
			return value
		end
	end
	return nil
end

-- Retry-After when it is a usable number, otherwise the fallback, plus random jitter.
local function retryWaitSeconds(headers: { [string]: string }): number
	local retryAfter = tonumber(getHeader(headers, "Retry-After"))
	local seconds = if retryAfter and retryAfter >= 0 then retryAfter else FALLBACK_WAIT_SECONDS
	return seconds + math.random() * MAX_JITTER_SECONDS
end

local function lookUpUsers(usernames: { string }): { UserByName }?
	local request: UsernamesRequest = { usernames = usernames, excludeBannedUsers = true }
	local body = HttpService:JSONEncode(request)
	for attempt = 1, MAX_ATTEMPTS do
		local sent, response = pcall(function()
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
			local decoded, result = pcall(function(): UsernamesResponse
				return HttpService:JSONDecode(response.Body or "")
			end)
			if not decoded then
				warn("The answer was not valid JSON:", result)
				return nil
			end
			return result.data
		elseif response.StatusCode == 429 or response.StatusCode == 503 then
			local waitSeconds = retryWaitSeconds(response.Headers)
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

local users = lookUpUsers({ "Roblox", "builderman" })
if users then
	for _, user in users do
		print(`{user.requestedUsername} is user {user.id} ({user.displayName})`)
	end
end
