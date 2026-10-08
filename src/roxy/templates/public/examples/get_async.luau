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
