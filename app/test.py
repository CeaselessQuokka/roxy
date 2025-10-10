# avatar.roblox.com/v2/avatar/users/1311979334/outfits
import re


def validate_url_old(url: str) -> bool:
    return re.match(r"\w+\.roblox\.com", url, re.IGNORECASE) != None


def validate_url(url: str) -> bool:
    return re.match(r"^[a-z]+\.roblox\.com/", url, re.IGNORECASE) != None
