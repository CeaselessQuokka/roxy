"""Browser challenge: a small proof-of-work page for browser clients with a high bot score (Tier 3, off by default).

What this is
    `make_challenge` (a signed, time-stamped puzzle bound to the client's IP and User-Agent), `verify_cookie` (checks
    a solved puzzle sent back in the `roxy_pow` cookie), `challenge_page` (the HTML page whose script solves the
    puzzle in the browser and reloads), and `solve` (the same search in Python, for tests). Plan 10.8.

Why it exists
    A scraper driving a real browser looks like a person to every header check. Making each fresh client spend a
    fraction of a second of CPU (about 0.3 s on a laptop at 18 bits) is invisible to a person but expensive for a
    farm of headless browsers. Roblox game servers cannot run JavaScript, so the challenge is only ever shown to
    requests classified as browsers (`is_browser`), and only when `challenge_enabled` is on.

How it works
    - Puzzle: `<issued_at>.<bits>.<random>.<signature>`; the signature is HMAC-SHA256 (a key derived from the
      `ip_hash_key` credential) over the puzzle text, the client IP and a hash of the User-Agent, so a solved puzzle
      cannot be replayed from another address or browser.
    - Solution: a number `n` such that SHA-256 of `<puzzle>:<n>` starts with `bits` zero bits. The page's script finds
      it with `crypto.subtle` (available on https), stores `roxy_pow=<puzzle>~<n>` as a cookie valid for
      `challenge_cookie_minutes`, and reloads. The check verifies signature, age, binding and the zero bits.
    - The page's script carries the per-response CSP nonce (the router passes `req.csp_nonce`); the response must use
      the page CSP, not the proxied-content CSP.

What to read next
    `roxy/abuse/bot.py` (the score that triggers it), then `roxy/abuse/checks/challenge.py`.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import secrets
from typing import Final

from roxy.abuse.bans import ua_hash
from roxy.abuse.messages import CHALLENGE_TITLE
from roxy.core.iphash import derived_key

COOKIE_NAME: Final = "roxy_pow"
SIGNATURE_HEX: Final = 32
MAX_COOKIE_LENGTH: Final = 300
MAX_SOLVE_ATTEMPTS: Final = 1 << 30


def challenge_key(ip_hash_key: bytes) -> bytes:
    """The HMAC key for puzzles, derived from the `ip_hash_key` credential (never used directly)."""
    return derived_key(ip_hash_key, "challenge")


def _sign(key: bytes, puzzle: str, client_ip: str, user_agent: str) -> str:
    message = f"{puzzle}|{client_ip}|{ua_hash(user_agent)}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:SIGNATURE_HEX]


def make_challenge(key: bytes, *, client_ip: str, user_agent: str, now: float, bits: int) -> str:
    """A new signed puzzle for this client."""
    puzzle = f"{int(now)}.{int(bits)}.{secrets.token_hex(8)}"
    return f"{puzzle}.{_sign(key, puzzle, client_ip, user_agent)}"


def leading_zero_bits(digest: bytes) -> int:
    """How many leading zero bits `digest` has."""
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        return count + (8 - byte.bit_length())
    return count


def _work(challenge: str, nonce: int) -> bytes:
    return hashlib.sha256(f"{challenge}:{nonce}".encode()).digest()


def solve(challenge: str, bits: int) -> int:
    """Find a solution in Python (tests and tooling; the browser does the same in JavaScript)."""
    for nonce in range(MAX_SOLVE_ATTEMPTS):
        if leading_zero_bits(_work(challenge, nonce)) >= bits:
            return nonce
    raise RuntimeError("no solution found")


def verify_cookie(
    key: bytes,
    cookie_value: str | None,
    *,
    client_ip: str,
    user_agent: str,
    now: float,
    max_age_s: float,
    min_bits: int,
) -> bool:
    """Whether `roxy_pow` holds a solved, unexpired puzzle issued to this IP and User-Agent."""
    if not cookie_value or len(cookie_value) > MAX_COOKIE_LENGTH or "~" not in cookie_value:
        return False
    challenge, _, nonce_text = cookie_value.partition("~")
    parts = challenge.split(".")
    if len(parts) != 4 or not nonce_text.isdigit():
        return False
    issued_text, bits_text, _rand, signature = parts
    if not issued_text.isdigit() or not bits_text.isdigit():
        return False
    puzzle = ".".join(parts[:3])
    if not hmac.compare_digest(signature, _sign(key, puzzle, client_ip, user_agent)):
        return False
    issued, bits = int(issued_text), int(bits_text)
    if bits < min_bits or not (0 <= now - issued <= max_age_s):
        return False
    return leading_zero_bits(_work(challenge, int(nonce_text))) >= bits


def cookie_from_header(cookie_header: str | None, name: str = COOKIE_NAME) -> str | None:
    """The value of cookie `name` in a `Cookie` header, or None."""
    for part in (cookie_header or "").split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            return value.strip()
    return None


def challenge_page(challenge: str, bits: int, *, max_age_s: int, nonce: str | None) -> str:
    """The HTML page that solves the puzzle and reloads. Every interpolated value is escaped."""
    nonce_attr = f' nonce="{html.escape(nonce, quote=True)}"' if nonce else ""
    data = html.escape(challenge, quote=True)
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(CHALLENGE_TITLE)}</title></head>\n"
        f"<body><main><h1>{html.escape(CHALLENGE_TITLE)}</h1>"
        "<p>This takes a moment and happens once. Please keep this page open.</p>"
        f'<p id="pow" data-challenge="{data}" data-bits="{int(bits)}" data-age="{int(max_age_s)}"></p>'
        "<noscript><p>Enable JavaScript to continue.</p></noscript></main>\n"
        f"<script{nonce_attr}>\n"
        "(async () => {\n"
        '  const el = document.getElementById("pow");\n'
        "  const challenge = el.dataset.challenge, bits = Number(el.dataset.bits);\n"
        "  const enc = new TextEncoder();\n"
        "  const zeroBits = (buf) => { let n = 0; for (const b of new Uint8Array(buf)) {\n"
        "    if (b === 0) { n += 8; continue; } return n + Math.clz32(b) - 24; } return n; };\n"
        "  for (let i = 0; ; i++) {\n"
        '    const digest = await crypto.subtle.digest("SHA-256", enc.encode(challenge + ":" + i));\n'
        "    if (zeroBits(digest) >= bits) {\n"
        f'      document.cookie = "{COOKIE_NAME}=" + challenge + "~" + i + "; Path=/; Max-Age=" + el.dataset.age +\n'
        '        "; SameSite=Lax; Secure";\n'
        "      location.reload(); return;\n"
        "    }\n"
        "  }\n"
        "})();\n"
        "</script></body></html>\n"
    )


__all__ = [
    "COOKIE_NAME",
    "challenge_key",
    "challenge_page",
    "cookie_from_header",
    "leading_zero_bits",
    "make_challenge",
    "solve",
    "verify_cookie",
]
