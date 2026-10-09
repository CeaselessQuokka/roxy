"""The webhook channel: the same alert fields as the email, POSTed as JSON to the owner's webhook URL.

What this is
    `load_webhook_url(credentials_dir)` and `WebhookSender.send(payload)`.

Why it exists
    Owner decision D14: a webhook (for example a Discord channel) reaches a phone instantly. The URL is a bearer
    secret (anyone holding it can post), so it is a systemd credential (`alert_webhook_url`), never a setting or
    an environment variable, and it is registered with the log redaction filter as soon as it is read.

How it works
    - httpx with `trust_env=False`: proxy variables and `.netrc` in the environment are ignored, so an alert can
      never be routed through some proxy the environment happens to name (the same rule as every Roxy client).
    - The TLS context comes from `egress.metering.tls_context`, the one the egress clients use: httpx's certifi
      bundle with the key log switched off, because CPython copies `SSLKEYLOGFILE` into every default context
      whatever `trust_env` says, and those session keys protect the URL's token (review finding cred-6).
    - Redirects are not followed (a redirect could send the payload somewhere else), the timeout is short, and
      any status other than 2xx is a failure.
    - Only https URLs are accepted, plus http to a loopback address (a local relay; tests).
    - The JSON body carries `content` and `text` (what Discord and Slack display) plus every structured field.

What to read next
    `roxy/notify/notifier.py` (where the payload is built and the channel is chosen).
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from roxy.core.redact import SecretRegistry
from roxy.egress.metering import tls_context

log = logging.getLogger("roxy.notify.webhook")

URL_CREDENTIAL = "alert_webhook_url"
TIMEOUT_S = 10.0


class WebhookError(RuntimeError):
    """The webhook did not accept the alert."""


def acceptable_url(url: str) -> bool:
    """https anywhere, or http only to a loopback address."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme == "https" and parts.hostname:
        return True
    if parts.scheme == "http" and parts.hostname:
        host = parts.hostname
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False
    return False


def load_webhook_url(credentials_dir: Path | None) -> str | None:
    """The webhook URL, or None when the credential is missing or not an acceptable URL."""
    if credentials_dir is None:
        return None
    try:
        url = (credentials_dir / URL_CREDENTIAL).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not url:
        return None
    SecretRegistry.register(URL_CREDENTIAL, url)
    if not acceptable_url(url):
        log.warning("webhook_url_rejected", extra={"fields": {"reason": "https only (http only for loopback)"}})
        return None
    return url


class WebhookSender:
    """POSTs alert payloads to one URL."""

    def __init__(self, url: str, *, client: httpx.AsyncClient | None = None, timeout_s: float = TIMEOUT_S) -> None:
        self._url = url
        self._own_client = client is None
        # trust_env=False: never pick up HTTPS_PROXY or .netrc from the environment; `tls_context` never logs keys.
        self._client = client or httpx.AsyncClient(
            trust_env=False, follow_redirects=False, timeout=timeout_s, verify=tls_context(True)
        )

    def __repr__(self) -> str:
        return "WebhookSender(<url hidden>)"

    async def send(self, payload: dict[str, Any]) -> None:
        try:
            response = await self._client.post(self._url, json=payload)
        except httpx.HTTPError as exc:
            raise WebhookError(type(exc).__name__) from exc
        if not 200 <= response.status_code < 300:
            raise WebhookError(f"HTTP {response.status_code}")

    async def aclose(self) -> None:
        if self._own_client:
            await self._client.aclose()
