/**
 * Requests to Roxy's own admin API from scripts (htmx requests are configured separately in htmx_setup.js).
 *
 * What this is
 *   `csrfToken()` reads the token from `<meta name="csrf-token">` and `setCsrfToken()` replaces it; `request(url,
 *   options)` is `fetch` with Roxy's rules applied; `getJSON(url)`, `postJSON(url, data)` and `postForm(url,
 *   fields)` are the shapes the modules need. `isReauthRequired()` and `signalReauth()` handle the "confirm it is
 *   you" answer, and `localAdminHref()` decides whether a link from data may be followed.
 *
 * Why it exists
 *   Plan 9.6: every state-changing request carries the CSRF token in the X-CSRF-Token header. The server embeds
 *   the token XOR-masked with a fresh random pad in each response (BREACH defense), so scripts send back exactly
 *   what the meta tag holds and the server unmasks it; the token never appears in a URL. Any answer of 401 means
 *   the session is over: one event (`roxy:unauthorized`) tells static/js/session.js to show the expired overlay,
 *   so no module needs its own copy of that logic (parity row 119).
 *   The session, and with it the CSRF secret, rotates when the admin re-authenticates for a sensitive action
 *   (`POST /admin/api/v1/auth/reauth` answers a new `CsrfToken`). A page that kept the old token would see every
 *   later write refused, so the token can be replaced in place: `setCsrfToken(token)` from a script, or the
 *   server's `HX-Trigger: {"roxy:csrf": {"token": "..."}}` header on any htmx answer (htmx_setup.js).
 *   A 403 that asks for a fresh second factor (`Roxy-Reauth: required`, or the JSON error code `reauth_required`
 *   of DESIGN.md 13) is not a CSRF failure: reloading would not help. It raises a cancelable `roxy:reauth` event;
 *   the page's re-authentication dialog (P11 part two) handles it and calls preventDefault, and when nothing does,
 *   the admin is told what is needed instead of "reload".
 *
 * How it works
 *   Same-origin only (relative URLs, `credentials: "same-origin"`, `redirect: "error"` so a redirect to a login page
 *   is never mistaken for data). Safe methods (GET, HEAD) skip the CSRF header; everything else gets it. A link
 *   that came from a server answer (palette search results) is followed only when it resolves to this origin and
 *   to a path under /admin: a compromised or confused data source can then never send the admin elsewhere.
 *
 * What to read next
 *   static/js/session.js (who listens for roxy:unauthorized), static/js/htmx_setup.js (the htmx side).
 */

const MAX_TOKEN_LENGTH = 512;
const MAX_ERROR_BODY = 4096;

export function csrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") || "" : "";
}

/** Replace the page's CSRF token (after a session rotation). Returns whether the value was accepted. */
export function setCsrfToken(token) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_\-+/=.]+$/.test(token) || token.length > MAX_TOKEN_LENGTH) {
    return false;
  }
  let meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta) {
    meta = document.createElement("meta");
    meta.setAttribute("name", "csrf-token");
    document.head.append(meta);
  }
  meta.setAttribute("content", token);
  return true;
}

export function signalUnauthorized(source) {
  document.dispatchEvent(new CustomEvent("roxy:unauthorized", { detail: { source } }));
}

/** True when a 403 answer asks for a fresh second factor (header or JSON error code), not a CSRF failure. */
export function isReauthRequired(status, headerValue, bodyText) {
  if (status !== 403) return false;
  if (String(headerValue || "").trim().toLowerCase() === "required") return true;
  if (!bodyText || bodyText.length > MAX_ERROR_BODY) return false;
  try {
    const data = JSON.parse(bodyText);
    return Boolean(data && data.error && data.error.code === "reauth_required");
  } catch {
    return false;
  }
}

/** Raise `roxy:reauth`; returns true when a listener (the re-auth dialog) took it over with preventDefault. */
export function signalReauth(source, detail = {}) {
  const event = new CustomEvent("roxy:reauth", { cancelable: true, detail: { source, ...detail } });
  return !document.dispatchEvent(event);
}

/** The plain-English message of an error answer: `{"error": {"message"}}`, a JSON string, or short text. */
export function errorMessage(bodyText) {
  const text = String(bodyText || "").slice(0, MAX_ERROR_BODY);
  try {
    const data = JSON.parse(text);
    if (typeof data === "string") return data.slice(0, 300);
    if (data && data.error && typeof data.error.message === "string") return data.error.message.slice(0, 300);
    if (data && typeof data.detail === "string") return data.detail.slice(0, 300);
    return "";
  } catch {
    return text.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
  }
}

/** `href` as a same-origin path under /admin, or null when it points anywhere else (or is not a URL). */
export function localAdminHref(href) {
  if (typeof href !== "string" || href === "") return null;
  let url;
  try {
    url = new URL(href, window.location.href);
  } catch {
    return null;
  }
  if (url.origin !== window.location.origin) return null;
  if (!/^\/admin(?:[/?#]|$)/.test(url.pathname)) return null;
  return url.pathname + url.search + url.hash;
}

/** fetch() for the admin API: same origin, CSRF header on writes, 401 and re-auth answers reported once. */
export async function request(url, { method = "GET", body, headers = {}, signal, accept = "application/json" } = {}) {
  const upper = method.toUpperCase();
  const finalHeaders = { Accept: accept, ...headers };
  if (upper !== "GET" && upper !== "HEAD") {
    const token = csrfToken();
    if (token) finalHeaders["X-CSRF-Token"] = token;
  }
  const response = await fetch(url, {
    method: upper,
    body,
    headers: finalHeaders,
    credentials: "same-origin",
    redirect: "error",
    cache: "no-store",
    signal,
  });
  if (response.status === 401) signalUnauthorized(url);
  if (response.status === 403) {
    // Read a copy of the body, so the caller can still read the original.
    const text = await response.clone().text().catch(() => "");
    if (isReauthRequired(403, response.headers.get("Roxy-Reauth"), text)) signalReauth("fetch", { url, method: upper });
  }
  return response;
}

export async function getJSON(url, options = {}) {
  const response = await request(url, options);
  if (!response.ok) throw new Error(`${url} answered ${response.status}`);
  return response.json();
}

/** POST a JSON object (the admin API rejects a missing or malformed body with 400, plan 9.6). */
export async function postJSON(url, data = {}, options = {}) {
  return request(url, {
    ...options,
    method: "POST",
    body: JSON.stringify(data),
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
}

export async function postForm(url, fields = {}, options = {}) {
  const body = new URLSearchParams();
  for (const [name, value] of Object.entries(fields)) body.append(name, String(value));
  return request(url, { ...options, method: "POST", body });
}
