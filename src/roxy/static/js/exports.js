/**
 * Downloads from the admin API: table exports and the LLM export (plan 14.5, 12.2, DESIGN.md 13.1 exports).
 *
 * What this is
 *   `downloadFrom(url)` fetches a file from the admin API and saves it under the name the server gives
 *   (`Content-Disposition`); `copyTextFrom(url)` fetches text and puts it on the clipboard. `initExports()` makes
 *   every `a[data-export]` link (the table macro's CSV and JSON menu) use `downloadFrom`.
 *
 * Why it exists
 *   A plain download link cannot react to the answer. The API builds at most two downloads at once per worker and
 *   answers 429 `rate_limited` with Retry-After beyond that, and cuts a file at 50,000 rows or 16 MiB, saying so in
 *   `Roxy-Export-Truncated: true` (JSON: `truncated`). The admin must hear both ("try again in a few seconds", "rows
 *   were left out"), not get an error page saved as a CSV file.
 *
 * How it works
 *   fetch with the session cookie (net.js `request`, same origin); on 200 the body becomes a Blob and an object URL
 *   clicked through a temporary `<a download>` (revoked right after); a toast says what happened. A 403 asking for a
 *   fresh second factor opens "Confirm it is you" and retries once.
 *
 * What to read next
 *   templates/components/table.html (the export menu), roxy/admin/api/common.py (`export_pages`).
 */

import { el } from "roxy/dom";
import { errorMessage, isReauthRequired, localAdminHref, request } from "roxy/net";
import { confirmIdentity } from "roxy/reauth";
import { toast } from "roxy/toast";

const FALLBACK_NAME = "roxy_export";
const MAX_NAME = 120;

function filenameOf(response) {
  const header = response.headers.get("Content-Disposition") || "";
  const match = /filename="?([^";]+)"?/i.exec(header);
  const name = match ? match[1] : FALLBACK_NAME;
  return name.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, MAX_NAME) || FALLBACK_NAME;
}

async function fetchOnce(url, accept) {
  let response = await request(url, { accept });
  if (response.status === 403) {
    const text = await response.clone().text().catch(() => "");
    if (isReauthRequired(403, response.headers.get("Roxy-Reauth"), text) && (await confirmIdentity())) {
      response = await request(url, { accept });
    }
  }
  return response;
}

async function explain(response) {
  if (response.status === 401) return;  // the session overlay is showing
  if (response.status === 429) {
    const wait = response.headers.get("Retry-After") || "a few";
    toast(`Two downloads are already being built. Try again in ${wait} seconds.`, { tone: "warn" });
    return;
  }
  const text = await response.text().catch(() => "");
  toast(errorMessage(text) || `The download was refused (${response.status}).`, { tone: "bad" });
}

/** Fetch `url` (a path under /admin) and save it as a file. Resolves true when a file was saved. */
export async function downloadFrom(url) {
  const target = localAdminHref(url);
  if (!target) return false;
  let response;
  try {
    response = await fetchOnce(target, "*/*");
  } catch {
    toast("Roxy could not be reached, so nothing was downloaded.", { tone: "bad" });
    return false;
  }
  if (!response.ok) {
    await explain(response);
    return false;
  }
  const blob = await response.blob();
  const name = filenameOf(response);
  const link = el("a", { href: URL.createObjectURL(blob), download: name, class: "sr-only" });
  document.body.append(link);
  link.click();
  window.setTimeout(() => {
    URL.revokeObjectURL(link.href);
    link.remove();
  }, 1000);
  const truncated = response.headers.get("Roxy-Export-Truncated") === "true";
  const rows = response.headers.get("Roxy-Export-Rows");
  if (truncated) {
    toast(`${name} is cut short: the file holds ${rows || "the first"} rows (the limit is 50,000 rows or 16 MiB). Narrow the filters for the rest.`, { tone: "warn" });
  } else {
    toast(`Downloaded ${name}${rows ? ` (${rows} rows)` : ""}.`, { tone: "ok" });
  }
  return true;
}

/** Fetch text from `url` and copy it (the palette's "Copy for LLM"). Resolves true when it was copied. */
export async function copyTextFrom(url) {
  const target = localAdminHref(url);
  if (!target) return false;
  let response;
  try {
    response = await fetchOnce(target, "text/plain");
  } catch {
    toast("Roxy could not be reached, so nothing was copied.", { tone: "bad" });
    return false;
  }
  if (!response.ok) {
    await explain(response);
    return false;
  }
  const text = await response.text();
  try {
    await navigator.clipboard.writeText(text);
    toast(`Copied ${text.length.toLocaleString("en-US")} characters for your assistant (IP addresses are hashed).`, { tone: "ok" });
    return true;
  } catch {
    toast("Copying is blocked in this browser; use Download instead.", { tone: "warn" });
    return false;
  }
}

export function initExports() {
  document.addEventListener("click", (event) => {
    const link = event.target instanceof Element ? event.target.closest("a[data-export]") : null;
    if (!link) return;
    event.preventDefault();
    const menu = link.closest("details[data-menu]");
    if (menu) menu.open = false;
    downloadFrom(link.getAttribute("href") || "");
  });
}
