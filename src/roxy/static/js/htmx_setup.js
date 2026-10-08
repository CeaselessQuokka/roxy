/**
 * htmx configuration for the dashboard (plan 9.2, 9.6, 14.10).
 *
 * What this is
 *   Imports the vendored htmx module, applies Roxy's security settings before htmx processes the page, adds the
 *   X-CSRF-Token header to every htmx request, takes a refreshed token from the server, and turns failed requests
 *   into a session overlay (401), a re-authentication request (403 asking for a fresh second factor) or a toast.
 *
 * Why it exists
 *   Under the strict CSP (nonce plus 'strict-dynamic', no 'unsafe-eval'), htmx must never evaluate strings:
 *   `allowEval = false` disables `hx-on`, `js:` values and event filters with code, so markup can only ask for
 *   server fragments. Fragments never carry <script> (`allowScriptTags = false`), htmx does not inject its own
 *   <style> (`includeIndicatorStyles = false`; the indicator rules are in components.css), and settling never
 *   copies a `style` attribute (setting it would be an inline style the CSP refuses). The page history cache is
 *   off: admin pages are `Cache-Control: no-store` (plan 9.3), so htmx must not keep copies in localStorage.
 *
 * How it works
 *   ES module evaluation order guarantees this runs after htmx's module body (which only schedules its start) and
 *   before DOMContentLoaded, when htmx reads its config. The CSRF token is read at request time from the meta tag,
 *   so a rotated token is honored at once: the server sends it as `HX-Trigger: {"roxy:csrf": {"token": "..."}}`
 *   (htmx raises that event for any status) and net.js `setCsrfToken` stores it. A 422 answer is swapped (the
 *   server re-renders a form with its validation errors); other 4xx and 5xx answers are not swapped. A 403 that
 *   asks for a fresh second factor raises `roxy:reauth` (net.js) instead of the generic "refused" toast. Requests
 *   made from inside a dialog (a dialog form, the drawer) report their errors inside that dialog (dialog.js).
 *
 * What to read next
 *   static/js/net.js (the same rules for fetch), static/js/session.js, static/js/dialog.js.
 */

import htmx from "vendor/htmx";
import { csrfToken, isReauthRequired, setCsrfToken, signalReauth, signalUnauthorized } from "roxy/net";
import { toast } from "roxy/toast";

const nonceSource = document.querySelector("script[nonce]");
const nonce = nonceSource ? nonceSource.nonce : "";

Object.assign(htmx.config, {
  allowEval: false,
  allowScriptTags: false,
  includeIndicatorStyles: false,
  inlineScriptNonce: nonce,
  inlineStyleNonce: nonce,
  historyCacheSize: 0,
  refreshOnHistoryMiss: true,
  selfRequestsOnly: true,
  withCredentials: false,
  attributesToSettle: ["class", "width", "height"],
  defaultSwapStyle: "innerHTML",
  scrollIntoViewOnBoost: false,
  responseHandling: [
    { code: "204", swap: false },
    { code: "[23]..", swap: true },
    { code: "422", swap: true, error: false },
    { code: "[45]..", swap: false, error: true },
  ],
});

document.addEventListener("htmx:configRequest", (event) => {
  const token = csrfToken();
  if (token) event.detail.headers["X-CSRF-Token"] = token;
});

// The server rotated the session (re-authentication): `HX-Trigger: {"roxy:csrf": {"token": "..."}}`.
document.addEventListener("roxy:csrf", (event) => {
  const detail = event.detail || {};
  setCsrfToken(typeof detail === "string" ? detail : detail.token ?? detail.value);
});

function inDialog(elt) {
  return elt instanceof Element && Boolean(elt.closest("dialog"));
}

document.addEventListener("htmx:responseError", (event) => {
  const xhr = event.detail.xhr;
  const status = xhr ? xhr.status : 0;
  if (status === 401) {
    signalUnauthorized("htmx");
    return;
  }
  if (xhr && isReauthRequired(status, xhr.getResponseHeader("Roxy-Reauth"), xhr.responseText)) {
    const config = event.detail.requestConfig || {};
    const handled = signalReauth("htmx", { verb: config.verb, path: config.path, elt: event.detail.elt });
    if (!handled && !inDialog(event.detail.elt)) {
      toast("This action needs your second factor again: confirm it is you, then try again. Nothing was changed.", {
        tone: "warn",
      });
    }
    return;
  }
  // Dialog forms and the drawer show the error inside the dialog (static/js/dialog.js).
  if (inDialog(event.detail.elt)) return;
  toast(
    status === 403
      ? "That action was refused (403). Reload the page and try again."
      : `The server could not complete that (${status || "no answer"}). Nothing was changed.`,
    { tone: "bad" },
  );
});

document.addEventListener("htmx:sendError", (event) => {
  if (inDialog(event.detail && event.detail.elt)) return;  // shown inside the dialog (dialog.js)
  toast("Roxy could not be reached. Check the connection and try again.", { tone: "bad" });
});

export default htmx;
