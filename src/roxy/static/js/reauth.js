/**
 * "Confirm it is you": a fresh second factor for sensitive actions, then one retry (plan 9.6, DESIGN.md 13.1).
 *
 * What this is
 *   `confirmIdentity()` opens the dialog of templates/admin/_layout/reauth.html and resolves true once the server
 *   accepted a code (false when the admin cancels). `initReauth()` listens for the `roxy:reauth` event that net.js
 *   and htmx_setup.js raise for a 403 `reauth_required` answer, takes it over (preventDefault), and retries an htmx
 *   request after a successful code. Scripts that use `request()` retry themselves: they `await confirmIdentity()`
 *   (the same pending promise, so one dialog serves both) and send their request again.
 *
 * Why it exists
 *   Settings of admin security and the credential, full exports, passkeys and the credential replace need a second
 *   factor entered within `admin_reauth_window_s`. Without this dialog the admin would see "refused" and have to
 *   find a way to re-authenticate; with it, the change they asked for happens right after the code.
 *
 * How it works
 *   `POST /admin/api/v1/auth/reauth` with `{method: "totp" | "recovery", code}` and the CSRF header. A 200 answer
 *   rotates the session and carries a new masked `CsrfToken`, which replaces the page's token at once (net.js
 *   `setCsrfToken`), so the retried request is accepted. A wrong code is the uniform 404 of every second factor
 *   failure; a 429 is the lockout. The dialog opens on top of an open dialog without closing it (dialog.js), so a
 *   half-filled form survives.
 *
 * What to read next
 *   static/js/net.js (`signalReauth`), static/js/api_forms.js and static/js/settings_api.js (the retrying callers).
 */

import htmx from "roxy/htmx_setup";
import { qs } from "roxy/dom";
import { closeDialog, openDialog } from "roxy/dialog";
import { errorMessage, postJSON, setCsrfToken } from "roxy/net";
import { toast } from "roxy/toast";

let pending = null;
let resolvePending = null;

function dialogEl() {
  return document.getElementById("reauth");
}

function finish(ok) {
  const resolve = resolvePending;
  pending = null;
  resolvePending = null;
  const dialog = dialogEl();
  if (dialog && dialog.open) closeDialog(dialog);
  if (resolve) resolve(ok);
}

/** Ask for a fresh second factor; resolves true when the server accepted one, false when the admin canceled. */
export function confirmIdentity() {
  if (pending) return pending;
  const dialog = dialogEl();
  if (!dialog) return Promise.resolve(false);
  pending = new Promise((resolve) => {
    resolvePending = resolve;
  });
  const form = qs("[data-reauth-form]", dialog);
  if (form) form.reset();
  const error = qs("[data-reauth-error]", dialog);
  if (error) error.hidden = true;
  openDialog(dialog);
  const code = qs("#reauth-code", dialog);
  if (code) code.focus();
  return pending;
}

async function submit(form) {
  const dialog = dialogEl();
  const error = qs("[data-reauth-error]", dialog);
  const data = new FormData(form);
  const code = String(data.get("code") || "").replace(/\s+/g, "");
  const method = data.get("method") === "recovery" ? "recovery" : "totp";
  const show = (text) => {
    if (!error) return;
    error.textContent = text;
    error.hidden = false;
  };
  if (!code) {
    show("Enter the code first.");
    return;
  }
  let response;
  try {
    response = await postJSON(dialog.dataset.reauthUrl || "/admin/api/v1/auth/reauth", { method, code });
  } catch {
    show("Roxy could not be reached. Check the connection and try again.");
    return;
  }
  if (response.ok) {
    const body = await response.json().catch(() => ({}));
    if (body && typeof body.CsrfToken === "string") setCsrfToken(body.CsrfToken);
    toast("Confirmed. Carrying on with what you asked.", { tone: "ok" });
    finish(true);
    return;
  }
  if (response.status === 401) {
    finish(false);  // the session ended: net.js already raised roxy:unauthorized
    return;
  }
  const text = await response.text().catch(() => "");
  if (response.status === 404) show("That code did not work. Check that your phone's clock is right, then try a new code.");
  else if (response.status === 429) show(errorMessage(text) || "Too many attempts; wait a moment before trying again.");
  else show(errorMessage(text) || `The server refused this (${response.status}).`);
}

export function initReauth() {
  const dialog = dialogEl();
  if (!dialog) return;
  const form = qs("[data-reauth-form]", dialog);
  if (form) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      submit(form);
    });
  }
  dialog.addEventListener("click", (event) => {
    if (event.target instanceof Element && event.target.closest("[data-reauth-cancel]")) finish(false);
  });
  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();  // Escape: resolve the promise as canceled, then close
    finish(false);
  });
  dialog.addEventListener("close", () => {
    if (pending) finish(false);  // closed another way (a click on the backdrop): the action stays undone
  });
  // A 403 `reauth_required` anywhere: ask once, then retry an htmx request (fetch callers retry themselves).
  document.addEventListener("roxy:reauth", (event) => {
    event.preventDefault();
    const detail = event.detail || {};
    confirmIdentity().then((ok) => {
      if (detail.source !== "htmx") return;  // a script that used request() retries (or reports) by itself
      if (!ok) {
        toast("Nothing was changed: the action needs your second factor.", { tone: "warn" });
        return;
      }
      if (detail.elt instanceof Element && detail.verb && detail.path) {
        htmx.ajax(String(detail.verb).toUpperCase(), detail.path, { source: detail.elt });
      }
    });
  });
}
