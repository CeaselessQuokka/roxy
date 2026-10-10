/**
 * Inline settings saved through the settings API: review, save, second factor, re-render (plan 14.1, 15.2, 15.6).
 *
 * What this is
 *   `initSettingsApi()` handles every setting control in API mode (`form[data-setting-api]`, built by
 *   templates/components/setting.html from `roxy.admin.pages.inline`): the first Save shows the review, the second
 *   saves; and when the event stream says `settings_changed`, every control that holds no unsaved edit is
 *   re-rendered from the server so it shows the value now in force.
 *
 * Why it exists
 *   Plan 15.2: a change is reviewed before it is saved (old value, new value, what happens, risk), high-risk values
 *   need a reason and a confirmation, and admin security, credential and a few other settings need a fresh second
 *   factor. The settings API already enforces every one of these rules; this module makes them a smooth flow on any
 *   card instead of a refused request.
 *
 * How it works
 *   1. Review: `POST /admin/api/v1/settings/preview` with `{changes: {key: text}}` (the text exactly as typed; the
 *      catalog parses "15m" and "64 MiB" on the server). The answer's item for the key is shown in the control's
 *      `[data-setting-review]` region (before, after, the consequence, the risk), and the button becomes "Save".
 *      Changing the value again goes back to Review.
 *   2. Second factor: when the control is marked `data-fresh-mfa` and `GET /auth/session` says the factor is not
 *      fresh, "Confirm it is you" opens first (reauth.js).
 *   3. Save: `PUT /admin/api/v1/settings/{key}` with `{value, reason, confirm_high_risk}`. A 403 `reauth_required`
 *      asks for the code and retries once; a 422 shows the server's message on the control (`setting-error` event,
 *      handled by the `settingControl` Alpine component; `confirmation_required` reveals the confirmation).
 *   4. After a save the control is replaced by `GET data-setting-fragment?saved=1` (the value as stored, the "Saved"
 *      mark, the new last-change line), and a toast says so.
 *
 * What to read next
 *   templates/components/setting.html, static/js/components.js (`settingControl`), roxy/admin/api/settings.py.
 */

import htmx from "roxy/htmx_setup";
import { el, qs, qsa } from "roxy/dom";
import { errorMessage, getJSON, isReauthRequired, postJSON, request } from "roxy/net";
import { confirmIdentity } from "roxy/reauth";
import { toast } from "roxy/toast";

const PREVIEW_URL = "/admin/api/v1/settings/preview";
const SESSION_URL = "/admin/api/v1/auth/session";
const MAX_ERROR_TEXT = 4096;
const REFRESH_GAP_MS = 1000;
const reviewed = new WeakMap();  // form -> the value text its shown review is about
let lastRefresh = 0;

function currentText(form) {
  const input = qs("[data-setting-input]", form);
  if (!input) return "";
  if (input.type === "checkbox") return input.checked ? "1" : "0";
  return input.value;
}

function serverError(form, message, code = "") {
  form.dispatchEvent(new CustomEvent("setting-error", { detail: { message, code } }));
}

function label(form, text) {
  const node = qs("[data-setting-submit-label]", form);
  if (node) node.textContent = text;
}

function showReview(form, item) {
  const box = qs("[data-setting-review]", form);
  if (!box) return;
  const rows = [
    el("p", { class: "setting__review-title", text: "Review this change" }),
    el("dl", { class: "kv setting__review-list" }, [
      el("dt", { text: "Now" }), el("dd", { text: display(item.current) }),
      el("dt", { text: "After saving" }), el("dd", { text: display(item.new) }),
    ]),
  ];
  if (item.consequence) rows.push(el("p", { class: "setting__review-what", text: item.consequence }));
  if (item.high_risk_reason) rows.push(el("p", { class: "setting__review-risk", text: `High risk: ${item.high_risk_reason}` }));
  if (item.restart_needed) rows.push(el("p", { class: "muted", text: "This takes effect after the next restart." }));
  box.replaceChildren(...rows);
  box.hidden = false;
}

function display(value) {
  if (value === null || value === undefined) return "not set";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "empty";
  return String(value);
}

function resetReview(form) {
  reviewed.delete(form);
  const box = qs("[data-setting-review]", form);
  if (box) {
    box.replaceChildren();
    box.hidden = true;
  }
  label(form, "Review");
}

async function readError(response) {
  const text = (await response.text().catch(() => "")).slice(0, MAX_ERROR_TEXT);
  let code = "";
  let fields = {};
  try {
    const parsed = JSON.parse(text);
    code = parsed && parsed.error && typeof parsed.error.code === "string" ? parsed.error.code : "";
    fields = parsed && parsed.error && parsed.error.fields && typeof parsed.error.fields === "object" ? parsed.error.fields : {};
  } catch {
    /* not JSON */
  }
  return { code, fields, message: errorMessage(text) || `The server refused this (${response.status}).` };
}

async function review(form, key, text) {
  let response;
  try {
    response = await postJSON(PREVIEW_URL, { changes: { [key]: text } });
  } catch {
    serverError(form, "Roxy could not be reached. Nothing was saved; try again.");
    return;
  }
  if (!response.ok) {
    if (response.status === 401) return;
    const error = await readError(response);
    serverError(form, error.fields[key] || error.message, error.code);
    return;
  }
  const answer = await response.json().catch(() => null);
  const item = answer && Array.isArray(answer.items) ? answer.items.find((entry) => entry.key === key) : null;
  if (!item || item.status === "invalid" || item.status === "unknown") {
    serverError(form, (item && item.message) || "The server could not check this value.");
    return;
  }
  const cross = answer.cross && answer.cross.length ? answer.cross[0].message : "";
  if (cross) {
    serverError(form, cross);
    return;
  }
  if (item.status === "unchanged") {
    serverError(form, "This is already the value in force; there is nothing to save.");
    return;
  }
  showReview(form, item);
  reviewed.set(form, text);
  label(form, "Save");
}

async function freshEnough() {
  try {
    const session = await getJSON(SESSION_URL);
    return Boolean(session && session.Fresh);
  } catch {
    return false;
  }
}

async function save(form, key, text, { retried = false } = {}) {
  const data = new FormData(form);
  const body = {
    value: text,
    reason: String(data.get("reason") || "").trim(),
    confirm_high_risk: data.get("confirm_high_risk") === "1",
  };
  let response;
  try {
    response = await request(form.dataset.settingApi, {
      method: "PUT",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    serverError(form, "Roxy could not be reached. Nothing was saved; try again.");
    return;
  }
  if (response.ok) {
    await rerender(form, true);
    toast(`${form.dataset.label || key} saved. Every worker uses it within a second.`, { tone: "ok" });
    return;
  }
  if (response.status === 401) return;
  if (!retried && response.status === 403) {
    const textBody = await response.clone().text().catch(() => "");
    if (isReauthRequired(403, response.headers.get("Roxy-Reauth"), textBody)) {
      if (await confirmIdentity()) {
        await save(form, key, text, { retried: true });
        return;
      }
      serverError(form, "Nothing was saved: this setting needs your second factor.");
      return;
    }
  }
  const error = await readError(response);
  serverError(form, error.fields[key] || error.fields.reason || error.message, error.code);
}

/** Replace a control with the server's rendering of it (`saved` adds the "Saved" mark). */
export function rerender(form, saved = false) {
  const src = form.dataset.settingFragment;
  if (!src) return Promise.resolve();
  const url = `${src}${src.includes("?") ? "&" : "?"}saved=${saved ? 1 : 0}`;
  return htmx.ajax("GET", url, { target: form, swap: "outerHTML", source: form });
}

async function onSubmit(form) {
  const key = form.dataset.settingKey;
  if (!key || form.getAttribute("aria-busy") === "true") return;
  const text = currentText(form);
  form.setAttribute("aria-busy", "true");
  try {
    if (reviewed.get(form) !== text) {
      await review(form, key, text);
      return;
    }
    if ("freshMfa" in form.dataset && !(await freshEnough())) {
      if (!(await confirmIdentity())) {
        serverError(form, "Nothing was saved: this setting needs your second factor.");
        return;
      }
    }
    await save(form, key, text);
  } finally {
    form.removeAttribute("aria-busy");
  }
}

/** After `settings_changed`: re-render every API-mode control without an unsaved edit (others are marked stale). */
function refreshAll() {
  const now = performance.now();
  if (now - lastRefresh < REFRESH_GAP_MS) return;
  lastRefresh = now;
  for (const form of qsa("form[data-setting-api]")) {
    if (form.hasAttribute("data-dirty") || form.contains(document.activeElement)) {
      form.dataset.stale = "1";
      continue;
    }
    rerender(form, false);
  }
}

export function initSettingsApi() {
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("form[data-setting-api]")) return;
    event.preventDefault();
    onSubmit(form);
  }, true);
  // Editing again after a review goes back to "Review": the review must match the value that is saved.
  document.addEventListener("input", (event) => {
    const form = event.target instanceof Element ? event.target.closest("form[data-setting-api]") : null;
    if (form && reviewed.has(form) && reviewed.get(form) !== currentText(form)) resetReview(form);
  });
  document.addEventListener("change", (event) => {
    const form = event.target instanceof Element ? event.target.closest("form[data-setting-api]") : null;
    if (form && reviewed.has(form) && reviewed.get(form) !== currentText(form)) resetReview(form);
  });
  document.addEventListener("click", (event) => {
    const cancel = event.target instanceof Element ? event.target.closest("form[data-setting-api] .setting__buttons .btn--ghost") : null;
    if (cancel) resetReview(cancel.closest("form"));
  });
  document.addEventListener("roxy:sse:settings_changed", refreshAll);
}
