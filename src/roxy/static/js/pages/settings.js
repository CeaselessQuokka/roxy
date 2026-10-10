/**
 * The Settings page's own script (templates/admin/pages/settings*): the editor's filters and pages, batch saves,
 * and the import (plan 15.2).
 *
 * What this is
 *   1. Filters and pages: the editor's filter form asks its fragment with htmx (only the results are swapped); this
 *      script resets to page 1 when a filter changes, moves between pages and page sizes, keeps the view in the
 *      address bar (replaceState, values equal to their default left out), and announces the new count.
 *   2. Batch edit: every setting edited in the editor and not yet saved is remembered (also across pages of
 *      results). "Review all changes" opens a dialog with the server's preview of the batch (`POST
 *      /admin/api/v1/settings/preview`: before, after, what happens, risk, the rules between settings); "Save the
 *      changes" sends only those keys with one reason (`PATCH /admin/api/v1/settings`), after "Confirm it is you"
 *      when a key needs a fresh second factor, with the high-risk confirmation when the preview asks for it.
 *   3. Import: reads an exported file in the browser, shows `POST /settings/import/preview`, then imports it with a
 *      reason (`POST /settings/import`).
 *   4. `/admin/settings#<key>` (recommendation evidence links there) shows that setting (`?key=<key>`).
 *
 * Why it exists
 *   The shared modules save one setting at a time (static/js/settings_api.js); plan 15.2 also asks for a reviewed
 *   batch and for import and export. The server judges everything again; this script only gathers and shows.
 *
 * How it works
 *   Unsaved edits live in a Map (key -> the text as typed, which the catalog parses on the server). A control that
 *   appears again (another page of results, a re-render after a single save) gets its unsaved text back, or is
 *   forgotten when the saved value now equals it. While edits are unsaved a hidden marker carries `data-dirty`, so
 *   the leave-page guard and the card refreshes know (static/js/dom.js, static/js/cards.js). Every value from the
 *   server or a file is put in the page as text (`el(..., {text})`), never as HTML.
 *
 * What to read next
 *   static/js/page.js, static/js/settings_api.js, roxy/admin/api/settings.py, roxy/admin/pages/settings.py.
 */

import { el, qs, qsa } from "roxy/dom";
import { confirmIdentity, getJSON, onContent, refreshCard, request, toast } from "roxy/page";

const SESSION_URL = "/admin/api/v1/auth/session";
const KEY_PATTERN = /^[a-z][a-z0-9_]{0,79}$/;
const MAX_IMPORT_BYTES = 512 * 1024;
const MAX_ERROR_TEXT = 4096;
const FILTER_NAMES = ["q", "group", "risk", "changed", "has_recommendation", "page", "page_size", "key"];
const DEFAULTS = { page: "1", page_size: "25" };

const pending = new Map();
let lastPreview = null;
let importState = null;
let firstResults = true;
let focusResults = false;

// ---------------------------------------------------------------------------------------------- small helpers

function display(value) {
  if (value === null || value === undefined) return "not set";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "empty";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function editorRoot() {
  return document.getElementById("editor");
}

function filterForm() {
  return document.getElementById("editor-filter");
}

async function readError(response) {
  const text = (await response.text().catch(() => "")).slice(0, MAX_ERROR_TEXT);
  try {
    const parsed = JSON.parse(text);
    const error = parsed && typeof parsed.error === "object" && parsed.error ? parsed.error : {};
    return {
      code: typeof error.code === "string" ? error.code : "",
      message: typeof error.message === "string" ? error.message : `The server refused this (${response.status}).`,
      fields: error.fields && typeof error.fields === "object" ? error.fields : {},
    };
  } catch {
    return { code: "", message: `The server refused this (${response.status}).`, fields: {} };
  }
}

function showError(box, message) {
  if (!box) return;
  box.textContent = message;
  box.hidden = !message;
}

async function freshEnough() {
  try {
    const session = await getJSON(SESSION_URL);
    return Boolean(session && session.Fresh);
  } catch {
    return false;
  }
}

/** Send a JSON write; a 403 asking for a fresh second factor gets "Confirm it is you" and one retry. */
async function sendJSON(url, method, body) {
  const send = () => request(url, { method, body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
  let response = await send();
  if (response.status === 403) {
    const error = await readError(response.clone());
    if (error.code === "reauth_required" || response.headers.get("Roxy-Reauth") === "required") {
      if (!(await confirmIdentity())) return { response: null, refusedFactor: true };
      response = await send();
    }
  }
  return { response, refusedFactor: false };
}

// ---------------------------------------------------------------------------------------------- unsaved edits

function textOf(form) {
  const input = qs("[data-setting-input]", form);
  if (!input) return "";
  return input.type === "checkbox" ? (input.checked ? "1" : "0") : input.value;
}

function setText(form, text) {
  const input = qs("[data-setting-input]", form);
  if (!input) return;
  if (input.type === "checkbox") input.checked = String(text) === "1";
  else input.value = text;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function inEditor(node) {
  return node instanceof Element && Boolean(node.closest("#editor-results"));
}

function track(form) {
  const key = form.dataset.settingKey;
  if (!key) return;
  const text = textOf(form);
  if (text.trim() === String(form.dataset.initial ?? "").trim()) pending.delete(key);
  else pending.set(key, text);
  renderBar();
}

function renderBar() {
  const root = editorRoot();
  const bar = root ? qs("[data-settings-batch]", root) : null;
  if (!bar) return;
  const count = pending.size;
  bar.hidden = count === 0;
  const guard = qs("[data-settings-guard]", bar);
  if (guard) guard.toggleAttribute("data-dirty", count > 0);
  const shown = new Set(qsa("#editor-results form[data-setting-key]").map((form) => form.dataset.settingKey));
  const elsewhere = [...pending.keys()].filter((key) => !shown.has(key)).length;
  const words = `${count} unsaved change${count === 1 ? "" : "s"}`;
  const text = elsewhere ? `${words} (${elsewhere} on other pages of results)` : words;
  const label = qs("[data-batch-count]", bar);
  if (label && label.textContent !== text) label.textContent = text;
}

/** A control that appears (first paint, another page of results, a re-render after a save) catches up. */
function adopt(form) {
  if (!inEditor(form)) return;
  const key = form.dataset.settingKey;
  if (key && pending.has(key)) {
    const text = pending.get(key);
    if (String(form.dataset.initial ?? "").trim() === String(text).trim()) pending.delete(key);
    else window.setTimeout(() => setText(form, text), 0);  // after Alpine has set the control up
  }
  renderBar();
}

function discardAll() {
  for (const form of qsa("#editor-results form[data-setting-key]")) {
    if (pending.has(form.dataset.settingKey)) setText(form, form.dataset.initial ?? "");
  }
  pending.clear();
  renderBar();
}

// ---------------------------------------------------------------------------------------------- filters, pages

function syncAddress() {
  const form = filterForm();
  if (!form) return;
  const url = new URL(window.location.href);
  for (const name of FILTER_NAMES) url.searchParams.delete(name);
  for (const field of qsa("input[name], select[name]", form)) {
    if ("editorKeep" in field.dataset) continue;
    if (field.type === "checkbox" && !field.checked) continue;
    const value = field.value.trim();
    if (!value || DEFAULTS[field.name] === value) continue;
    url.searchParams.set(field.name, value);
  }
  if (url.href !== window.location.href) window.history.replaceState(window.history.state, "", url.href);
}

function submitFilters({ page } = {}) {
  const form = filterForm();
  if (!form) return;
  const pageField = qs("[data-editor-page]", form);
  if (pageField && page !== undefined) pageField.value = String(page);
  focusResults = true;
  form.requestSubmit();
}

function onResults(results) {
  const status = qs("[data-editor-status]");
  if (status && results.dataset.summary && status.textContent !== results.dataset.summary) {
    status.textContent = results.dataset.summary;
  }
  if (firstResults) {
    firstResults = false;
  } else {
    syncAddress();
  }
  if (focusResults) {
    focusResults = false;
    results.focus({ preventScroll: true });
    results.scrollIntoView({ block: "start" });
  }
  renderBar();
}

// ---------------------------------------------------------------------------------------------- batch review

function batchDialog() {
  return document.getElementById("settings-batch-dialog");
}

function itemOutcome(item) {
  if (item.status === "change") {
    const parts = [el("span", { text: item.consequence || "Changes the value." })];
    if (item.high_risk_reason) parts.push(el("strong", { class: "settings-batch__risk", text: `High risk: ${item.high_risk_reason}` }));
    if (item.restart_needed) parts.push(el("span", { class: "muted", text: "Takes effect after the next restart." }));
    return parts;
  }
  if (item.status === "unchanged") return [el("span", { class: "muted", text: "Already the value in force; nothing to save." })];
  if (item.status === "unknown") return [el("strong", { class: "settings-batch__bad", text: "Unknown setting." })];
  return [el("strong", { class: "settings-batch__bad", text: item.message || "Not valid." })];
}

function fillPreview(answer) {
  const dialog = batchDialog();
  const rows = qs("[data-batch-rows]", dialog);
  rows.replaceChildren(...answer.items.map((item) => el("tr", { "data-batch-key": item.key }, [
    el("th", { scope: "row" }, [el("span", { text: item.label || item.key }), el("code", { class: "settings-batch__key", text: item.key })]),
    el("td", { text: display(item.current) }),
    el("td", { text: item.status === "change" || item.status === "unchanged" ? display(item.new) : "" }),
    el("td", {}, [el("div", { class: "settings-batch__what" }, itemOutcome(item))]),
  ])));
  const problems = qs("[data-batch-problems]", dialog);
  const issues = (answer.cross || []).map((issue) => issue.message);
  if (!answer.ok && !issues.length) issues.push("Some values are not valid: fix them in the list (they are marked there), then review again.");
  problems.replaceChildren(...issues.map((text) => el("li", { text })));
  problems.hidden = issues.length === 0;
  const mfa = qs("[data-batch-mfa]", dialog);
  mfa.hidden = !answer.fresh_mfa_required;
  qs("[data-batch-mfa-text]", dialog).textContent = answer.fresh_mfa_required
    ? `Saving asks for a current code from your authenticator app first (${answer.fresh_mfa_keys.join(", ")}).`
    : "";
  const reason = qs("[data-batch-reason]", dialog);
  reason.required = Boolean(answer.reason_required);
  qs("[data-batch-reason-hint]", dialog).textContent = answer.reason_required
    ? "(required: the batch holds a high-risk change)"
    : "(optional, saved in the audit log)";
  const confirm = qs("[data-batch-confirm]", dialog);
  confirm.hidden = !answer.confirm_required;
  qs("[data-batch-confirm-box]", dialog).checked = false;
  const save = qs("[data-batch-save]", dialog);
  save.disabled = !answer.ok || !answer.changes;
  save.textContent = answer.changes ? `Save ${answer.changes} change${answer.changes === 1 ? "" : "s"}` : "Nothing to save";
}

async function review() {
  const dialog = batchDialog();
  const root = editorRoot();
  if (!dialog || !root) return;
  showError(qs("[data-batch-error]", dialog), "");
  showError(qs("[data-batch-reason-error]", dialog), "");
  qs("[data-batch-rows]", dialog).replaceChildren(el("tr", {}, [el("td", { colspan: "4", class: "muted", text: "Asking the server what these changes would do..." })]));
  qs("[data-batch-save]", dialog).disabled = true;
  const changes = Object.fromEntries(pending);
  lastPreview = null;
  let response;
  try {
    response = await request(root.querySelector("[data-settings-editor]").dataset.previewUrl, {
      method: "POST",
      body: JSON.stringify({ changes }),
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    showError(qs("[data-batch-error]", dialog), "Roxy could not be reached. Nothing was saved; try again.");
    return;
  }
  if (!response.ok) {
    if (response.status !== 401) showError(qs("[data-batch-error]", dialog), (await readError(response)).message);
    return;
  }
  const answer = await response.json().catch(() => null);
  if (!answer || !Array.isArray(answer.items)) {
    showError(qs("[data-batch-error]", dialog), "The server's preview could not be read. Nothing was saved.");
    return;
  }
  lastPreview = { changes, answer };
  fillPreview(answer);
}

async function saveBatch(form) {
  const dialog = batchDialog();
  const errorBox = qs("[data-batch-error]", dialog);
  const reasonBox = qs("[data-batch-reason-error]", dialog);
  showError(errorBox, "");
  showError(reasonBox, "");
  if (!lastPreview) return;
  const { changes, answer } = lastPreview;
  const reason = qs("[data-batch-reason]", dialog).value.trim();
  const confirmed = qs("[data-batch-confirm-box]", dialog).checked;
  if (answer.reason_required && !reason) {
    showError(reasonBox, "Give a reason: this batch holds a high-risk change and the reason goes in the audit log.");
    qs("[data-batch-reason]", dialog).focus();
    return;
  }
  if (answer.confirm_required && !confirmed) {
    showError(errorBox, "Tick the confirmation first: this batch holds a high-risk change.");
    return;
  }
  if (answer.fresh_mfa_required && !(await freshEnough()) && !(await confirmIdentity())) {
    showError(errorBox, "Nothing was saved: some of these settings need your second factor.");
    return;
  }
  const button = qs("[data-batch-save]", form);
  button.disabled = true;
  let result;
  try {
    result = await sendJSON(qs("[data-settings-editor]").dataset.saveUrl, "PATCH", { changes, reason, confirm_high_risk: confirmed });
  } catch {
    showError(errorBox, "Roxy could not be reached. Nothing was saved; try again.");
    button.disabled = false;
    return;
  } finally {
    button.disabled = false;
  }
  if (result.refusedFactor) {
    showError(errorBox, "Nothing was saved: some of these settings need your second factor.");
    return;
  }
  const response = result.response;
  if (response.ok) {
    const saved = await response.json().catch(() => ({}));
    const count = Array.isArray(saved.changed) ? saved.changed.length : Object.keys(changes).length;
    pending.clear();
    renderBar();
    dialog.close();
    toast(`Saved ${count} setting${count === 1 ? "" : "s"}. Every worker uses ${count === 1 ? "it" : "them"} within a second.`, { tone: "ok" });
    refreshCard("editor");
    refreshCard("history");
    return;
  }
  if (response.status === 401) return;
  const error = await readError(response);
  if (error.code === "confirmation_required") qs("[data-batch-confirm]", dialog).hidden = false;
  if (error.fields.reason) showError(reasonBox, String(error.fields.reason));
  for (const [key, message] of Object.entries(error.fields)) {
    const row = qs(`[data-batch-key="${CSS.escape(key)}"] .settings-batch__what`, dialog);
    if (row) row.replaceChildren(el("strong", { class: "settings-batch__bad", text: String(message) }));
  }
  const retry = response.headers.get("Retry-After");
  showError(errorBox, retry ? `${error.message} Try again in ${retry} seconds.` : error.message);
}

// ---------------------------------------------------------------------------------------------- import

async function readDocument(form) {
  const file = qs("[data-import-file]", form);
  const chosen = file && file.files && file.files[0];
  let text = "";
  if (chosen) {
    if (chosen.size > MAX_IMPORT_BYTES) throw new Error("That file is larger than 512 KB, so it is not a Roxy settings export.");
    text = await chosen.text();
  } else {
    text = qs("[data-import-text]", form).value;
  }
  if (!text.trim()) throw new Error("Choose an exported file, or paste its text, first.");
  if (text.length > MAX_IMPORT_BYTES) throw new Error("That text is longer than 512 KB, so it is not a Roxy settings export.");
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    throw new Error("That is not JSON. Use a file made by Export my changes.");
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("That JSON is not a settings export (it should be an object with overrides).");
  }
  return document;
}

const IMPORT_STATUS = {
  change: "Will change",
  unchanged: "Already set",
  invalid: "Not valid",
  unknown: "Unknown setting",
  skipped: "Skipped",
  reset: "Back to the default",
};

function showImport(answer) {
  const root = qs("[data-import-result]");
  const rows = qs("[data-import-rows]", root);
  rows.replaceChildren(...answer.items.map((item) => el("tr", {}, [
    el("th", { scope: "row" }, [el("code", { text: item.key })]),
    el("td", { text: display(item.current) }),
    el("td", { text: item.status === "unknown" ? "" : display(item.new) }),
    el("td", {}, [
      el("span", { class: item.status === "invalid" || item.status === "unknown" ? "settings-batch__bad" : "", text: IMPORT_STATUS[item.status] || item.status }),
      item.message ? el("span", { class: "muted settings-import__message", text: ` ${item.message}` }) : el("span"),
      item.high_risk_reason ? el("strong", { class: "settings-batch__risk", text: ` High risk: ${item.high_risk_reason}` }) : el("span"),
    ]),
  ])));
  const summary = [`${answer.changes} change${answer.changes === 1 ? "" : "s"} to import.`];
  if (!answer.catalog_version_matches) summary.push("The file was made with another version of the settings catalog; keys this release does not know are listed as unknown.");
  if (!answer.ok) summary.push("Some entries are not valid, so nothing can be imported until the file is fixed.");
  qs("[data-import-summary]", root).textContent = summary.join(" ");
  const problems = qs("[data-import-problems]", root);
  problems.replaceChildren(...(answer.cross || []).map((issue) => el("li", { text: issue.message })));
  problems.hidden = !(answer.cross || []).length;
  const mfaKeys = answer.fresh_mfa_keys || [];
  qs("[data-import-mfa]", root).hidden = !mfaKeys.length;
  qs("[data-import-mfa-text]", root).textContent = mfaKeys.length
    ? `Importing asks for a current code from your authenticator app first (${mfaKeys.join(", ")}).`
    : "";
  qs("[data-import-confirm]", root).hidden = !answer.confirm_required;
  qs("[data-import-confirm-box]", root).checked = false;
  qs("[data-import-submit]", root).disabled = !answer.ok || !answer.changes;
  root.hidden = false;
  const heading = qs("[data-import-heading]", root);
  if (heading) heading.focus();
}

async function previewImport(form) {
  const errorBox = qs("[data-import-error]", form);
  showError(errorBox, "");
  let document;
  try {
    document = await readDocument(form);
  } catch (error) {
    showError(errorBox, error.message);
    return;
  }
  const replace = qs("[data-import-replace]", form).checked;
  let response;
  try {
    response = await request(form.dataset.previewUrl, {
      method: "POST",
      body: JSON.stringify({ document, replace }),
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    showError(errorBox, "Roxy could not be reached. Nothing was imported; try again.");
    return;
  }
  if (!response.ok) {
    if (response.status !== 401) showError(errorBox, (await readError(response)).message);
    return;
  }
  const answer = await response.json().catch(() => null);
  if (!answer || !Array.isArray(answer.items)) {
    showError(errorBox, "The server's preview could not be read. Nothing was imported.");
    return;
  }
  importState = { document, replace, answer, url: form.dataset.importUrl };
  showImport(answer);
}

function closeImport() {
  const root = qs("[data-import-result]");
  if (root) root.hidden = true;
  importState = null;
}

async function applyImport(form) {
  const errorBox = qs("[data-import-apply-error]", form);
  const reasonBox = qs("[data-import-reason-error]", form);
  showError(errorBox, "");
  showError(reasonBox, "");
  if (!importState) return;
  const reason = qs("[data-import-reason]", form).value.trim();
  if (!reason) {
    showError(reasonBox, "Give a reason for this import; it goes in the audit log.");
    qs("[data-import-reason]", form).focus();
    return;
  }
  const confirmed = qs("[data-import-confirm-box]", form).checked;
  const { answer } = importState;
  if (answer.confirm_required && !confirmed) {
    showError(errorBox, "Tick the confirmation first: the file holds high-risk values.");
    return;
  }
  if ((answer.fresh_mfa_keys || []).length && !(await freshEnough()) && !(await confirmIdentity())) {
    showError(errorBox, "Nothing was imported: some of these settings need your second factor.");
    return;
  }
  let result;
  try {
    result = await sendJSON(importState.url, "POST", {
      document: importState.document, replace: importState.replace, reason, confirm_high_risk: confirmed,
    });
  } catch {
    showError(errorBox, "Roxy could not be reached. Nothing was imported; try again.");
    return;
  }
  if (result.refusedFactor) {
    showError(errorBox, "Nothing was imported: some of these settings need your second factor.");
    return;
  }
  const response = result.response;
  if (response.ok) {
    const done = await response.json().catch(() => ({}));
    const count = Array.isArray(done.changed) ? done.changed.length : 0;
    closeImport();
    for (const node of qsa("[data-settings-import], [data-import-apply]")) node.reset();
    toast(`Imported ${count} change${count === 1 ? "" : "s"}. Every worker uses them within a second.`, { tone: "ok" });
    refreshCard("editor");
    refreshCard("history");
    return;
  }
  if (response.status === 401) return;
  const error = await readError(response);
  if (error.code === "confirmation_required") qs("[data-import-confirm]", form).hidden = false;
  if (error.fields.reason) showError(reasonBox, String(error.fields.reason));
  showError(errorBox, error.message);
}

// ---------------------------------------------------------------------------------------------- wiring

function wire() {
  // A filter changed: back to page 1, and out of the one-setting view (capture: before htmx reads the form).
  const reset = (event) => {
    const form = event.target instanceof Element ? event.target.closest("#editor-filter") : null;
    if (!form || event.target.type === "hidden") return;
    const pageField = qs("[data-editor-page]", form);
    if (pageField) pageField.value = "1";
    const key = qs("[data-editor-key]", form);
    if (key) key.remove();
  };
  document.addEventListener("input", reset, true);
  document.addEventListener("change", reset, true);

  document.addEventListener("input", (event) => {
    const form = event.target instanceof Element ? event.target.closest("form[data-setting-key]") : null;
    if (form && inEditor(form)) track(form);
  });
  document.addEventListener("change", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    if (target.matches("[data-editor-size-select]")) {
      const size = qs("[data-editor-size]", filterForm());
      if (size) size.value = target.value;
      submitFilters({ page: 1 });
      return;
    }
    const form = target.closest("form[data-setting-key]");
    if (form && inEditor(form)) track(form);
  });
  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const go = target.closest("[data-editor-goto]");
    if (go && !go.disabled) {
      submitFilters({ page: Number(go.dataset.editorGoto) || 1 });
      return;
    }
    if (target.closest("[data-batch-review]")) {
      review();
      return;
    }
    if (target.closest("[data-batch-discard]")) {
      discardAll();
      return;
    }
    if (target.closest("[data-import-cancel]")) {
      closeImport();
      return;
    }
    // Cancel and "Reset to default" change a control without an input event: look again after them.
    const form = target.closest("form[data-setting-key]");
    if (form && inEditor(form)) window.setTimeout(() => track(form), 0);
  });
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.matches("[data-batch-form]")) {
      event.preventDefault();
      saveBatch(form);
    } else if (form.matches("[data-settings-import]")) {
      event.preventDefault();
      previewImport(form);
    } else if (form.matches("[data-import-apply]")) {
      event.preventDefault();
      applyImport(form);
    }
  });
}

/** `/admin/settings#<key>`: show that setting when it is not on the page already. */
function followKeyHash() {
  const key = decodeURIComponent(window.location.hash.slice(1));
  if (!KEY_PATTERN.test(key) || document.getElementById(key)) return;
  if (new URLSearchParams(window.location.search).get("key") === key) return;  // not a setting: the page says so
  window.location.replace(`/admin/settings?key=${encodeURIComponent(key)}#${key}`);
}

wire();
followKeyHash();
onContent("#editor-results form[data-setting-key]", adopt);
onContent("#editor-results", onResults);
