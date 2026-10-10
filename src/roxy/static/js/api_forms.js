/**
 * Forms that send JSON to the admin API: dialogs, card actions and the preferences form (plan 9.6, DESIGN.md 13).
 *
 * What this is
 *   `initApiForms()` handles the submit of every `form[data-api-form]` on the page (and swapped in later): it builds
 *   a JSON body from the fields, sends it to `data-api-url` with `data-api-method` (POST, PUT, PATCH, DELETE) and
 *   the X-CSRF-Token header (net.js), and handles the answer. `submitApiForm(form)` does it from a script.
 *
 * Why it exists
 *   Page routes are read-only: every change goes through the admin API, so its validation, risk rules, fresh second
 *   factors and audit log have one implementation. HTML forms cannot send JSON or custom headers, and the API refuses
 *   a missing or malformed body with 400 (it is never treated as `{}`), so one small module turns a form into the
 *   API's body shape and its section 13 errors back into messages next to the right field.
 *
 * How it works
 *   * Body: every named field, unless `data-json="never"` (type-to-confirm text). `data-json` gives its type:
 *     `bool` ("true", "1", "on" are true; a checkbox is its checked state), `int`, `float`, `string` (sent even when
 *     empty), `skip-empty` (left out when empty, the default for text), `list` (one item per line). Repeated names
 *     become a list. Disabled fields are skipped.
 *   * 2xx: the dialog around the form closes, a toast says `data-success` (or the answer's `message`), and
 *     `data-on-success` decides what follows: `reload` the page, `refresh` (the cards named in `data-refresh`, or
 *     the card the form sits in, static/js/cards.js), or nothing. A `roxy:api-success` event carries the answer.
 *   * 403 `reauth_required`: "Confirm it is you" (reauth.js), then the same request once more.
 *   * 422: each `error.fields` message goes under its field (`[data-field-error="<name>"]`, or a message element
 *     added after the input, tied with aria-describedby); `confirmation_required` reveals `[data-confirm-field]`.
 *   * 409, 429 (with Retry-After), 503 and anything else: the message shows in `[data-dialog-error]` (or a toast).
 *
 * What to read next
 *   templates/components/dialog.html (`confirm_dialog(..., api=True)`), static/js/reauth.js, static/js/net.js.
 */

import { el, qs, qsa } from "roxy/dom";
import { closeDialog } from "roxy/dialog";
import { errorMessage, isReauthRequired, request } from "roxy/net";
import { confirmIdentity } from "roxy/reauth";
import { toast } from "roxy/toast";

const MAX_ERROR_TEXT = 4096;
const busy = new WeakSet();

function truthy(value) {
  return ["true", "1", "on", "yes"].includes(String(value).trim().toLowerCase());
}

/** The JSON body of `form` (see "How it works"). */
export function formBody(form) {
  const body = {};
  const put = (name, value) => {
    if (name in body) body[name] = [].concat(body[name], value);
    else body[name] = value;
  };
  for (const field of qsa("input[name], select[name], textarea[name]", form)) {
    if (field.disabled) continue;
    const kind = field.dataset.json || (field.type === "checkbox" ? "bool" : "skip-empty");
    if (kind === "never") continue;
    if (field.closest("[data-confirm-field][hidden]")) continue;  // a confirmation not asked for is not sent
    if (field.type === "radio" && !field.checked) continue;
    const raw = field.type === "checkbox" ? field.checked : field.value;
    if (kind === "bool") put(field.name, typeof raw === "boolean" ? raw : truthy(raw));
    else if (kind === "int" || kind === "float") {
      const text = String(raw).trim().replace(/[,_\s]/g, "");
      if (text === "") continue;
      const number = kind === "int" ? Number.parseInt(text, 10) : Number.parseFloat(text);
      put(field.name, Number.isFinite(number) && String(number) !== "NaN" ? number : text);  // the API judges bad text
    } else if (kind === "list") put(field.name, String(raw).split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
    else if (kind === "string") put(field.name, String(raw));
    else if (String(raw).trim() !== "") put(field.name, String(raw));
  }
  return body;
}

function clearErrors(form) {
  for (const node of qsa("[data-field-error]", form)) {
    node.textContent = "";
    node.hidden = true;
  }
  for (const node of qsa("[data-api-added-error]", form)) node.remove();
  for (const field of qsa("[aria-invalid='true']", form)) field.removeAttribute("aria-invalid");
  const general = qs("[data-dialog-error]", form);
  if (general) general.hidden = true;
}

function fieldError(form, name, message) {
  const field = qs(`[name="${CSS.escape(name)}"]`, form);
  let box = qs(`[data-field-error="${CSS.escape(name)}"]`, form);
  if (!box && field) {
    box = el("p", { class: "field__error", "data-field-error": name, "data-api-added-error": "1", id: `${field.id || name}-api-error` });
    field.insertAdjacentElement("afterend", box);
    const described = (field.getAttribute("aria-describedby") || "").split(/\s+/).filter(Boolean);
    if (!described.includes(box.id)) field.setAttribute("aria-describedby", [...described, box.id].join(" "));
  }
  if (field) field.setAttribute("aria-invalid", "true");
  if (box) {
    box.textContent = message;
    box.hidden = false;
    return true;
  }
  return false;
}

function generalError(form, message) {
  const box = qs("[data-dialog-error]", form);
  if (box) {
    box.textContent = message;
    box.hidden = false;
  } else {
    toast(message, { tone: "bad" });
  }
}

async function readError(response) {
  const text = (await response.text().catch(() => "")).slice(0, MAX_ERROR_TEXT);
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  const error = parsed && parsed.error && typeof parsed.error === "object" ? parsed.error : {};
  return {
    code: typeof error.code === "string" ? error.code : "",
    message: errorMessage(text) || `The server refused this (${response.status}). Nothing was changed.`,
    fields: error.fields && typeof error.fields === "object" ? error.fields : {},
  };
}

function afterSuccess(form, answer) {
  const message = form.dataset.success || (answer && typeof answer.message === "string" ? answer.message : "") || "Done.";
  const dialog = form.closest("dialog");
  form.dispatchEvent(new CustomEvent("roxy:api-success", { bubbles: true, detail: { answer } }));
  if (dialog) {
    form.reset();
    closeDialog(dialog);
  }
  toast(message, { tone: "ok" });
  const then = form.dataset.onSuccess || "";
  if (then === "reload") {
    window.setTimeout(() => window.location.reload(), 300);
  } else if (then === "refresh") {
    const names = (form.dataset.refresh || "").split(/\s+/).filter(Boolean);
    document.dispatchEvent(new CustomEvent("roxy:refresh-cards", { detail: { cards: names, from: form } }));
  }
}

/** Send `form` to the admin API (see the module docstring). Resolves true on success. */
export async function submitApiForm(form, { retried = false } = {}) {
  if (busy.has(form)) return false;
  const url = form.dataset.apiUrl;
  if (!url) return false;
  const method = (form.dataset.apiMethod || "POST").toUpperCase();
  busy.add(form);
  form.setAttribute("aria-busy", "true");
  clearErrors(form);
  let response;
  try {
    response = await request(url, {
      method,
      body: JSON.stringify(formBody(form)),
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    generalError(form, "Roxy could not be reached. Nothing was changed; try again.");
    return false;
  } finally {
    busy.delete(form);
    form.removeAttribute("aria-busy");
  }
  if (response.ok) {
    const answer = response.status === 204 ? null : await response.json().catch(() => null);
    afterSuccess(form, answer);
    return true;
  }
  if (response.status === 401) return false;  // the session overlay is already showing (net.js)
  if (!retried && response.status === 403) {
    const text = await response.clone().text().catch(() => "");
    if (isReauthRequired(403, response.headers.get("Roxy-Reauth"), text)) {
      if (await confirmIdentity()) return submitApiForm(form, { retried: true });
      generalError(form, "Nothing was changed: this action needs your second factor.");
      return false;
    }
  }
  const error = await readError(response);
  if (response.status === 422) {
    let placed = false;
    for (const [name, message] of Object.entries(error.fields)) placed = fieldError(form, name, String(message)) || placed;
    if (error.code === "confirmation_required") {
      for (const box of qsa("[data-confirm-field]", form)) box.hidden = false;
      const check = qs("[data-confirm-field] input", form);
      if (check) check.focus();
    }
    if (!placed || error.code === "confirmation_required") generalError(form, error.message);
    return false;
  }
  const retry = response.headers.get("Retry-After");
  const suffix = response.status === 429 || response.status === 503 ? ` Try again in ${retry || "a few"} seconds.` : "";
  generalError(form, `${error.message}${suffix && !error.message.includes("try again") ? suffix : ""}`);
  return false;
}

export function initApiForms() {
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("form[data-api-form]")) return;
    event.preventDefault();
    if (form.checkValidity && !form.checkValidity()) {
      form.reportValidity();
      return;
    }
    submitApiForm(form);
  });
}
