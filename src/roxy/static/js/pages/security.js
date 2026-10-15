/**
 * The Security page's own script (templates/admin/pages/security.html): fingerprint tabs, new recovery codes shown
 * once, and adding a passkey.
 *
 * What this is
 *   * Tabs: the fingerprint card holds four lists in tab panels (ARIA tabs: arrow keys, Home and End move between
 *     them, the open one is remembered while the page is open, so a refresh of the card after an action keeps it).
 *   * Recovery codes: `POST /security/recovery-codes/regenerate` answers the new codes once. When the "Make new
 *     codes" dialog succeeds (static/js/api_forms.js raises `roxy:api-success` with the answer), the codes are shown
 *     in the card as text nodes with a copy button, and the count says how many are left. They never come back from
 *     the server again and "Hide them" drops them from the page.
 *   * Add a passkey: asks `auth/passkeys/register/options` (a fresh second factor: "Confirm it is you" first when
 *     it is stale), lets the browser create the passkey (WebAuthn `navigator.credentials.create`), and sends it to
 *     `auth/passkeys/register/verify`; then the card is refreshed from the server.
 *
 * Why it exists
 *   These three need behavior the shared design system does not have; everything else on the page (tables,
 *   drawers, dialogs, the action forms) is the shared one.
 *
 * How it works
 *   Only `roxy/page` is imported (P11 contract). DOM is built with text nodes (`textContent`), never from HTML
 *   strings (plan 9.16). The WebAuthn helpers turn the server's base64url fields into ArrayBuffers and back, as
 *   the sign-in page's script does (static/js/auth.js).
 *
 * What to read next
 *   static/js/page.js, roxy/admin/pages/security.py, roxy/admin/api/security.py, roxy/admin/auth/routes.py.
 */

import { confirmIdentity, onContent, postJSON, refreshCard, toast } from "roxy/page";

// ------------------------------------------------------------------------------------------------ tabs

let openTab = "";

function selectTab(root, tab, { focus = false } = {}) {
  const tabs = [...root.querySelectorAll("[data-fp-tab]")];
  for (const item of tabs) {
    const selected = item === tab;
    item.setAttribute("aria-selected", selected ? "true" : "false");
    item.tabIndex = selected ? 0 : -1;
    const panel = document.getElementById(item.getAttribute("aria-controls"));
    if (panel) panel.hidden = !selected;
  }
  openTab = tab.dataset.fpTab || "";
  if (focus) tab.focus();
}

function initTabs(root) {
  const tabs = [...root.querySelectorAll("[data-fp-tab]")];
  if (!tabs.length) return;
  const remembered = tabs.find((tab) => tab.dataset.fpTab === openTab);
  if (remembered) selectTab(root, remembered);
  root.addEventListener("click", (event) => {
    const tab = event.target instanceof Element ? event.target.closest("[data-fp-tab]") : null;
    if (tab && root.contains(tab)) selectTab(root, tab);
  });
  root.addEventListener("keydown", (event) => {
    const tab = event.target instanceof Element ? event.target.closest("[data-fp-tab]") : null;
    if (!tab) return;
    const index = tabs.indexOf(tab);
    let next = null;
    if (event.key === "ArrowRight") next = tabs[(index + 1) % tabs.length];
    else if (event.key === "ArrowLeft") next = tabs[(index - 1 + tabs.length) % tabs.length];
    else if (event.key === "Home") next = tabs[0];
    else if (event.key === "End") next = tabs[tabs.length - 1];
    if (next) {
      event.preventDefault();
      selectTab(root, next, { focus: true });
    }
  });
}

onContent("[data-fp-tabs]", initTabs);

// ------------------------------------------------------------------------------------------------ recovery codes

let shownCodes = [];

function showCodes(codes) {
  const card = document.getElementById("recovery-codes");
  if (!card) return;
  const region = card.querySelector("[data-recovery-new]");
  const list = card.querySelector("[data-recovery-list]");
  if (!region || !list) return;
  shownCodes = codes.map((code) => String(code));
  list.replaceChildren(...shownCodes.map((code) => {
    const item = document.createElement("li");
    item.textContent = code;
    return item;
  }));
  for (const node of card.querySelectorAll("[data-recovery-remaining], [data-recovery-total]")) {
    node.textContent = String(shownCodes.length);
  }
  const state = card.querySelector("[data-recovery-state]");
  if (state) state.hidden = true;
  region.hidden = false;
  region.focus();
}

function hideCodes() {
  const card = document.getElementById("recovery-codes");
  const region = card ? card.querySelector("[data-recovery-new]") : null;
  const list = card ? card.querySelector("[data-recovery-list]") : null;
  shownCodes = [];
  if (list) list.replaceChildren();
  if (region) region.hidden = true;
}

document.addEventListener("roxy:api-success", (event) => {
  const form = event.target instanceof Element ? event.target : null;
  if (!form || !form.closest("#dlg-recovery-new")) return;
  const answer = event.detail && event.detail.answer;
  const codes = answer && Array.isArray(answer.codes) ? answer.codes.filter((code) => typeof code === "string") : [];
  if (codes.length) showCodes(codes);
});

document.addEventListener("click", async (event) => {
  const target = event.target instanceof Element ? event.target : null;
  if (!target) return;
  if (target.closest("[data-recovery-copy]")) {
    if (!shownCodes.length) return;
    try {
      await navigator.clipboard.writeText(shownCodes.join("\n"));
      toast("Copied. Paste them somewhere safe now.", { tone: "ok" });
    } catch {
      toast("Copying is blocked in this browser; select the codes and copy them by hand.", { tone: "warn" });
    }
  } else if (target.closest("[data-recovery-hide]")) {
    hideCodes();
  }
});

// ------------------------------------------------------------------------------------------------ passkeys

function fromBase64url(text) {
  const padded = String(text).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(text).length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function toBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function creationOptions(options) {
  const publicKey = {
    ...options,
    challenge: fromBase64url(options.challenge),
    user: { ...options.user, id: fromBase64url(options.user.id) },
  };
  if (Array.isArray(options.excludeCredentials)) {
    publicKey.excludeCredentials = options.excludeCredentials.map((c) => ({ ...c, id: fromBase64url(c.id) }));
  }
  return publicKey;
}

function credentialJson(credential) {
  if (typeof credential.toJSON === "function") return credential.toJSON();
  const response = credential.response;
  const json = {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      attestationObject: toBase64url(response.attestationObject),
    },
  };
  if (typeof response.getTransports === "function") json.response.transports = response.getTransports();
  return json;
}

async function needsReauth(response) {
  if (response.status !== 403) return false;
  if ((response.headers.get("Roxy-Reauth") || "").toLowerCase() === "required") return true;
  const text = await response.clone().text().catch(() => "");
  try {
    const data = JSON.parse(text);
    return Boolean(data && data.error && data.error.code === "reauth_required");
  } catch {
    return false;
  }
}

/** POST JSON; on "confirm it is you" ask for the code once and send it again. */
async function postWithReauth(url, body) {
  let response = await postJSON(url, body);
  if (await needsReauth(response)) {
    if (!(await confirmIdentity())) return null;
    response = await postJSON(url, body);
  }
  return response;
}

async function messageOf(response, fallback) {
  const text = await response.text().catch(() => "");
  try {
    const data = JSON.parse(text);
    if (typeof data === "string" && data) return data.slice(0, 300);
    if (data && data.error && typeof data.error.message === "string") return data.error.message.slice(0, 300);
  } catch {
    // not JSON: fall through
  }
  return fallback;
}

async function addPasskey(form) {
  const status = form.querySelector("[data-passkey-status]");
  const button = form.querySelector("button[type=submit]");
  const say = (text) => {
    if (status) status.textContent = text;
  };
  if (typeof window.PublicKeyCredential !== "function" || !navigator.credentials) {
    say("This browser cannot create passkeys here.");
    return;
  }
  const name = String(new FormData(form).get("name") || "").trim().slice(0, 64) || "Passkey";
  if (button) button.disabled = true;
  try {
    const options = await postWithReauth(form.dataset.optionsUrl, {});
    if (!options) {
      say("Nothing was added: adding a passkey needs your second factor.");
      return;
    }
    if (!options.ok) {
      say(await messageOf(options, "Could not start adding a passkey."));
      return;
    }
    const data = await options.json();
    say("Follow your browser's prompt to create the passkey.");
    const credential = await navigator.credentials.create({ publicKey: creationOptions(data.Options) });
    const result = await postWithReauth(form.dataset.verifyUrl, { credential: credentialJson(credential), name });
    if (!result || !result.ok) {
      say(result ? await messageOf(result, "The passkey could not be added.") : "Nothing was added.");
      return;
    }
    toast("Passkey added.", { tone: "ok" });
    refreshCard("passkeys");
  } catch {
    say("Adding the passkey was canceled or failed. Nothing was added.");
  } finally {
    if (button && button.isConnected) button.disabled = false;
  }
}

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches("[data-passkey-add]")) return;
  event.preventDefault();
  addPasskey(form);
});
