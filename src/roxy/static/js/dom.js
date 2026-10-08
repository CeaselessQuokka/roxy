/**
 * DOM helpers shared by every dashboard module.
 *
 * What this is
 *   `el()` builds elements without innerHTML, `icon()` builds a sprite icon, `qs()`/`qsa()` query, and `store`
 *   reads and writes this browser's remembered preferences. `initOverlayLayer()` keeps the page-wide overlays
 *   (tooltip, toasts, live regions) usable while a modal dialog is open, and `hasUnsavedChanges()` says whether
 *   leaving the page now would lose an edit.
 *
 * Why it exists
 *   Building DOM with `textContent` and `setAttribute` (never innerHTML with data) is how the dashboard stays safe
 *   with attacker-controlled text such as user agents and probe paths (plan 9.16). Browser storage can be
 *   missing or throw (private windows, blocked site data), so every read and write is wrapped once, here, and
 *   callers get the fallback instead of an exception (v1 bug 23).
 *   A modal <dialog> sits in the browser's top layer and makes everything outside it inert: drawn underneath, and
 *   hidden from screen readers. A tooltip, a toast or a live region announcement made while the drawer, the phone
 *   menu or a confirm dialog is open would be invisible and silent there (plan 14.9), so those few nodes move into
 *   the topmost open modal while it is open and back to <body> when it closes.
 *
 * How it works
 *   `el("button", {class: "btn", type: "button", "aria-label": "Close"}, ["text", child])`: attributes are set with
 *   setAttribute except `dataset`, and children are appended as text nodes or elements. Style is never set through
 *   attributes (the CSP forbids inline style attributes); modules that position things use the CSSOM
 *   (`node.style.left = ...`), which the CSP allows.
 *   The overlay layer watches the `open` attribute of every <dialog> with one MutationObserver (so a dialog opened
 *   by any code is noticed, not only by dialog.js), keeps the modals in the order they opened, and re-parents the
 *   overlay nodes into the last one. They are `position: fixed`, so moving them changes nothing on screen except
 *   which layer they are drawn in.
 *
 * What to read next
 *   static/js/app.js (how modules start), static/js/toast.js (a small user of these helpers).
 */

const SVG_NS = "http://www.w3.org/2000/svg";

export function qs(selector, root = document) {
  return root.querySelector(selector);
}

export function qsa(selector, root = document) {
  return Array.from(root.querySelectorAll(selector));
}

/** Create an element with attributes and children (strings become text nodes, never HTML). */
export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "dataset") {
      Object.assign(node.dataset, value);
    } else if (name === "text") {
      node.textContent = String(value);
    } else {
      node.setAttribute(name, value === true ? "" : String(value));
    }
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** An icon from the inline sprite (decorative: hidden from assistive technology). */
export function icon(name, cls = "") {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", cls ? `icon ${cls}` : "icon");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}

/** True when keyboard input is going into a text field (shortcuts must not fire then). */
export function isTyping(target) {
  if (!(target instanceof Element)) return false;
  // A field inside a dialog that just closed can keep focus for a moment; it is not where the admin types.
  if (target.closest("dialog:not([open])")) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  if (tag === "TEXTAREA" || tag === "SELECT") return true;
  if (tag !== "INPUT") return false;
  const type = (target.getAttribute("type") || "text").toLowerCase();
  return !["checkbox", "radio", "button", "submit", "reset", "range"].includes(type);
}

/** Remembered per-browser preferences. Never throws; returns the fallback when storage is unavailable. */
export const store = {
  get(key, fallback = null) {
    try {
      const raw = window.localStorage.getItem(`roxy.${key}`);
      return raw === null ? fallback : JSON.parse(raw);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      window.localStorage.setItem(`roxy.${key}`, JSON.stringify(value));
    } catch {
      /* storage blocked or full: the preference is simply not remembered */
    }
  },
  remove(key) {
    try {
      window.localStorage.removeItem(`roxy.${key}`);
    } catch {
      /* nothing to do */
    }
  },
};

// ------------------------------------------------------------------------------------------ overlay layer

const overlayNodes = [];
const modalStack = [];  // open modal dialogs, oldest first

function isModal(dialog) {
  try {
    return dialog.open && dialog.matches(":modal");
  } catch {
    return dialog.open;  // a browser without :modal: treat every open dialog as modal
  }
}

/** The modal dialog drawn on top right now, or null. */
export function topModal() {
  for (let i = modalStack.length - 1; i >= 0; i -= 1) {
    const dialog = modalStack[i];
    if (dialog.isConnected && isModal(dialog)) return dialog;
    modalStack.splice(i, 1);  // closed or removed since: forget it
  }
  return null;
}

/** Where page-wide overlays must live now: inside the top modal (else they are inert under it), or <body>. */
export function overlayHost() {
  return topModal() || document.body;
}

function rehomeOverlays() {
  const host = overlayHost();
  for (const node of overlayNodes) {
    if (node.parentNode !== host) host.append(node);
  }
}

/** Keep the nodes matching `selectors` in the topmost open modal dialog (see the module docstring). */
export function initOverlayLayer(selectors) {
  for (const selector of selectors) {
    const node = qs(selector);
    if (node && !overlayNodes.includes(node)) overlayNodes.push(node);
  }
  for (const dialog of qsa("dialog[open]")) if (isModal(dialog)) modalStack.push(dialog);
  new MutationObserver((records) => {
    let changed = false;
    for (const record of records) {
      const dialog = record.target;
      if (!(dialog instanceof HTMLDialogElement)) continue;
      changed = true;
      const index = modalStack.indexOf(dialog);
      if (index >= 0) modalStack.splice(index, 1);
      if (isModal(dialog)) modalStack.push(dialog);
    }
    if (changed) rehomeOverlays();
  }).observe(document.documentElement, { subtree: true, attributes: true, attributeFilter: ["open"] });
  rehomeOverlays();
}

// ------------------------------------------------------------------------------------------ unsaved changes

let leavingOnPurpose = false;

/** The page is about to leave on purpose (logout, an expired session): unsaved edits no longer count. */
export function leaveOnPurpose() {
  leavingOnPurpose = true;
}

/** True when a setting control holds an unsaved value, or an open dialog's form has text the admin typed. */
export function hasUnsavedChanges(root = document) {
  if (leavingOnPurpose) return false;
  if (qs(".setting[data-dirty]", root)) return true;
  for (const form of qsa("dialog[open] form[data-dialog-form]", root)) {
    for (const field of qsa("input, textarea", form)) {
      const type = (field.getAttribute("type") || "text").toLowerCase();
      if (["hidden", "checkbox", "radio", "button", "submit", "reset"].includes(type)) continue;
      if (field.value !== field.defaultValue) return true;
    }
  }
  return false;
}

/** Run `fn` at most once per animation frame (resize and scroll handlers). */
export function rafThrottle(fn) {
  let queued = false;
  let lastArgs = [];
  return (...args) => {
    lastArgs = args;
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      fn(...lastArgs);
    });
  };
}
