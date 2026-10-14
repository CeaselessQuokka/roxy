/**
 * DOM helpers shared by every dashboard module.
 *
 * What this is
 *   `el()` builds elements without innerHTML, `icon()` builds a sprite icon, `qs()`/`qsa()` query, and `store`
 *   reads and writes this browser's remembered preferences. `initOverlayLayer()` keeps the page-wide overlays
 *   (tooltip, toasts, live regions) usable while a modal dialog is open, `hasUnsavedChanges()` says whether
 *   leaving the page now would lose an edit, and `reloadPage()` reloads the page once however many modules ask.
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

// ------------------------------------------------------------------------------------------ busy controls

/**
 * Keyboard focus survives a control that disables itself while its request runs (review finding a11y-8). A
 * disabled element cannot hold focus, so the browser moves it to <body> and it never comes back: the keyboard user
 * starts again from the top. This keeper notices a focused button or field becoming disabled (one MutationObserver
 * on the `disabled` attribute for the whole page, so every page's busy buttons are covered) and gives focus back
 * when it is enabled again, or, when a refresh replaced it, to its successor with the same id or action, as long as
 * focus is still on <body> (the admin has not moved on).
 */
export function initFocusKeeper() {
  let lastFocused = null;
  const parked = new Map();  // the disabled element -> how to find its successor
  document.addEventListener("focusin", (event) => {
    const target = event.target instanceof HTMLElement ? event.target : null;
    lastFocused = target;
    if (target && target !== document.body && !parked.has(target)) parked.clear();  // the admin moved on
  }, true);
  const idle = () => !document.activeElement || document.activeElement === document.body;
  const restore = () => {
    for (const [node, twin] of parked) {
      if (document.activeElement === node) {
        if (!node.disabled) parked.delete(node);  // enabled again before the browser moved focus away
        continue;
      }
      if (!idle()) continue;
      if (node.isConnected && !node.disabled) {
        parked.delete(node);
        node.focus();
      } else if (!node.isConnected) {
        parked.delete(node);
        const successor = twin ? document.querySelector(twin) : null;
        if (successor instanceof HTMLElement && !successor.disabled) successor.focus();
      }
    }
  };
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      const node = record.target;
      // The browser moves focus off a disabled element only at its next rendering step, so the element may still
      // be the active one here: it is parked either way, and given focus back only while focus is on <body>.
      if (record.type === "attributes" && node instanceof HTMLElement && node.disabled
          && (node === document.activeElement || node === lastFocused)) {
        const twin = node.id ? `#${CSS.escape(node.id)}`
          : node.dataset.action ? `[data-action="${CSS.escape(node.dataset.action)}"]` : "";
        parked.set(node, twin);
      }
    }
    if (parked.size) restore();
  });
  observer.observe(document.body, { attributes: true, attributeFilter: ["disabled"], childList: true, subtree: true });
}

// ------------------------------------------------------------------------------------------ reloading

let reloadStarted = false;
let unloading = false;
const RELOAD_KEPT_MS = 1500;

window.addEventListener("pagehide", () => {
  unloading = true;
});

/** Reload the page once. One change can ask twice (an action's own reload after its API answer, and the shell's
 *  status check when the stream reports the same change); a second `location.reload()` would abort the navigation the
 *  first one started, so every later call is ignored. `delayMs` lets a toast be seen first.
 *  When an unsaved edit makes the browser ask "Leave site?" and the admin stays, the page was not replaced: the
 *  pending mark is cleared and `roxy:reload-kept` lets the shell redraw what the reload was for (the top bar,
 *  banners and dialogs after a pause; review finding functional-8). The browser's question pauses this page's
 *  timers, so the check runs only after the admin answered it. */
export function reloadPage({ delayMs = 0 } = {}) {
  if (reloadStarted) return;
  reloadStarted = true;
  const reload = () => {
    const asks = hasUnsavedChanges();
    window.location.reload();
    if (!asks) return;
    window.setTimeout(() => {
      if (unloading) return;
      reloadStarted = false;
      document.dispatchEvent(new CustomEvent("roxy:reload-kept"));
    }, RELOAD_KEPT_MS);
  };
  if (delayMs > 0) window.setTimeout(reload, delayMs);
  else reload();
}

/** True once `reloadPage` was asked: the page is about to be replaced, so there is nothing left to check. */
export function reloadPending() {
  return reloadStarted;
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
