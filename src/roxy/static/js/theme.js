/**
 * Theme (dark, light, follow the system) and table density (plan 14.4).
 *
 * What this is
 *   `setTheme(name)`, `cycleTheme()` and `initTheme()`: the buttons with `data-theme-set` switch the theme, the
 *   checkbox with `data-density-toggle` switches dense tables, and both choices are remembered.
 *
 * Why it exists
 *   The server renders the admin's saved theme into `<html data-theme>` so the first paint is already right (no
 *   flash of the wrong colors). Switching only changes that attribute: every color is a token whose light and
 *   dark values are both defined (tokens.css), so the whole dashboard follows at once. Canvas charts cannot follow
 *   CSS by themselves, so a `roxy:theme` event tells static/js/charts.js to redraw with the new colors.
 *
 * How it works
 *   The choice is saved to the admin's preferences when the page offers a URL for that (`data-prefs-url` on
 *   <body>, posted with the CSRF header), and to this browser's storage otherwise; a stored browser choice is
 *   applied at load only when the server has no saved preference to offer. With "system", a change of the
 *   operating system's light or dark setting also raises `roxy:theme`.
 *
 * What to read next
 *   static/css/tokens.css (the light-dark() tokens), static/js/charts.js (the redraw).
 */

import { qsa, store } from "roxy/dom";
import { postForm } from "roxy/net";

const THEMES = ["system", "dark", "light"];
const root = document.documentElement;

function prefsUrl() {
  return document.body ? document.body.dataset.prefsUrl || "" : "";
}

function announceTheme() {
  document.dispatchEvent(new CustomEvent("roxy:theme", { detail: { theme: root.dataset.theme || "dark" } }));
}

function reflect(name) {
  for (const button of qsa("[data-theme-set]")) {
    button.setAttribute("aria-pressed", String(button.dataset.themeSet === name));
  }
}

export function currentTheme() {
  return root.dataset.theme || "dark";
}

export function setTheme(name, { save = true } = {}) {
  if (!THEMES.includes(name)) return;
  root.dataset.theme = name;
  reflect(name);
  announceTheme();
  if (!save) return;
  store.set("theme", name);
  const url = prefsUrl();
  if (url) postForm(url, { theme: name }).catch(() => {});
}

export function cycleTheme() {
  const next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
  setTheme(next);
  return next;
}

export function setDensity(dense) {
  root.dataset.density = dense ? "dense" : "comfortable";
  for (const box of qsa("[data-density-toggle]")) box.checked = dense;
  store.set("density", root.dataset.density);
  const url = prefsUrl();
  if (url) postForm(url, { density: root.dataset.density }).catch(() => {});
}

export function initTheme() {
  if (!prefsUrl()) {
    const saved = store.get("theme");
    if (THEMES.includes(saved) && saved !== currentTheme()) setTheme(saved, { save: false });
    const density = store.get("density");
    if (density === "dense" || density === "comfortable") root.dataset.density = density;
  }
  reflect(currentTheme());
  for (const box of qsa("[data-density-toggle]")) box.checked = root.dataset.density === "dense";

  document.addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest("[data-theme-set]") : null;
    if (button) setTheme(button.dataset.themeSet);
  });
  document.addEventListener("change", (event) => {
    if (event.target instanceof HTMLInputElement && event.target.matches("[data-density-toggle]")) {
      setDensity(event.target.checked);
    }
  });
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", () => {
    if (currentTheme() === "system") announceTheme();
  });
}
