/**
 * Alpine.js components for small pieces of form state: the setting control and type-to-confirm.
 *
 * What this is
 *   `registerComponents(Alpine)` defines `settingControl` (templates/components/setting.html) and `typeConfirm`
 *   (templates/components/dialog.html). Markup refers to them by name (`x-data="settingControl"`) and only to their
 *   properties and methods (`x-show="dirty"`, `x-on:input="onInput"`).
 *
 * Why it exists
 *   The CSP build of Alpine never evaluates code strings (no eval, no `new Function`, plan 9.2): expressions in
 *   attributes are parsed by its own small interpreter and can only read properties and call methods of
 *   components registered here. Keeping the logic in this module, not in attributes, also makes it readable and
 *   testable. The browser checks are a convenience: the server validates every value again with the catalog.
 *
 * How it works
 *   settingControl reads its configuration from data-* attributes rendered from the SettingSpec (type, unit,
 *   min, max, step, default, the high-risk conditions as JSON, enum option descriptions as JSON). On every input it
 *   parses the text the way roxy/config/catalog.py does (durations such as "15m" and sizes such as "64 MiB"
 *   included), shows the error or a plain-language preview, marks the field aria-invalid, keeps the slider and the
 *   text box in step, and says when the new value is high risk (then a reason and "I understand" are required).
 *   While the value differs from the saved one the form carries `data-dirty`, which the shortcut keys and the
 *   leave-page guard read so an unsaved edit is never discarded by surprise (static/js/dom.js).
 *   `revert` puts the saved value back; `resetToDefault` fills in the default without saving (parity row 124).
 *
 * What to read next
 *   templates/components/setting.html, static/js/format.js (the parsers), roxy/config/spec.py (RiskCondition).
 */

import { fmtBytes, fmtNumber, humanDuration, parseBytes, parseDuration, parseNumber } from "roxy/format";

function readJSON(text, fallback) {
  try {
    return text ? JSON.parse(text) : fallback;
  } catch {
    return fallback;
  }
}

function riskMatches(cond, value) {
  const target = cond.value;
  switch (cond.op) {
    case "eq": return value === target || String(value) === String(target);
    case "ne": return !(value === target || String(value) === String(target));
    case "gt": return typeof value === "number" && value > target;
    case "gte": return typeof value === "number" && value >= target;
    case "lt": return typeof value === "number" && value < target;
    case "lte": return typeof value === "number" && value <= target;
    case "in": return Array.isArray(target) && target.map(String).includes(String(value));
    default: return false;
  }
}

function inRange(value, min, max, unit) {
  const suffix = unit ? ` ${unit}` : "";
  if (min !== null && max !== null && (value < min || value > max)) {
    return `Must be between ${fmtNumber(min, Number.isInteger(min) ? 0 : 2)} and ${fmtNumber(max, Number.isInteger(max) ? 0 : 2)}${suffix}`;
  }
  if (min !== null && value < min) return `Must be at least ${fmtNumber(min)}${suffix}`;
  if (max !== null && value > max) return `Must be at most ${fmtNumber(max)}${suffix}`;
  return "";
}

/** Parse the control's text by setting type: {value, error, preview}. */
function parseSetting(cfg, text) {
  const trimmed = String(text).trim();
  switch (cfg.type) {
    case "bool":
      return { value: trimmed === "1" ? 1 : 0 };
    case "enum":
      return { value: trimmed };
    case "string":
      if (cfg.maxLength && trimmed.length > cfg.maxLength) return { error: `At most ${fmtNumber(cfg.maxLength)} characters` };
      return { value: trimmed };
    case "list[str]":
    case "list[int]":
    case "list[cidr]": {
      const items = trimmed.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
      if (cfg.maxLength && items.length > cfg.maxLength) return { error: `At most ${fmtNumber(cfg.maxLength)} entries` };
      if (cfg.type === "list[int]" && items.some((item) => !/^[+-]?\d+$/.test(item))) {
        return { error: "Every entry must be a whole number" };
      }
      if (cfg.type === "list[cidr]" && items.some((item) => !/^[0-9a-f:.]+(?:\/\d{1,3})?$/i.test(item))) {
        return { error: "Every entry must be an IP address or a range such as 203.0.113.0/24" };
      }
      return { value: items, preview: items.length ? `${items.length} entr${items.length === 1 ? "y" : "ies"}` : "Empty list" };
    }
    case "duration": {
      const parsed = parseDuration(trimmed, cfg.unitMs);
      if (parsed.error) return { error: parsed.error };
      const error = inRange(parsed.value, cfg.min, cfg.max, cfg.unit);
      return { value: parsed.value, error, preview: error ? "" : `= ${humanDuration(parsed.value * cfg.unitMs)}` };
    }
    case "bytes": {
      const parsed = parseBytes(trimmed, 1);
      if (parsed.error) return { error: parsed.error };
      const error = inRange(parsed.value, cfg.min, cfg.max, "bytes");
      return { value: parsed.value, error, preview: error ? "" : `= ${fmtBytes(parsed.value)} (${fmtNumber(parsed.value)} bytes)` };
    }
    default: {
      const number = parseNumber(trimmed);
      if (number === null) return { error: "Enter a number" };
      if (cfg.type === "int" && !Number.isInteger(number)) return { error: "Must be a whole number" };
      return { value: number, error: inRange(number, cfg.min, cfg.max, cfg.unit) };
    }
  }
}

function settingControl() {
  // DOM references live in this closure, not in Alpine's reactive state.
  let root = null;
  let input = null;
  let slider = null;
  let cfg = null;

  const currentText = () => {
    if (!input) return "";
    if (cfg.type === "bool") return input.checked ? "1" : "0";
    return input.value;
  };
  const setText = (text) => {
    if (!input) return;
    if (cfg.type === "bool") input.checked = String(text) === "1";
    else input.value = text;
    if (slider) {
      const number = parseNumber(text);
      if (number !== null) slider.value = String(number);
    }
  };

  return {
    dirty: false,
    error: "",  // the message on screen: the browser's own check, or the server's answer until the value changes
    invalid: false,  // only the browser's check disables Save; a server message (a missing reason) must not
    preview: "",
    riskWhy: "",
    optionText: "",

    get highRisk() {
      return this.riskWhy !== "";
    },

    init() {
      const data = this.$el.dataset;
      const numberOrNull = (value) => (value === undefined || value === "" ? null : Number(value));
      cfg = {
        type: data.type,
        unit: data.unit || "",
        min: numberOrNull(data.min),
        max: numberOrNull(data.max),
        maxLength: numberOrNull(data.maxLength),
        unitMs: Number(data.unitMs) || 1000,
        initial: data.initial ?? "",
        fallback: data.default ?? "",
        conds: readJSON(data.riskConds, []),
        options: readJSON(data.options, {}),
      };
      root = this.$el;
      input = this.$el.querySelector("[data-setting-input]");
      slider = this.$el.querySelector("[data-setting-slider]");
      this.check();
      if (data.serverError) {
        this.error = data.serverError;
        if (input) input.setAttribute("aria-invalid", "true");
      }
    },

    check() {
      const text = currentText();
      this.dirty = text.trim() !== String(cfg.initial).trim();
      // `data-dirty` on the form lets the page ask "would leaving lose an edit?" (dom.js hasUnsavedChanges).
      if (root) root.toggleAttribute("data-dirty", this.dirty);
      const result = parseSetting(cfg, text);
      this.invalid = Boolean(result.error);
      this.error = result.error || "";
      this.preview = this.invalid ? "" : result.preview || "";
      if (input) input.setAttribute("aria-invalid", this.invalid ? "true" : "false");
      const risky = this.invalid ? null : cfg.conds.find((cond) => riskMatches(cond, result.value));
      this.riskWhy = risky ? risky.why : "";
      if (cfg.type === "enum") this.optionText = cfg.options[result.value] || "";
    },

    onInput() {
      if (slider && cfg.type !== "duration" && cfg.type !== "bytes") {
        const number = parseNumber(currentText());
        if (number !== null) slider.value = String(number);
      }
      this.check();
    },

    onSlide(event) {
      if (input) input.value = event.target.value;
      this.check();
    },

    revert() {
      setText(cfg.initial);
      this.check();
    },

    resetToDefault() {
      setText(cfg.fallback);
      this.check();
      if (input) input.focus();
    },
  };
}

function typeConfirm() {
  return {
    typed: "",
    expected: "",
    get blocked() {
      return this.expected !== "" && this.typed.trim() !== this.expected;
    },
    init() {
      this.expected = this.$el.dataset.expected || "";
    },
    onType(event) {
      this.typed = event.target.value;
    },
    clear() {
      this.typed = "";
    },
  };
}

export function registerComponents(Alpine) {
  Alpine.data("settingControl", settingControl);
  Alpine.data("typeConfirm", typeConfirm);
}
