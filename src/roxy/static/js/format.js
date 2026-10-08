/**
 * Number, size, time and duration formatting and parsing for the browser side of the dashboard.
 *
 * What this is
 *   Formatters (`fmtNumber`, `fmtCompact`, `fmtBytes`, `fmtPercent`, `fmtDuration`, `fmtTime`, `fmtValue`) and the
 *   two parsers the setting control uses (`parseDuration` for "90s", "15m", "1h30m"; `parseBytes` for "64 MiB").
 *
 * Why it exists
 *   Numbers must read the same in a server-rendered tile (templates/components/format.html) and in a chart
 *   tooltip drawn in the browser. The parsers mirror roxy/config/catalog.py `parse_duration` and `parse_bytes` so
 *   the editor can say "= 5 minutes" as you type and flag a typo before the round trip; the server still
 *   validates every value (the browser is a convenience, never the guard).
 *
 * How it works
 *   Intl.NumberFormat with en-US grouping. Durations accept a plain number in the setting's own unit, or one or more
 *   "<number><unit>" parts; sizes accept a plain number or one "<number> <unit>" with SI (KB = 1000) or IEC
 *   (KiB = 1024) units, exactly like the catalog. Missing values format as "n/a" (plan C5 replaced v1's dash).
 *
 * What to read next
 *   roxy/config/catalog.py (`parse_duration`, `parse_bytes`), then static/js/components.js.
 */

const NUMBER = new Intl.NumberFormat("en-US");
const DECIMAL = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });

export function fmtNumber(value, digits = 0) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "n/a";
  return new Intl.NumberFormat("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(value);
}

/** Significant digits that matter: 1234 stays whole, 43.38 becomes 43.4, 0.274 becomes 0.27. */
function fmtSmall(value) {
  const abs = Math.abs(value);
  if (Number.isInteger(value) || abs >= 100) return NUMBER.format(Math.round(value));
  if (abs >= 10) return value.toFixed(1);
  return DECIMAL.format(value);
}

export function fmtCompact(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return "n/a";
  const abs = Math.abs(value);
  if (abs < 1000) return fmtSmall(value);
  if (abs < 1e6) return `${(value / 1e3).toFixed(1)}k`;
  if (abs < 1e9) return `${(value / 1e6).toFixed(1)}M`;
  return `${(value / 1e9).toFixed(1)}B`;
}

export function fmtBytes(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return "n/a";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let n = Math.abs(value);
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  const sign = value < 0 ? "-" : "";
  return i === 0 ? `${sign}${NUMBER.format(n)} B` : `${sign}${n.toFixed(1)} ${units[i]}`;
}

export function fmtPercent(ratio, digits = 1) {
  if (ratio === null || ratio === undefined || !Number.isFinite(Number(ratio))) return "n/a";
  return `${(ratio * 100).toFixed(digits)}%`;
}

/** Seconds as "45s", "3m 20s", "2h 5m", "3d 4h". */
export function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined || !Number.isFinite(Number(seconds))) return "n/a";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${s % 60 ? ` ${s % 60}s` : ""}`;
  if (s < 86400) {
    const m = Math.floor((s % 3600) / 60);
    return `${Math.floor(s / 3600)}h${m ? ` ${m}m` : ""}`;
  }
  const h = Math.floor((s % 86400) / 3600);
  return `${Math.floor(s / 86400)}d${h ? ` ${h}h` : ""}`;
}

/** Words for a duration in milliseconds: "1 hour 30 minutes", "500 milliseconds". */
export function humanDuration(ms) {
  if (!Number.isFinite(ms)) return "";
  if (ms === 0) return "0 seconds";
  if (ms < 1000) return `${NUMBER.format(ms)} millisecond${ms === 1 ? "" : "s"}`;
  const parts = [];
  let rest = Math.round(ms / 1000);
  for (const [size, name] of [[604800, "week"], [86400, "day"], [3600, "hour"], [60, "minute"], [1, "second"]]) {
    if (rest >= size) {
      const count = Math.floor(rest / size);
      rest -= count * size;
      parts.push(`${NUMBER.format(count)} ${name}${count === 1 ? "" : "s"}`);
    }
    if (parts.length === 2) break;
  }
  return parts.join(" ");
}

/** HH:MM:SS (or "Mon 14:02" with `withDay`) in the browser's time zone. */
export function fmtTime(epochSeconds, { withDay = false, withSeconds = true } = {}) {
  if (!Number.isFinite(epochSeconds)) return "n/a";
  const date = new Date(epochSeconds * 1000);
  const options = { hour: "2-digit", minute: "2-digit", hour12: false };
  if (withSeconds) options.second = "2-digit";
  if (withDay) Object.assign(options, { weekday: "short", month: "short", day: "numeric" });
  return new Intl.DateTimeFormat("en-US", options).format(date);
}

/** Format a chart value by the axis format: count, bytes, percent (a ratio), ms, seconds. */
export function fmtValue(value, format = "count", unit = "") {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return "n/a";
  switch (format) {
    case "bytes":
      return fmtBytes(value);
    case "percent":
      return fmtPercent(value);
    case "ms":
      return value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${fmtSmall(value)} ms`;
    case "seconds":
      return fmtDuration(value);
    default:
      return unit ? `${fmtCompact(value)} ${unit}` : fmtCompact(value);
  }
}

/** A plain number from text, allowing thousands separators; null when the text is not a number. */
export function parseNumber(text) {
  const clean = String(text).trim().replace(/[,_\s]/g, "");
  if (!/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(clean)) return null;
  const value = Number(clean);
  return Number.isFinite(value) ? value : null;
}

const DURATION_MS = {
  ms: 1, msec: 1, millisecond: 1, milliseconds: 1,
  s: 1000, sec: 1000, secs: 1000, second: 1000, seconds: 1000,
  m: 60000, min: 60000, mins: 60000, minute: 60000, minutes: 60000,
  h: 3600000, hr: 3600000, hrs: 3600000, hour: 3600000, hours: 3600000,
  d: 86400000, day: 86400000, days: 86400000,
  w: 604800000, week: 604800000, weeks: 604800000,
};
const DURATION_TEXT = /^\d+(?:\.\d+)?\s*[a-z]+(?:\s*\d+(?:\.\d+)?\s*[a-z]+)*$/;
const DURATION_PART = /(\d+(?:\.\d+)?)\s*([a-z]+)/g;
const MAX_DURATION_TEXT = 64;

/**
 * Parse a duration into the setting's unit (unitMs = 1000 for seconds settings, 1 for milliseconds).
 * Returns {value} or {error}. Mirrors catalog.parse_duration, including "must be whole".
 */
export function parseDuration(text, unitMs = 1000) {
  const unitName = unitMs === 1 ? "milliseconds" : "seconds";
  const hint = `Enter a duration such as 90, 90s, 15m or 2h (a plain number means ${unitName})`;
  const raw = String(text).trim().toLowerCase();
  if (raw === "") return { error: hint };
  let totalMs;
  if (/[a-z]/.test(raw)) {
    if (raw.length > MAX_DURATION_TEXT || !DURATION_TEXT.test(raw)) return { error: hint };
    totalMs = 0;
    for (const [, amount, suffix] of raw.matchAll(DURATION_PART)) {
      const factor = DURATION_MS[suffix];
      if (factor === undefined) return { error: `Unknown time unit "${suffix}". ${hint}` };
      totalMs += Number(amount) * factor;
    }
  } else {
    const number = parseNumber(raw);
    if (number === null) return { error: hint };
    totalMs = number * unitMs;
  }
  const value = totalMs / unitMs;
  if (!Number.isInteger(Math.round(value * 1e9) / 1e9)) return { error: `Must be a whole number of ${unitName}` };
  return { value: Math.round(value), ms: totalMs };
}

const BYTE_SUFFIX = {
  b: 1, byte: 1, bytes: 1,
  kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12,
  kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3, tib: 1024 ** 4,
};

/** Parse a size into bytes (unitBytes = 1 for byte settings). Returns {value} or {error}; mirrors catalog. */
export function parseBytes(text, unitBytes = 1) {
  const hint = "Enter a size such as 65536, 64 KiB, 64 MiB or 1 GiB (KB, MB and GB are powers of 1000)";
  const raw = String(text).trim().toLowerCase().replace(/[,_]/g, "");
  if (raw === "") return { error: hint };
  let total;
  if (/[a-z]/.test(raw)) {
    const found = /^(\d+(?:\.\d+)?)\s*([a-z]+)$/.exec(raw);
    if (!found || BYTE_SUFFIX[found[2]] === undefined) return { error: hint };
    total = Number(found[1]) * BYTE_SUFFIX[found[2]];
  } else {
    const number = parseNumber(raw);
    if (number === null) return { error: hint };
    total = number * unitBytes;
  }
  const value = total / unitBytes;
  if (!Number.isInteger(Math.round(value * 1e6) / 1e6)) return { error: "Must be a whole number of bytes" };
  return { value: Math.round(value), bytes: total };
}
