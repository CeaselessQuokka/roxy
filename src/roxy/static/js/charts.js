/**
 * Time-series charts on uPlot (plan 14.5): zoom, crosshair readout, legend toggles, comparison, annotations.
 *
 * What this is
 *   `initCharts(root)` turns every `<figure data-chart>` (templates/components/chart.html) into a uPlot chart. The
 *   spec comes from the figure's `data-spec` JSON or is fetched from `data-src` (shape documented in chart.html).
 *
 * Why it exists
 *   uPlot draws tens of thousands of points on a canvas quickly and is about 50 KB, which keeps the dashboard light
 *   (plan 14.10). This wrapper adds what the plan requires around it:
 *   - Zoom by dragging across the plot, and also with buttons (dragging must never be the only way, WCAG 2.5.7);
 *     double click or "Show the whole range" resets.
 *   - A crosshair readout with the value of every series at the pointer, in the legend and in a small tooltip.
 *   - A legend of real buttons (aria-pressed) to hide and show series from the keyboard; uPlot's own legend is a
 *     table of clickable rows, so it is hidden.
 *   - The comparison period as dashed lines, stacked areas (a band between each series and the one below it),
 *     and annotation markers for config changes and incidents (dashed vertical lines, a dot you can hover, and
 *     the visible list under the chart that links to the audit entry).
 *   - Accessibility: a plain-language summary is the plot's accessible name, and the same data is a real table
 *     inside "Show the data as a table" (at most 500 rows, sampled evenly, with a note when sampled).
 *
 * How it works
 *   Colors are design tokens. A canvas cannot use CSS variables, and the tokens are light-dark() pairs, so each
 *   token is resolved through a hidden probe element (getComputedStyle gives the final rgb). On a `roxy:theme`
 *   event every chart is rebuilt with the new colors, keeping its zoom. Sizes follow the container through a
 *   ResizeObserver. Styles are set through the CSSOM only (`node.style.left = ...`), which the CSP allows; there
 *   are no inline style attributes. uPlot animates nothing, which also satisfies prefers-reduced-motion.
 *   Bounded memory (plan P9): a uPlot instance registers window listeners and holds its canvas, so a chart that
 *   leaves the page must be destroyed or it lives as long as the tab. A chart is destroyed when htmx is about to
 *   remove it (`htmx:beforeCleanupElement`), when its ResizeObserver reports it disconnected (any other removal:
 *   observers fire when an observed element leaves the document), and when a later scan finds it gone.
 *
 * What to read next
 *   templates/components/chart.html (the spec), static/css/components.css (chart and uPlot rules),
 *   static/vendor/VERSIONS.md (the pinned uPlot build).
 */

import uPlot from "vendor/uplot";
import { el, qs, qsa, rafThrottle } from "roxy/dom";
import { fmtTime, fmtValue } from "roxy/format";
import { getJSON } from "roxy/net";

const MAX_TABLE_ROWS = 500;
const MAX_SERIES = 8;
const live = new Set();
const byFigure = new WeakMap();
let probe = null;
let listening = false;

function resolveColor(token) {
  if (!probe) {
    probe = el("span", { "aria-hidden": "true", class: "sr-only" });
    document.body.append(probe);
  }
  probe.style.color = `var(${token})`;
  return getComputedStyle(probe).color;
}

function withAlpha(rgb, alpha) {
  const parts = rgb.match(/[\d.]+/g);
  return parts && parts.length >= 3 ? `rgba(${parts[0]}, ${parts[1]}, ${parts[2]}, ${alpha})` : rgb;
}

function themeColors() {
  return {
    series: Array.from({ length: MAX_SERIES }, (_, i) => resolveColor(`--series-${i + 1}`)),
    text: resolveColor("--text-muted"),
    grid: resolveColor("--chart-grid"),
    axis: resolveColor("--chart-axis"),
    info: resolveColor("--info"),
    bad: resolveColor("--bad"),
    surface: resolveColor("--surface-1"),
  };
}

class Chart {
  constructor(figure) {
    this.figure = figure;
    this.plot = qs("[data-chart-plot]", figure);
    this.legend = qs("[data-chart-legend]", figure);
    this.tableBox = qs("[data-chart-table]", figure);
    this.title = (qs(".chart__title", figure)?.textContent || "Chart").trim();
    this.u = null;
    this.tip = null;
    this.marks = [];
    this.legendButtons = [];
    this.observer = null;
    this.destroyed = false;
    this.figure.dataset.chartReady = "loading";
    this.load();
  }

  async load() {
    try {
      this.spec = this.figure.dataset.spec ? JSON.parse(this.figure.dataset.spec) : await getJSON(this.figure.dataset.src);
    } catch {
      if (!this.destroyed) this.fail("The chart data could not be loaded. Reload the page to try again.");
      return;
    }
    if (this.destroyed || !this.figure.isConnected) {  // removed while its data was loading
      this.destroy();
      return;
    }
    this.prepare();
    if (!this.x.length) {
      this.fail("No data in this range yet.");
      return;
    }
    this.build();
    this.buildLegend();
    this.renderTable();
    this.describe();
    this.bindTools();
    this.observer = new ResizeObserver(rafThrottle(() => {
      if (!this.figure.isConnected) this.destroy();  // the figure left the page
      else this.resize();
    }));
    this.observer.observe(this.plot);
    this.figure.dataset.chartReady = "1";
  }

  /** Release everything this chart holds: uPlot (its canvas and window listeners) and the observer. */
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    if (this.observer) this.observer.disconnect();
    this.observer = null;
    if (this.u) this.u.destroy();
    this.u = null;
    this.tip = null;
    this.marks = [];
    live.delete(this);
    if (byFigure.get(this.figure) === this) byFigure.delete(this.figure);
    delete this.figure.dataset.chartReady;  // put back on a page later, it is built again
  }

  fail(message) {
    this.plot.replaceChildren(el("p", { class: "chart__loading", text: message }));
    this.figure.dataset.chartReady = "error";
  }

  prepare() {
    const spec = this.spec;
    this.x = Array.isArray(spec.x) ? spec.x : [];
    this.yFormat = (spec.y && spec.y.format) || "count";
    this.yUnit = (spec.y && spec.y.unit) || "";
    this.yMin = spec.y && Number.isFinite(spec.y.min) ? spec.y.min : null;
    this.compareLabel = spec.compare_label || "Comparison";
    this.annotations = Array.isArray(spec.annotations) ? spec.annotations : [];
    this.series = (spec.series || []).slice(0, MAX_SERIES).map((s, i) => ({
      label: String(s.label || `Series ${i + 1}`),
      values: Array.isArray(s.values) ? s.values : [],
      slot: Math.min(Math.max(Number(s.color) || i + 1, 1), MAX_SERIES),
      kind: s.kind || "line",
      stack: s.stack || null,
      compare: Array.isArray(s.compare) ? s.compare : null,
    }));
    // Stacked series are drawn as running totals; the raw values stay for the legend, tooltip and table.
    const totals = new Map();
    const previous = new Map();
    this.plotted = this.series.map((s, i) => {
      if (!s.stack) return s.values;
      const base = totals.get(s.stack) || this.x.map(() => 0);
      const top = this.x.map((_, j) => (s.values[j] ?? 0) + base[j]);
      s.below = previous.has(s.stack) ? previous.get(s.stack) : null;
      totals.set(s.stack, top);
      previous.set(s.stack, i);
      return top;
    });
    this.compareIndex = [];
    this.series.forEach((s, i) => {
      if (s.compare) this.compareIndex.push(i);
    });
  }

  options(colors) {
    const font = `12px ${getComputedStyle(document.body).fontFamily}`;
    const fmt = (v) => fmtValue(v, this.yFormat, "");
    const series = [{ value: (u, v) => (v == null ? "n/a" : fmtTime(v, { withDay: true })) }];
    const bands = [];
    this.series.forEach((s, i) => {
      const color = colors.series[s.slot - 1];
      const option = {
        label: s.label,
        stroke: color,
        width: s.kind === "bars" ? 0 : 2,
        points: { show: this.x.length <= 2 },
        value: (u, v) => fmt(v),
      };
      if (s.kind === "bars") {
        option.fill = withAlpha(color, 0.85);
        option.paths = uPlot.paths.bars({ size: [0.7, 48], gap: 2 });
      } else if (s.kind === "area" || s.stack) {
        option.fill = withAlpha(color, s.stack ? 0.28 : 0.12);
      }
      if (s.stack && s.below !== null) {
        bands.push({ series: [i + 1, s.below + 1], fill: withAlpha(color, 0.28) });
        option.fill = undefined;
      }
      series.push(option);
    });
    for (const i of this.compareIndex) {
      const s = this.series[i];
      series.push({
        label: `${s.label} (${this.compareLabel})`,
        stroke: withAlpha(colors.series[s.slot - 1], 0.75),
        width: 1.5,
        dash: [5, 4],
        points: { show: false },
        value: (u, v) => fmt(v),
      });
    }
    const yMin = this.yMin;
    return {
      width: Math.max(this.plot.clientWidth, 120),
      height: Math.max(this.plot.clientHeight, 120),
      class: "roxy-uplot",
      legend: { show: false },
      focus: { alpha: 0.35 },
      cursor: {
        drag: { x: true, y: false, setScale: true },
        points: { size: 7, width: 2, fill: colors.surface },
        focus: { prox: 30 },
      },
      scales: {
        x: { time: true },
        y: {
          range: (u, lo, hi) => {
            const min = yMin ?? Math.min(0, lo ?? 0);
            let max = hi ?? 1;
            if (!(max > min)) max = min + 1;
            return [min, max + (max - min) * 0.08];
          },
        },
      },
      axes: [
        {
          stroke: colors.text,
          font,
          grid: { stroke: colors.grid, width: 1 },
          ticks: { stroke: colors.axis, width: 1, size: 4 },
          space: 70,
        },
        {
          stroke: colors.text,
          font,
          size: 56,
          gap: 6,
          grid: { stroke: colors.grid, width: 1 },
          ticks: { show: false },
          values: (u, splits) => splits.map((v) => fmt(v)),
        },
      ],
      series,
      bands,
      hooks: {
        setCursor: [(u) => this.onCursor(u)],
        draw: [(u) => this.drawAnnotations(u, colors)],
        setScale: [(u, key) => {
          if (key === "x") this.onZoom(u);
        }],
      },
    };
  }

  data() {
    return [this.x, ...this.plotted, ...this.compareIndex.map((i) => this.series[i].compare)];
  }

  build(keepScale = null) {
    const colors = themeColors();
    this.plot.replaceChildren();
    this.u = new uPlot(this.options(colors), this.data(), this.plot);
    this.tip = el("div", { class: "chart__tip", "aria-hidden": "true", hidden: true });
    this.plot.append(this.tip);
    this.marks = this.annotations.map((note) => {
      const mark = el("span", {
        class: `chart__mark chart__mark--${note.kind === "incident" ? "incident" : "config"}`,
        "aria-hidden": "true",
        "data-tip": [note.when, note.label].filter(Boolean).join(": "),
      });
      this.u.over.append(mark);
      return mark;
    });
    for (const button of this.legendButtons) {
      if (button.getAttribute("aria-pressed") === "false") this.applyVisibility(button, false);
    }
    if (keepScale) this.u.setScale("x", keepScale);
    this.positionMarks();
    this.onCursor(this.u);
  }

  rebuild() {
    if (!this.u) return;
    const scale = { min: this.u.scales.x.min, max: this.u.scales.x.max };
    this.u.destroy();
    this.build(scale);
  }

  resize() {
    if (!this.u) return;
    const width = Math.max(this.plot.clientWidth, 120);
    const height = Math.max(this.plot.clientHeight, 120);
    if (width !== this.u.width || height !== this.u.height) this.u.setSize({ width, height });
    this.positionMarks();
  }

  buildLegend() {
    if (!this.legend) return;
    this.legend.replaceChildren();
    this.legendButtons = [];
    this.series.forEach((s, i) => {
      const value = el("span", { class: "legend-item__value" });
      const button = el("button", { type: "button", class: "legend-item", "aria-pressed": "true", "data-series": String(i) }, [
        el("span", { class: `swatch sw-${s.slot}`, "aria-hidden": "true" }),
        el("span", { class: "legend-item__label", text: s.label }),
        value,
      ]);
      button.addEventListener("click", () => this.toggle(button));
      this.legend.append(button);
      this.legendButtons.push(button);
    });
    if (this.compareIndex.length) {
      const first = this.series[this.compareIndex[0]];
      const button = el("button", { type: "button", class: "legend-item", "aria-pressed": "true", "data-series": "compare" }, [
        el("span", { class: `swatch swatch--compare sw-${first.slot}`, "aria-hidden": "true" }),
        el("span", { class: "legend-item__label", text: this.compareLabel }),
      ]);
      button.addEventListener("click", () => this.toggle(button));
      this.legend.append(button);
      this.legendButtons.push(button);
    }
  }

  applyVisibility(button, show) {
    const which = button.dataset.series;
    if (which === "compare") {
      this.compareIndex.forEach((_, k) => this.u.setSeries(this.series.length + 1 + k, { show }));
    } else {
      const i = Number(which);
      this.u.setSeries(i + 1, { show });
      const k = this.compareIndex.indexOf(i);
      const compareShown = this.legendButtons.find((b) => b.dataset.series === "compare");
      if (k >= 0 && (!compareShown || compareShown.getAttribute("aria-pressed") === "true")) {
        this.u.setSeries(this.series.length + 1 + k, { show });
      }
    }
  }

  toggle(button) {
    const show = button.getAttribute("aria-pressed") !== "true";
    button.setAttribute("aria-pressed", String(show));
    this.applyVisibility(button, show);
  }

  latestIndex(values) {
    for (let j = values.length - 1; j >= 0; j -= 1) if (values[j] !== null && values[j] !== undefined) return j;
    return -1;
  }

  onCursor(u) {
    const idx = u.cursor.idx;
    this.legendButtons.forEach((button) => {
      const value = qs(".legend-item__value", button);
      if (!value) return;
      const s = this.series[Number(button.dataset.series)];
      const j = idx === null || idx === undefined ? this.latestIndex(s.values) : idx;
      value.textContent = j >= 0 ? fmtValue(s.values[j], this.yFormat, "") : "n/a";
    });
    if (!this.tip) return;
    if (idx === null || idx === undefined || u.cursor.left < 0) {
      this.tip.hidden = true;
      return;
    }
    const rows = [el("div", { class: "chart__tip-time", text: fmtTime(this.x[idx], { withDay: true }) })];
    this.series.forEach((s, i) => {
      if (!u.series[i + 1].show) return;
      rows.push(el("div", { class: "chart__tip-row" }, [
        el("span", { class: `swatch sw-${s.slot}` }), el("span", { text: s.label }),
        el("span", { text: fmtValue(s.values[idx], this.yFormat, this.yUnit) }),
      ]));
      const k = this.compareIndex.indexOf(i);
      if (k >= 0 && u.series[this.series.length + 1 + k].show) {
        rows.push(el("div", { class: "chart__tip-row" }, [
          el("span", { class: `swatch swatch--compare sw-${s.slot}` }), el("span", { text: this.compareLabel }),
          el("span", { text: fmtValue(s.compare[idx], this.yFormat, this.yUnit) }),
        ]));
      }
    });
    this.tip.replaceChildren(...rows);
    this.tip.hidden = false;
    const over = u.over.getBoundingClientRect();
    const host = this.plot.getBoundingClientRect();
    const tipWidth = this.tip.offsetWidth;
    let left = over.left - host.left + u.cursor.left + 14;
    if (left + tipWidth > host.width) left = over.left - host.left + u.cursor.left - tipWidth - 14;
    this.tip.style.transform = `translate(${Math.max(0, Math.round(left))}px, ${Math.round(over.top - host.top + 4)}px)`;
  }

  onZoom(u) {
    const reset = qs('[data-chart-zoom="reset"]', this.figure);
    const zoomed = u.scales.x.min > this.x[0] || u.scales.x.max < this.x[this.x.length - 1];
    if (reset) reset.setAttribute("aria-pressed", String(zoomed));
    this.positionMarks();
  }

  positionMarks() {
    if (!this.u) return;
    const { min, max } = this.u.scales.x;
    this.annotations.forEach((note, i) => {
      const mark = this.marks[i];
      if (!mark) return;
      const inside = note.t >= min && note.t <= max;
      mark.hidden = !inside;
      if (inside) mark.style.left = `${Math.round(this.u.valToPos(note.t, "x"))}px`;
    });
  }

  drawAnnotations(u, colors) {
    const { min, max } = u.scales.x;
    const ctx = u.ctx;
    for (const note of this.annotations) {
      if (!(note.t >= min && note.t <= max)) continue;
      const x = Math.round(u.valToPos(note.t, "x", true));
      ctx.save();
      ctx.strokeStyle = withAlpha(note.kind === "incident" ? colors.bad : colors.info, 0.8);
      ctx.lineWidth = Math.max(1, window.devicePixelRatio || 1);
      ctx.setLineDash([4 * (window.devicePixelRatio || 1), 4 * (window.devicePixelRatio || 1)]);
      ctx.beginPath();
      ctx.moveTo(x, u.bbox.top);
      ctx.lineTo(x, u.bbox.top + u.bbox.height);
      ctx.stroke();
      ctx.restore();
    }
  }

  zoom(direction) {
    if (!this.u) return;
    const first = this.x[0];
    const last = this.x[this.x.length - 1];
    if (direction === "reset") {
      this.u.setScale("x", { min: first, max: last });
      return;
    }
    const { min, max } = this.u.scales.x;
    const span = max - min;
    const center = min + span / 2;
    const next = direction === "in" ? span / 2 : Math.min(span * 2, last - first);
    let low = Math.max(first, center - next / 2);
    let high = Math.min(last, low + next);
    low = Math.max(first, high - next);
    if (high - low > 0) this.u.setScale("x", { min: low, max: high });
  }

  bindTools() {
    for (const button of qsa("[data-chart-zoom]", this.figure)) {
      button.addEventListener("click", () => this.zoom(button.dataset.chartZoom));
    }
  }

  renderTable() {
    if (!this.tableBox || qs("table", this.tableBox)) return;
    const step = Math.max(1, Math.ceil(this.x.length / MAX_TABLE_ROWS));
    const head = el("tr", {}, [el("th", { scope: "col", text: "Time" })]);
    this.series.forEach((s) => {
      head.append(el("th", { scope: "col", class: "num", text: s.label }));
      if (s.compare) head.append(el("th", { scope: "col", class: "num", text: `${s.label} (${this.compareLabel})` }));
    });
    const body = el("tbody");
    for (let j = 0; j < this.x.length; j += step) {
      const row = el("tr", {}, [el("th", { scope: "row", text: fmtTime(this.x[j], { withDay: true }) })]);
      this.series.forEach((s) => {
        row.append(el("td", { class: "num", text: fmtValue(s.values[j], this.yFormat, this.yUnit) }));
        if (s.compare) row.append(el("td", { class: "num", text: fmtValue(s.compare[j], this.yFormat, this.yUnit) }));
      });
      body.append(row);
    }
    const caption = el("caption", { class: "sr-only", text: `${this.title}, data table` });
    const table = el("table", { class: "simple-table" }, [caption, el("thead", {}, [head]), body]);
    const nodes = [table];
    if (step > 1) {
      nodes.unshift(el("p", { class: "muted", text: `Every ${step}th point is shown (${MAX_TABLE_ROWS} rows at most).` }));
    }
    this.tableBox.replaceChildren(...nodes);
  }

  describe() {
    if (this.plot.getAttribute("aria-label") !== this.title) return;  // the server gave a summary: keep it
    const parts = [`${this.title}: ${this.series.length} series from ${fmtTime(this.x[0], { withDay: true, withSeconds: false })} to ${fmtTime(this.x[this.x.length - 1], { withDay: true, withSeconds: false })}.`];
    for (const s of this.series.slice(0, 3)) {
      const j = this.latestIndex(s.values);
      const numbers = s.values.filter((v) => Number.isFinite(v));
      if (j < 0 || !numbers.length) continue;
      parts.push(`${s.label}: latest ${fmtValue(s.values[j], this.yFormat, this.yUnit)}, highest ${fmtValue(Math.max(...numbers), this.yFormat, this.yUnit)}.`);
    }
    this.plot.setAttribute("aria-label", parts.join(" "));
  }
}

/** Destroy every chart whose figure is no longer in the document. */
function prune() {
  for (const chart of Array.from(live)) if (!chart.figure.isConnected) chart.destroy();
}

export function initCharts(root = document) {
  prune();
  const figures = root instanceof Element && root.matches("[data-chart]") ? [root] : qsa("[data-chart]", root);
  for (const figure of figures) {
    if (figure.dataset.chartReady) continue;
    const chart = new Chart(figure);
    if (chart.destroyed) continue;
    live.add(chart);
    byFigure.set(figure, chart);
  }
  if (!listening) {
    listening = true;
    document.addEventListener("roxy:theme", () => {
      prune();
      for (const chart of Array.from(live)) chart.rebuild();
    });
    // htmx raises this on every element of the content it is about to remove (swaps, outerHTML replacements).
    document.addEventListener("htmx:beforeCleanupElement", (event) => {
      const chart = event.target instanceof Element ? byFigure.get(event.target) : null;
      if (chart) chart.destroy();
    });
  }
}
