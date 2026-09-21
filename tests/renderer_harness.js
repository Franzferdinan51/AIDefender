#!/usr/bin/env node
"use strict";
const fs = require("fs");
const path = require("path");

const ui = path.join(__dirname, "..", "ui", "renderer");
const html = fs.readFileSync(path.join(ui, "index.html"), "utf8");
const js = fs.readFileSync(path.join(ui, "app.js"), "utf8");

function parseTabs(markup) {
  const tabs = [];
  const re = /data-tab="([^"]+)"/g;
  let m;
  while ((m = re.exec(markup))) tabs.push(m[1]);
  return tabs;
}

class Elem {
  constructor(id, tag) {
    this.id = id || "";
    this.tagName = (tag || "div").toUpperCase();
    this.children = [];
    this.listeners = {};
    this.className = "";
    this._text = "";
    this.value = "";
    this.checked = false;
    this.attributes = {};
  }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); }
  getAttribute(name) { return this.attributes[name] || this.id; }
  setAttribute(name, val) { this.attributes[name] = val; }
  classList = {
    add: (c) => { this.className += " " + c; },
    remove: (_c) => {},
  };
  addEventListener(ev, fn) {
    this.listeners[ev] = this.listeners[ev] || [];
    this.listeners[ev].push(fn);
  }
  click() {
    (this.listeners.click || []).forEach((fn) => fn());
  }
}

const byId = {};
const navButtons = [];
parseTabs(html).forEach((tab) => {
  const btn = new Elem("nav-" + tab, "button");
  btn.attributes["data-tab"] = tab;
  navButtons.push(btn);
  byId[tab] = new Elem(tab, "section");
});
[
  "cli-pill", "dash-out", "scan-out", "scan-path", "scan-quarantine",
  "protect-out", "q-out", "intel-out", "ids-out", "eng-out",
  "analyze-out", "analyze-path", "allow-out", "allow-kind", "allow-value",
  "allow-note", "diag-out", "processes-out", "network-out", "events-out",
  "refresh-dash", "update-defs", "pick-folder", "pick-file", "run-scan",
  "protect-once", "service-install", "service-status", "q-refresh",
  "intel-update", "ids-check", "eng-refresh", "pick-analyze", "run-analyze",
  "allow-list", "allow-add", "allow-remove", "run-diag", "run-processes",
  "run-network", "run-events", "ai-detect", "ai-preset", "ai-url", "ai-model",
  "ai-use", "ai-test", "ai-out", "cfg-load", "cfg-key", "cfg-value",
  "cfg-save", "cfg-out",
].forEach((id) => {
  if (!byId[id]) byId[id] = new Elem(id);
});

const document = {
  getElementById(id) { return byId[id] || null; },
  querySelectorAll(sel) {
    if (sel === "nav button") return navButtons;
    if (sel === ".tab") return parseTabs(html).map((t) => byId[t]);
    return [];
  },
};

const calls = [];
const window = {
  aidefender: {
    run: async (args) => {
      calls.push(args.slice());
      return { code: 0, stdout: JSON.stringify({ ok: true, argv: args }), stderr: "" };
    },
    pick: async () => "",
    cliInfo: async () => ({ bundled: false, command: "python3", prefix: ["-m", "aidefender"] }),
  },
};

global.window = window;
global.document = document;

try {
  eval(js);
} catch (err) {
  console.error("THROW", err && err.stack ? err.stack : err);
  process.exit(1);
}

const tabs = parseTabs(html);
const needed = ["dash", "scan", "protect", "quarantine", "intel", "intrusion", "engines", "analyze", "allow", "diag", "processes", "network", "events", "settings"];
const missing = needed.filter((t) => tabs.indexOf(t) < 0);
if (missing.length) {
  console.error("MISSING_TABS", missing.join(","));
  process.exit(1);
}

setTimeout(() => {
  const usedIpc = calls.some((a) => a[0] === "--json");
  const report = {
    ok: true,
    tabs,
    ipc: "window.aidefender",
    jsonCalls: calls.length,
    usedJsonFlag: usedIpc,
    dashText: (byId["dash-out"].textContent || "").slice(0, 200),
  };
  console.log(JSON.stringify(report, null, 2));
}, 50);
