/* Tab → CLI argv after the global --json flag. Keep in sync with tests/test_ui.py */
var CLI_COMMANDS = {
  status: ["status"],
  engines: ["engines"],
  scan: ["scan"],
  protect: ["protect", "--once"],
  quarantine: ["quarantine", "list"],
  update: ["update"],
  intrusion: ["intrusion"],
  analyze: ["analyze"],
  allow: ["allow", "list"],
  "allow-add": ["allow", "add"],
  "allow-remove": ["allow", "remove"],
  diag: ["diag"],
  processes: ["processes"],
  network: ["network"],
  events: ["events", "-n", "50"],
  "ai-status": ["ai", "status"],
  "ai-use": ["ai", "use"],
  "ai-test": ["ai", "test"],
  "config-get": ["config", "get"],
  "config-set": ["config", "set"]
};

function pretty(value) {
  if (typeof value === "string") {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch (_e) {
      return value;
    }
  }
  return JSON.stringify(value, null, 2);
}

async function runJson(args) {
  const result = await window.aidefender.run(["--json"].concat(args));
  const text = (result.stdout || "").trim() || result.stderr || "";
  return Object.assign({}, result, { text: text });
}

function show(id, text) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = text || "(empty)";
  }
}

document.querySelectorAll("nav button").forEach(function (btn) {
  btn.addEventListener("click", function () {
    document.querySelectorAll("nav button").forEach(function (b) {
      b.classList.remove("active");
    });
    document.querySelectorAll(".tab").forEach(function (t) {
      t.classList.remove("active");
    });
    btn.classList.add("active");
    const tab = document.getElementById(btn.getAttribute("data-tab"));
    if (tab) {
      tab.classList.add("active");
    }
  });
});

async function loadDash() {
  show("dash-out", "Loading…");
  const status = await runJson(CLI_COMMANDS.status);
  const engines = await runJson(CLI_COMMANDS.engines);
  show(
    "dash-out",
    "exit=" + status.code + "\n\nSTATUS\n" + pretty(status.text) + "\n\nENGINES\n" + pretty(engines.text)
  );
}

document.getElementById("refresh-dash").onclick = loadDash;
document.getElementById("update-defs").onclick = async function () {
  show("dash-out", "Updating definitions…");
  const res = await runJson(CLI_COMMANDS.update);
  show("dash-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("pick-folder").onclick = async function () {
  const p = await window.aidefender.pick("folder");
  if (p) document.getElementById("scan-path").value = p;
};
document.getElementById("pick-file").onclick = async function () {
  const p = await window.aidefender.pick("file");
  if (p) document.getElementById("scan-path").value = p;
};
document.getElementById("run-scan").onclick = async function () {
  const target = document.getElementById("scan-path").value.trim();
  if (!target) {
    show("scan-out", "Choose a file or folder first.");
    return;
  }
  show("scan-out", "Scanning…");
  const args = CLI_COMMANDS.scan.concat([target]);
  if (document.getElementById("scan-quarantine").checked) args.push("--quarantine");
  const res = await runJson(args);
  show("scan-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("protect-once").onclick = async function () {
  show("protect-out", "Running one protection tick…");
  const res = await runJson(CLI_COMMANDS.protect);
  show("protect-out", pretty(res.text) + "\n\nexit=" + res.code);
};
document.getElementById("service-install").onclick = async function () {
  const res = await window.aidefender.run(["service", "install"]);
  show("protect-out", (res.stdout || res.stderr) + "\nexit=" + res.code);
};
document.getElementById("service-status").onclick = async function () {
  const res = await runJson(["service", "status"]);
  show("protect-out", pretty(res.text));
};

document.getElementById("q-refresh").onclick = async function () {
  show("q-out", "Loading…");
  const res = await runJson(CLI_COMMANDS.quarantine);
  show("q-out", pretty(res.text) || "(none)");
};

document.getElementById("intel-update").onclick = async function () {
  show("intel-out", "Pulling feed…");
  const res = await runJson(CLI_COMMANDS.update);
  show("intel-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("ids-check").onclick = async function () {
  show("ids-out", "Checking inbound sessions and auth failures…");
  const res = await runJson(CLI_COMMANDS.intrusion);
  show("ids-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("eng-refresh").onclick = async function () {
  show("eng-out", "Loading…");
  const res = await runJson(CLI_COMMANDS.engines);
  show("eng-out", pretty(res.text));
};

document.getElementById("pick-analyze").onclick = async function () {
  const p = await window.aidefender.pick("file");
  if (p) document.getElementById("analyze-path").value = p;
};
document.getElementById("run-analyze").onclick = async function () {
  const target = document.getElementById("analyze-path").value.trim();
  if (!target) {
    show("analyze-out", "Choose a file first.");
    return;
  }
  show("analyze-out", "Analyzing…");
  const res = await runJson(CLI_COMMANDS.analyze.concat([target]));
  show("analyze-out", pretty(res.text) + "\n\nexit=" + res.code);
};

async function allowMutate(cmd) {
  const kind = document.getElementById("allow-kind").value;
  const value = document.getElementById("allow-value").value.trim();
  const note = document.getElementById("allow-note").value.trim();
  let args;
  if (cmd === "list") {
    args = CLI_COMMANDS.allow.slice();
  } else if (cmd === "add") {
    if (!value) {
      show("allow-out", "Enter a value to allow add.");
      return;
    }
    args = CLI_COMMANDS["allow-add"].concat(["--" + kind, value]);
    if (note) args.push("--note", note);
  } else {
    if (!value) {
      show("allow-out", "Enter a value to allow remove.");
      return;
    }
    args = CLI_COMMANDS["allow-remove"].concat(["--" + kind, value]);
  }
  show("allow-out", "Working…");
  const res = await runJson(args);
  show("allow-out", pretty(res.text) + "\n\nexit=" + res.code);
}

document.getElementById("allow-list").onclick = function () {
  allowMutate("list");
};
document.getElementById("allow-add").onclick = function () {
  allowMutate("add");
};
document.getElementById("allow-remove").onclick = function () {
  allowMutate("remove");
};

document.getElementById("run-diag").onclick = async function () {
  show("diag-out", "Loading diag…");
  const res = await runJson(CLI_COMMANDS.diag);
  show("diag-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("run-processes").onclick = async function () {
  show("processes-out", "Loading processes…");
  const res = await runJson(CLI_COMMANDS.processes);
  show("processes-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("run-network").onclick = async function () {
  show("network-out", "Loading network…");
  const res = await runJson(CLI_COMMANDS.network);
  show("network-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("run-events").onclick = async function () {
  show("events-out", "Loading events…");
  const res = await runJson(CLI_COMMANDS.events);
  show("events-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("ai-detect").onclick = async function () {
  show("ai-out", "Probing LM Studio / Ollama / configured URL…");
  const res = await runJson(CLI_COMMANDS["ai-status"]);
  show("ai-out", pretty(res.text) + "\n\nexit=" + res.code);
};
document.getElementById("ai-use").onclick = async function () {
  const custom = document.getElementById("ai-url").value.trim();
  const target = custom || document.getElementById("ai-preset").value;
  const model = document.getElementById("ai-model").value.trim();
  const args = CLI_COMMANDS["ai-use"].concat([target]);
  if (model) args.push("--model", model);
  show("ai-out", "Switching backend…");
  const res = await runJson(args);
  show("ai-out", pretty(res.text) + "\n\nexit=" + res.code);
};
document.getElementById("ai-test").onclick = async function () {
  show("ai-out", "Testing chat roundtrip…");
  const res = await runJson(CLI_COMMANDS["ai-test"]);
  show("ai-out", pretty(res.text) + "\n\nexit=" + res.code);
};

document.getElementById("cfg-load").onclick = async function () {
  show("cfg-out", "Loading settings…");
  const res = await runJson(CLI_COMMANDS["config-get"]);
  show("cfg-out", pretty(res.text) + "\n\nexit=" + res.code);
};
document.getElementById("cfg-save").onclick = async function () {
  const key = document.getElementById("cfg-key").value.trim();
  const value = document.getElementById("cfg-value").value;
  if (!key) {
    show("cfg-out", "Enter a setting key first (Load settings to list them).");
    return;
  }
  show("cfg-out", "Saving…");
  const res = await runJson(CLI_COMMANDS["config-set"].concat([key, value]));
  show("cfg-out", pretty(res.text) + "\n\nexit=" + res.code);
};

(async function () {
  try {
    const info = await window.aidefender.cliInfo();
    const pill = document.getElementById("cli-pill");
    if (pill) {
      pill.textContent = info.bundled
        ? "bundled CLI\n" + info.command
        : "python module\n" + info.command + " " + (info.prefix || []).join(" ");
    }
  } catch (_e) {
    /* harness / tests may omit cliInfo */
  }
  if (window.aidefender && window.aidefender.run) {
    loadDash();
  }
})();
