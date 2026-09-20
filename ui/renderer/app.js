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
  const result = await window.aidefender.run(["--json", ...args]);
  const text = (result.stdout || "").trim() || result.stderr || "";
  return { ...result, text };
}

function show(id, text) {
  document.getElementById(id).textContent = text || "(empty)";
}

document.querySelectorAll("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
});

async function loadDash() {
  show("dash-out", "Loading…");
  const status = await runJson(["status"]);
  const engines = await runJson(["engines"]);
  show(
    "dash-out",
    `exit=${status.code}\n\nSTATUS\n${pretty(status.text)}\n\nENGINES\n${pretty(engines.text)}`
  );
}

document.getElementById("refresh-dash").onclick = loadDash;
document.getElementById("update-defs").onclick = async () => {
  show("dash-out", "Updating definitions…");
  const res = await runJson(["update"]);
  show("dash-out", pretty(res.text) + `\n\nexit=${res.code}`);
};

document.getElementById("pick-folder").onclick = async () => {
  const p = await window.aidefender.pick("folder");
  if (p) document.getElementById("scan-path").value = p;
};
document.getElementById("pick-file").onclick = async () => {
  const p = await window.aidefender.pick("file");
  if (p) document.getElementById("scan-path").value = p;
};
document.getElementById("run-scan").onclick = async () => {
  const target = document.getElementById("scan-path").value.trim();
  if (!target) {
    show("scan-out", "Choose a file or folder first.");
    return;
  }
  show("scan-out", "Scanning…");
  const args = ["scan", target];
  if (document.getElementById("scan-quarantine").checked) args.push("--quarantine");
  const res = await runJson(args);
  show("scan-out", pretty(res.text) + `\n\nexit=${res.code}`);
};

document.getElementById("protect-once").onclick = async () => {
  show("protect-out", "Running one protection tick…");
  const res = await runJson(["protect", "--once"]);
  show("protect-out", pretty(res.text) + `\n\nexit=${res.code}`);
};
document.getElementById("service-install").onclick = async () => {
  const res = await window.aidefender.run(["service", "install"]);
  show("protect-out", (res.stdout || res.stderr) + `\nexit=${res.code}`);
};
document.getElementById("service-status").onclick = async () => {
  const res = await runJson(["service", "status"]);
  show("protect-out", pretty(res.text));
};

document.getElementById("q-refresh").onclick = async () => {
  show("q-out", "Loading…");
  const res = await runJson(["quarantine", "list"]);
  show("q-out", pretty(res.text) || "(none)");
};

document.getElementById("intel-update").onclick = async () => {
  show("intel-out", "Pulling feed…");
  const res = await runJson(["update"]);
  show("intel-out", pretty(res.text) + `\n\nexit=${res.code}`);
};

document.getElementById("ids-check").onclick = async () => {
  show("ids-out", "Checking inbound sessions and auth failures…");
  const res = await runJson(["intrusion"]);
  show("ids-out", pretty(res.text) + `\n\nexit=${res.code}`);
};

document.getElementById("eng-refresh").onclick = async () => {
  show("eng-out", "Loading…");
  const res = await runJson(["engines"]);
  show("eng-out", pretty(res.text));
};

(async () => {
  const info = await window.aidefender.cliInfo();
  document.getElementById("cli-pill").textContent = info.bundled
    ? `bundled CLI\n${info.command}`
    : `python module\n${info.command} ${info.prefix.join(" ")}`;
  loadDash();
})();
