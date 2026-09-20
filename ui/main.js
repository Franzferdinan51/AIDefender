const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

function bundledBinary() {
  const name = process.platform === "win32" ? "aidefender.exe" : "aidefender";
  const roots = [
    path.join(process.resourcesPath || "", name),
    path.join(process.resourcesPath || "", "aidefender", name),
    path.join(__dirname, "resources", name),
  ];
  return roots.find((p) => p && fs.existsSync(p)) || null;
}

function resolveCli() {
  const bundled = bundledBinary();
  if (bundled) {
    return { command: bundled, prefix: [] };
  }
  const py =
    process.env.AIDEFENDER_PYTHON ||
    (process.platform === "win32" ? "python" : "python3");
  return { command: py, prefix: ["-m", "aidefender"] };
}

function runAidefender(args, timeoutMs = 120000) {
  const { command, prefix } = resolveCli();
  const argv = [...prefix, ...args];
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    const child = spawn(command, argv, {
      env: process.env,
      windowsHide: true,
    });
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          child.kill();
        } catch (_e) {
          /* ignore */
        }
        resolve({ code: -1, stdout, stderr: stderr + "\ntimeout" });
      }
    }, timeoutMs);
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: String(err) });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 860,
    minHeight: 560,
    title: "AIDefender",
    backgroundColor: "#0b1220",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, "renderer", "index.html"));
}

app.whenReady().then(() => {
  ipcMain.handle("aidefender:run", (_evt, args) => {
    const list = Array.isArray(args) ? args.map(String) : [];
    return runAidefender(list);
  });
  ipcMain.handle("aidefender:pick", async (_evt, kind) => {
    const properties =
      kind === "file" ? ["openFile"] : ["openDirectory", "createDirectory"];
    const res = await dialog.showOpenDialog({ properties });
    if (res.canceled || !res.filePaths.length) return "";
    return res.filePaths[0];
  });
  ipcMain.handle("aidefender:cliInfo", () => {
    const cli = resolveCli();
    return { ...cli, bundled: Boolean(bundledBinary()) };
  });
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

module.exports = { resolveCli, runAidefender, bundledBinary };
