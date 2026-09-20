const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aidefender", {
  run: (args) => ipcRenderer.invoke("aidefender:run", args),
  pick: (kind) => ipcRenderer.invoke("aidefender:pick", kind),
  cliInfo: () => ipcRenderer.invoke("aidefender:cliInfo"),
});
