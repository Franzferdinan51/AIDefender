"""Launch the Electron desktop UI when installed next to the package."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def ui_root() -> Path:
    return Path(__file__).resolve().parent.parent / "ui"


def launch_ui() -> int:
    root = ui_root()
    if not (root / "main.js").is_file():
        print("Electron UI is not in this install. Clone the repo and run: cd ui && npm install && npm start", file=sys.stderr)
        return 1
    electron = root / "node_modules" / ".bin" / ("electron.cmd" if os.name == "nt" else "electron")
    cmd = None
    if electron.exists():
        cmd = [str(electron), str(root)]
    elif shutil.which("npx"):
        cmd = ["npx", "--yes", "electron", str(root)]
    else:
        print("Install Node.js, then: cd ui && npm install && npm start", file=sys.stderr)
        return 1
    print(f"starting UI from {root}")
    proc = subprocess.run(cmd, cwd=str(root))
    return int(proc.returncode or 0)
