"""Install always-on protection as a user login service.

macOS LaunchAgent, systemd --user, or Windows Startup folder. This is how
consumer AV stays resident; it is not a kernel driver.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .config import DefenderConfig, get_config, is_linux, is_mac, is_windows


SERVICE_LABEL = "ai.aidefender.protect"


def _python() -> str:
    return sys.executable


def _argv(cfg: DefenderConfig) -> list[str]:
    return [
        _python(),
        "-m",
        "aidefender",
        "--config-dir",
        cfg.base_dir,
        "protect",
        "--auto-quarantine",
    ]


def default_unit_path() -> Path:
    home = Path.home()
    if is_mac():
        return home / "Library" / "LaunchAgents" / f"{SERVICE_LABEL}.plist"
    if is_windows():
        appdata = os.environ.get("APPDATA") or str(home / "AppData" / "Roaming")
        return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "AIDefender-protect.bat"
    return home / ".config" / "systemd" / "user" / "aidefender.service"


def render_unit(cfg: DefenderConfig, path: Path | None = None) -> str:
    path = path or default_unit_path()
    args = _argv(cfg)
    if path.suffix == ".plist" or is_mac():
        arg_xml = "\n".join(f"    <string>{a}</string>" for a in args)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{SERVICE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{arg_xml}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{cfg.base_dir}/protect.out.log</string>
  <key>StandardErrorPath</key>
  <string>{cfg.base_dir}/protect.err.log</string>
</dict>
</plist>
"""
    if path.suffix == ".bat" or is_windows():
        quoted = " ".join(f'"{a}"' if " " in a else a for a in args)
        return f"@echo off\r\n{quoted}\r\n"
    exec_start = " ".join(args)
    return f"""[Unit]
Description=AIDefender always-on protection
[Service]
ExecStart={exec_start}
Restart=on-failure
RestartSec=5
[Install]
WantedBy=default.target
"""


def install_service(cfg: DefenderConfig | None = None, dest: str | os.PathLike | None = None) -> Path:
    cfg = cfg or get_config()
    cfg.ensure_dirs()
    path = Path(dest) if dest else default_unit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_unit(cfg, path), encoding="utf-8")
    return path


def uninstall_service(dest: str | os.PathLike | None = None) -> bool:
    path = Path(dest) if dest else default_unit_path()
    if path.exists():
        path.unlink()
        return True
    return False


def service_installed(dest: str | os.PathLike | None = None) -> bool:
    path = Path(dest) if dest else default_unit_path()
    return path.exists()
