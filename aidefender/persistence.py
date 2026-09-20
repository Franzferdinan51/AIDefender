"""User-space persistence locations (LaunchAgents, autostart, Startup folder)."""
from __future__ import annotations

import os
from pathlib import Path

from .config import DefenderConfig, get_config, is_linux, is_mac, is_windows
from .scanner import Finding, scan_file
from .signatures import SignatureDB, load_db


def persistence_watch_paths() -> list[str]:
    home = Path.home()
    paths: list[str] = []
    if is_mac():
        paths.extend(
            [
                str(home / "Library" / "LaunchAgents"),
                str(home / "Library" / "LaunchDaemons"),
            ]
        )
    elif is_windows():
        appdata = os.environ.get("APPDATA") or str(home / "AppData" / "Roaming")
        paths.append(
            str(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        )
    else:
        paths.extend(
            [
                str(home / ".config" / "autostart"),
                str(home / ".config" / "systemd" / "user"),
            ]
        )
    if is_linux() or is_mac():
        paths.append(str(home / ".config" / "autostart"))
    return [p for p in paths if p]


def existing_persistence_paths() -> list[str]:
    return [p for p in persistence_watch_paths() if Path(p).exists()]


def scan_persistence(
    cfg: DefenderConfig | None = None,
    db: SignatureDB | None = None,
) -> list[Finding]:
    """Scan user persistence dirs; missing dirs are skipped, never an error."""
    cfg = cfg or get_config()
    db = db or load_db(cfg.signatures_file)
    findings: list[Finding] = []
    for raw in existing_persistence_paths():
        root = Path(raw)
        try:
            for child in root.rglob("*"):
                if child.is_symlink() or not child.is_file():
                    continue
                findings.append(scan_file(child, db=db, cfg=cfg))
        except OSError:
            continue
    return findings
