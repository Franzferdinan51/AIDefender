"""Platform-aware paths and configuration (macOS / Linux / Windows)."""
from __future__ import annotations

import json
import os
import platform
from dataclasses import asdict, dataclass, field
from pathlib import Path


def system_name() -> str:
    return platform.system()  # Darwin, Linux, Windows


def is_mac() -> bool:
    return system_name() == "Darwin"


def is_linux() -> bool:
    return system_name() == "Linux"


def is_windows() -> bool:
    return system_name() == "Windows"


def default_base_dir() -> Path:
    sys = system_name()
    if sys == "Windows":
        appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(appdata) / "AIDefender"
    if sys == "Darwin":
        return Path.home() / "Library" / "Application Support" / "AIDefender"
    # Linux / other POSIX: XDG config home
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "aidefender"


def default_watch_paths() -> list[str]:
    home = Path.home()
    if is_windows():
        return [str(home / "Downloads"), str(home / "Desktop")]
    if is_mac():
        return [str(home / "Downloads"), str(home / "Desktop")]
    return [str(home / "Downloads"), str(home / "Desktop")]


@dataclass
class DefenderConfig:
    base_dir: str = ""
    quarantine_dir: str = ""
    signatures_file: str = ""
    log_file: str = ""
    signatures_url: str = "https://raw.githubusercontent.com/Franzferdinan51/AIDefender/main/signatures.json"
    auto_quarantine: bool = False
    max_scan_bytes: int = 64 * 1024 * 1024  # skip heuristic body past this
    heuristic_suspicious: int = 40
    heuristic_malicious: int = 75
    watch_paths: field = field(default_factory=default_watch_paths)  # type: ignore

    def ensure_dirs(self) -> "DefenderConfig":
        Path(self.quarantine_dir).mkdir(parents=True, exist_ok=True)
        Path(self.base_dir).mkdir(parents=True, exist_ok=True)
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
        return self


def _config_file(base: Path) -> Path:
    return base / "config.json"


def get_config(base_dir: str | os.PathLike | None = None) -> DefenderConfig:
    base = Path(base_dir) if base_dir else default_base_dir()
    cfg_path = _config_file(base)
    cfg = DefenderConfig(
        base_dir=str(base),
        quarantine_dir=str(base / "quarantine"),
        signatures_file=str(base / "signatures.json"),
        log_file=str(base / "aidefender.log"),
    )
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            for key, value in data.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, value)
        except (OSError, ValueError):
            pass
    # Re-anchor derived paths if only base_dir was overridden in file.
    if not cfg.quarantine_dir:
        cfg.quarantine_dir = str(base / "quarantine")
    if not cfg.signatures_file:
        cfg.signatures_file = str(base / "signatures.json")
    if not cfg.log_file:
        cfg.log_file = str(base / "aidefender.log")
    return cfg


def save_config(cfg: DefenderConfig) -> Path:
    base = Path(cfg.base_dir)
    base.mkdir(parents=True, exist_ok=True)
    path = _config_file(base)
    data = asdict(cfg)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path
