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
    archive_max_depth: int = 3
    archive_max_members: int = 256
    archive_max_member_bytes: int = 8 * 1024 * 1024
    archive_max_total_bytes: int = 32 * 1024 * 1024
    local_ai_base_url: str = "http://127.0.0.1:11434/v1"
    local_ai_model: str = "llama3.2"
    local_ai_api_key: str = ""
    cloud_ai_base_url: str = ""
    cloud_ai_model: str = ""
    cloud_ai_api_key: str = ""
    ai_timeout_seconds: float = 8.0
    ai_sample_bytes: int = 4096
    file_settle_seconds: float = 0.25
    file_cooldown_seconds: float = 0.75
    burst_window_seconds: float = 8.0
    burst_file_threshold: int = 25
    protect_interval_seconds: float = 10.0
    network_bad_ips: list = field(default_factory=lambda: ["127.0.0.2"])
    network_bad_ports: list = field(default_factory=lambda: [4444, 5555, 6666, 31337, 12345, 1337, 6667])
    signatures_urls: list = field(default_factory=list)
    definition_update_interval_seconds: float = 900.0
    auto_update_definitions: bool = True
    clamd_enable: bool = False
    clamd_socket: str = ""
    clamd_timeout_seconds: float = 8.0
    intrusion_auto_block: bool = True
    intrusion_firewall_block: bool = True
    intrusion_geo: bool = True
    intrusion_brute_threshold: int = 4
    intrusion_scan_ports: int = 8
    intrusion_window_seconds: float = 300.0
    intrusion_allow_ips: list = field(default_factory=list)

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
