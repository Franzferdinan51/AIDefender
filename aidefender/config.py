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
    intrusion_firewall_block: bool = False
    intrusion_geo: bool = True
    intrusion_brute_threshold: int = 4
    intrusion_scan_ports: int = 8
    intrusion_window_seconds: float = 300.0
    intrusion_allow_ips: list = field(default_factory=list)
    intrusion_ddos_sources: int = 12
    intrusion_ddos_syn: int = 20

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
    _coerce_loaded(cfg)
    return cfg


def save_config(cfg: DefenderConfig) -> Path:
    base = Path(cfg.base_dir)
    base.mkdir(parents=True, exist_ok=True)
    path = _config_file(base)
    data = asdict(cfg)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


# Keys the operator may change via `config set` / desktop Settings.
# Maps key -> (kind, description). Secrets are deliberately absent:
# API keys come from environment variables, never the settings UI.
SETTABLE: dict[str, tuple[str, str]] = {
    "local_ai_base_url": ("str", "Local OpenAI-compatible base URL (LM Studio :1234, Ollama :11434)"),
    "local_ai_model": ("str", "Local model id (LM Studio: any loaded model)"),
    "cloud_ai_base_url": ("str", "Cloud OpenAI-compatible base URL (empty disables)"),
    "cloud_ai_model": ("str", "Cloud model id"),
    "ai_timeout_seconds": ("float", "AI HTTP timeout seconds"),
    "ai_sample_bytes": ("int", "Max file sample bytes sent to local AI"),
    "watch_paths": ("list", "Comma-separated folders for protect/daemon"),
    "auto_quarantine": ("bool", "Quarantine malicious hits automatically"),
    "heuristic_suspicious": ("int", "Score >= this is suspicious (0-100)"),
    "heuristic_malicious": ("int", "Score >= this is malicious (0-100)"),
    "max_scan_bytes": ("int", "Skip heuristic body past this many bytes"),
    "protect_interval_seconds": ("float", "Seconds between protect ticks"),
    "auto_update_definitions": ("bool", "Refresh intel feed during protect/daemon"),
    "definition_update_interval_seconds": ("float", "Seconds between feed refreshes"),
    "signatures_url": ("str", "Primary intel feed URL"),
    "clamd_enable": ("bool", "Use local ClamAV daemon (no cloud upload)"),
    "clamd_socket": ("str", "clamd socket path/host:port (empty = auto)"),
    "intrusion_auto_block": ("bool", "Persist caught attacker IPs to local blocklist"),
    "intrusion_firewall_block": ("bool", "Also drop attackers in the OS firewall (OPT-IN)"),
    "intrusion_geo": ("bool", "Reverse-DNS + geo enrichment for intrusions"),
    "intrusion_brute_threshold": ("int", "Failed logins before brute-force alert"),
    "intrusion_scan_ports": ("int", "Distinct ports before port-scan alert"),
    "intrusion_window_seconds": ("float", "Correlation window seconds for IDS"),
    "intrusion_ddos_sources": ("int", "Distinct public sources before DDOS alert"),
    "intrusion_ddos_syn": ("int", "SYN_RECV count before DDOS alert"),
    "network_bad_ports": ("intlist", "Comma-separated risky remote ports"),
}

_BOOL_TRUE = {"1", "true", "yes", "y", "on"}
_BOOL_FALSE = {"0", "false", "no", "n", "off"}


def coerce_value(key: str, raw: str):
    """Coerce a CLI string to the setting's type. Raises ValueError."""
    if key not in SETTABLE:
        raise ValueError(f"unknown setting: {key} (see `config get`)")
    kind = SETTABLE[key][0]
    text = (raw or "").strip()
    if kind == "bool":
        low = text.lower()
        if low in _BOOL_TRUE:
            return True
        if low in _BOOL_FALSE:
            return False
        raise ValueError(f"{key} needs true/false (got {raw!r})")
    if kind == "int":
        try:
            return int(text, 10)
        except ValueError:
            raise ValueError(f"{key} needs an integer (got {raw!r})") from None
    if kind == "float":
        try:
            return float(text)
        except ValueError:
            raise ValueError(f"{key} needs a number (got {raw!r})") from None
    if kind == "list":
        return [part.strip() for part in text.split(",") if part.strip()]
    if kind == "intlist":
        try:
            return [int(part.strip(), 10) for part in text.split(",") if part.strip()]
        except ValueError:
            raise ValueError(f"{key} needs comma-separated integers (got {raw!r})") from None
    return text


def validate_config(cfg: DefenderConfig) -> list[str]:
    """Clamp/fix unsafe values in place. Returns human warnings."""
    warnings: list[str] = []

    def _clamp(key: str, lo: float, hi: float) -> None:
        try:
            value = float(getattr(cfg, key))
        except (TypeError, ValueError):
            setattr(cfg, key, getattr(DefenderConfig(), key))
            warnings.append(f"{key} was not a number; reset to default")
            return
        fixed = min(hi, max(lo, value))
        if fixed != value:
            kind = SETTABLE.get(key, ("float",))[0]
            setattr(cfg, key, int(fixed) if kind == "int" else fixed)
            warnings.append(f"{key} clamped to {fixed:g}")

    _clamp("heuristic_suspicious", 0, 100)
    _clamp("heuristic_malicious", 0, 100)
    if cfg.heuristic_malicious < cfg.heuristic_suspicious:
        cfg.heuristic_malicious = cfg.heuristic_suspicious
        warnings.append("heuristic_malicious raised to heuristic_suspicious")
    for key in ("ai_timeout_seconds", "protect_interval_seconds",
                "definition_update_interval_seconds", "intrusion_window_seconds",
                "file_settle_seconds", "file_cooldown_seconds", "burst_window_seconds",
                "clamd_timeout_seconds"):
        _clamp(key, 0.05, 86400)
    for key in ("ai_sample_bytes", "max_scan_bytes", "burst_file_threshold",
                "archive_max_depth", "archive_max_members", "archive_max_member_bytes",
                "archive_max_total_bytes", "intrusion_brute_threshold",
                "intrusion_scan_ports", "intrusion_ddos_sources", "intrusion_ddos_syn"):
        _clamp(key, 1, 1 << 40)
    for key in ("local_ai_base_url", "cloud_ai_base_url", "signatures_url", "clamd_socket"):
        value = getattr(cfg, key, "")
        if isinstance(value, str) and value != value.strip():
            setattr(cfg, key, value.strip())
    if not isinstance(cfg.watch_paths, list):
        cfg.watch_paths = default_watch_paths()
        warnings.append("watch_paths was not a list; reset to default")
    return warnings


def _coerce_loaded(cfg: DefenderConfig) -> list[str]:
    """Repair wrong-typed values from an edited config.json. Returns warnings."""
    defaults = DefenderConfig()
    warnings: list[str] = []
    for key in list(vars(cfg).keys()):
        current = getattr(cfg, key)
        default = getattr(defaults, key, None)
        if isinstance(default, bool) and not isinstance(current, bool):
            if isinstance(current, str) and current.strip().lower() in _BOOL_TRUE | _BOOL_FALSE:
                setattr(cfg, key, current.strip().lower() in _BOOL_TRUE)
            else:
                setattr(cfg, key, default)
                warnings.append(f"{key} was not true/false; reset to default")
        elif isinstance(default, int) and not isinstance(current, bool) and not isinstance(current, int):
            try:
                setattr(cfg, key, int(current))
            except (TypeError, ValueError):
                setattr(cfg, key, default)
                warnings.append(f"{key} was not an integer; reset to default")
        elif isinstance(default, float) and not isinstance(current, (int, float)):
            try:
                setattr(cfg, key, float(current))
            except (TypeError, ValueError):
                setattr(cfg, key, default)
                warnings.append(f"{key} was not a number; reset to default")
    warnings.extend(validate_config(cfg))
    return warnings


def redacted_dict(cfg: DefenderConfig) -> dict:
    """Config as JSON-safe dict with secrets redacted for display."""
    data = asdict(cfg)
    for key in list(data.keys()):
        if "api_key" in key:
            data[key] = "***set***" if data[key] else ""
    data["_api_key_hint"] = "API keys come from AIDEFENDER_CLOUD_AI_API_KEY / OPENAI_API_KEY env vars; never stored here by `config set`."
    return data
