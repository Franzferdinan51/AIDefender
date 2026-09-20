"""Persistent attacker blocklist + optional OS firewall drop.

App-level blocks always apply (network guard treats the IP as hostile).
Firewall commands are best-effort and never crash the defender if sudo/pf
is unavailable.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from .config import DefenderConfig, get_config, is_linux, is_mac, is_windows
from .ipaddr import is_public_ip, normalize_ip


def blocklist_path(cfg: DefenderConfig | None = None) -> Path:
    cfg = cfg or get_config()
    return Path(cfg.base_dir) / "blocked-ips.json"


def load_blocked(cfg: DefenderConfig | None = None) -> dict[str, dict]:
    cfg = cfg or get_config()
    path = blocklist_path(cfg)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if isinstance(data, dict):
        return {normalize_ip(k): v if isinstance(v, dict) else {"reason": str(v)} for k, v in data.items()}
    return {}


def save_blocked(cfg: DefenderConfig, blocked: dict[str, dict]) -> None:
    path = blocklist_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(blocked, indent=2), encoding="utf-8")


def try_firewall_block(ip: str) -> tuple[bool, str]:
    """Best-effort inbound drop. Returns (ok, detail)."""
    ip = normalize_ip(ip)
    if not is_public_ip(ip):
        return False, "refusing to firewall-block a non-public address"
    try:
        if is_windows() and shutil.which("netsh"):
            name = f"AIDefender-block-{ip}"
            res = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={name}", "dir=in", "action=block", f"remoteip={ip}",
                ],
                capture_output=True, text=True, timeout=8,
            )
            return res.returncode == 0, (res.stdout or res.stderr or "").strip()[:300]
        if is_linux() and shutil.which("iptables"):
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=8,
            )
            if check.returncode == 0:
                return True, "iptables rule already present"
            res = subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=8,
            )
            return res.returncode == 0, (res.stdout or res.stderr or "").strip()[:300]
        if is_mac() and shutil.which("pfctl"):
            return False, "pfctl table add requires a preconfigured pf anchor (not applied)"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return False, "no supported firewall command"


def block_ip(
    cfg: DefenderConfig,
    ip: str,
    reason: str,
    details: dict | None = None,
    firewall: bool = False,
) -> dict:
    ip = normalize_ip(ip)
    blocked = load_blocked(cfg)
    entry = {
        "ip": ip,
        "reason": reason,
        "ts": time.time(),
        "details": details or {},
        "firewall": {"attempted": False, "ok": False, "detail": ""},
    }
    if firewall and is_public_ip(ip):
        ok, detail = try_firewall_block(ip)
        entry["firewall"] = {"attempted": True, "ok": ok, "detail": detail}
    blocked[ip] = entry
    save_blocked(cfg, blocked)
    return entry


def try_firewall_unblock(ip: str) -> tuple[bool, str]:
    ip = normalize_ip(ip)
    try:
        if is_windows() and shutil.which("netsh"):
            name = f"AIDefender-block-{ip}"
            res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                capture_output=True, text=True, timeout=8,
            )
            return res.returncode == 0, (res.stdout or res.stderr or "").strip()[:300]
        if is_linux() and shutil.which("iptables"):
            res = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=8,
            )
            return res.returncode == 0, (res.stdout or res.stderr or "").strip()[:300]
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return False, "no supported firewall command"


def unblock_ip(cfg: DefenderConfig, ip: str, firewall: bool = False) -> dict:
    ip = normalize_ip(ip)
    blocked = load_blocked(cfg)
    entry = blocked.pop(ip, None)
    save_blocked(cfg, blocked)
    fw = {"attempted": False, "ok": False, "detail": ""}
    if firewall:
        ok, detail = try_firewall_unblock(ip)
        fw = {"attempted": True, "ok": ok, "detail": detail}
    return {"ip": ip, "removed": entry is not None, "previous": entry, "firewall": fw}
