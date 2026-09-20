"""User/agent allowlist: IPs, CIDRs, ports, processes, paths, hashes.

Things the operator knows are safe (home lab, this repo, a VPN egress)
are skipped by scan, process, network, and intrusion checks.
"""
from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path

from .config import DefenderConfig, get_config
from .ipaddr import normalize_ip, parse_ip


def allowlist_path(cfg: DefenderConfig | None = None) -> Path:
    cfg = cfg or get_config()
    return Path(cfg.base_dir) / "allowlist.json"


def _empty() -> dict:
    return {"ips": {}, "cidrs": {}, "ports": {}, "processes": {}, "paths": {}, "hashes": {}}


def load_allowlist(cfg: DefenderConfig | None = None) -> dict:
    cfg = cfg or get_config()
    path = allowlist_path(cfg)
    data = _empty()
    if not path.exists():
        for ip in getattr(cfg, "intrusion_allow_ips", None) or []:
            data["ips"][normalize_ip(str(ip))] = {"note": "config intrusion_allow_ips", "ts": 0}
        return data
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return data
    if not isinstance(raw, dict):
        return data
    for key in data:
        src = raw.get(key) or {}
        if isinstance(src, dict):
            data[key] = {str(k): (v if isinstance(v, dict) else {"note": str(v)}) for k, v in src.items()}
        elif isinstance(src, list):
            data[key] = {str(v): {"note": "", "ts": 0} for v in src}
    for ip in getattr(cfg, "intrusion_allow_ips", None) or []:
        data["ips"].setdefault(normalize_ip(str(ip)), {"note": "config intrusion_allow_ips", "ts": 0})
    return data


def save_allowlist(cfg: DefenderConfig, data: dict) -> Path:
    path = allowlist_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    merged = _empty()
    merged.update({k: data.get(k) or {} for k in merged})
    path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return path


def add_entry(cfg: DefenderConfig, kind: str, value: str, note: str = "") -> dict:
    aliases = {
        "ip": "ips", "ips": "ips",
        "cidr": "cidrs", "cidrs": "cidrs",
        "port": "ports", "ports": "ports",
        "process": "processes", "processes": "processes",
        "path": "paths", "paths": "paths",
        "hash": "hashes", "hashes": "hashes",
    }
    kind = aliases.get(kind.lower())
    if kind not in ("ips", "cidrs", "ports", "processes", "paths", "hashes"):
        raise ValueError(f"unknown allowlist kind: {kind}")
    data = load_allowlist(cfg)
    key = value.strip()
    if kind == "ips":
        key = normalize_ip(key)
    if kind == "hashes":
        key = key.lower()
    if kind == "processes":
        key = key.lower()
    if kind == "ports":
        key = str(int(key))
    if kind == "cidrs":
        ipaddress.ip_network(key, strict=False)  # validate
    data[kind][key] = {"note": note, "ts": time.time()}
    save_allowlist(cfg, data)
    return data[kind][key]


def remove_entry(cfg: DefenderConfig, kind: str, value: str) -> bool:
    data = load_allowlist(cfg)
    mapping = {
        "ip": "ips", "ips": "ips", "cidr": "cidrs", "cidrs": "cidrs",
        "port": "ports", "ports": "ports", "process": "processes", "processes": "processes",
        "path": "paths", "paths": "paths", "hash": "hashes", "hashes": "hashes",
    }
    bucket = mapping.get(kind.lower())
    if not bucket:
        return False
    key = value.strip()
    if bucket == "ips":
        key = normalize_ip(key)
    if bucket == "hashes":
        key = key.lower()
    if bucket == "processes":
        key = key.lower()
    if bucket == "ports":
        try:
            key = str(int(key))
        except ValueError:
            return False
    existed = key in data[bucket]
    data[bucket].pop(key, None)
    save_allowlist(cfg, data)
    return existed


def is_ip_allowed(cfg: DefenderConfig | None, ip: str) -> str | None:
    """Return a note/reason if allowed, else None."""
    if not ip:
        return None
    data = load_allowlist(cfg)
    nip = normalize_ip(ip)
    if nip in data["ips"]:
        return data["ips"][nip].get("note") or f"allowlisted ip {nip}"
    addr = parse_ip(nip)
    if addr is None:
        return None
    for cidr, meta in data["cidrs"].items():
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr in net:
            return (meta or {}).get("note") or f"allowlisted cidr {cidr}"
    return None


def is_port_allowed(cfg: DefenderConfig | None, port: int | None) -> str | None:
    if port is None:
        return None
    data = load_allowlist(cfg)
    meta = data["ports"].get(str(int(port)))
    if meta is not None:
        return meta.get("note") or f"allowlisted port {port}"
    return None


def is_process_allowed(cfg: DefenderConfig | None, name: str = "", exe: str = "", cmdline: str = "") -> str | None:
    data = load_allowlist(cfg)
    blob = f"{name} {exe} {cmdline}".lower()
    for needle, meta in data["processes"].items():
        n = needle.lower()
        if n and n in blob:
            return (meta or {}).get("note") or f"allowlisted process {needle}"
    return None


def is_file_allowed(cfg: DefenderConfig | None, path: str = "", sha256: str = "") -> str | None:
    data = load_allowlist(cfg)
    digest = (sha256 or "").lower()
    if digest and digest in data["hashes"]:
        return data["hashes"][digest].get("note") or "allowlisted hash"
    p = str(path or "")
    for prefix, meta in data["paths"].items():
        if prefix and (p == prefix or p.startswith(prefix.rstrip("/") + "/") or p.startswith(prefix.rstrip("\\") + "\\")):
            return (meta or {}).get("note") or f"allowlisted path {prefix}"
    return None
