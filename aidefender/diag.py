"""Host diagnostics for operators and agents: netstat-class views.

Wraps ss/netstat/lsof/ifconfig/arp/route when present. Parsers are
stdlib and testable from captured command text. This is inspection only
— no packet injection.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass, field

from .network import Connection, _split_hostport, list_connections

DIAG_TOOLS = (
    "ss", "netstat", "lsof", "tcpdump", "tshark", "dumpcap",
    "ifconfig", "ip", "arp", "route", "ping", "traceroute", "tracepath", "nslookup", "dig",
)


@dataclass
class ToolInfo:
    name: str
    path: str = ""
    present: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def inventory_tools() -> list[ToolInfo]:
    out: list[ToolInfo] = []
    for name in DIAG_TOOLS:
        path = shutil.which(name) or ""
        out.append(ToolInfo(name=name, path=path, present=bool(path)))
    return out


def _run(cmd: list[str], timeout: float = 8.0) -> tuple[int, str]:
    if not cmd or not shutil.which(cmd[0]):
        return 127, ""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return int(res.returncode or 0), (res.stdout or "") + (res.stderr or "")


def parse_listeners(conns: list[Connection]) -> list[dict]:
    rows: list[dict] = []
    for c in conns:
        status = (c.status or "").upper()
        if status not in {"LISTEN", "LISTENING"}:
            continue
        host, port = _split_hostport(c.local)
        rows.append({
            "local": c.local,
            "host": host,
            "port": port,
            "pid": c.pid,
            "status": c.status,
        })
    return rows


def parse_arp_text(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("address"):
            continue
        # arp -an: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        ip = ""
        mac = ""
        if "(" in line and ")" in line:
            ip = line.split("(", 1)[1].split(")", 1)[0]
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "at" and i + 1 < len(parts):
                mac = parts[i + 1]
        if not ip and parts:
            ip = parts[0]
        if ip:
            rows.append({"ip": ip, "mac": mac, "raw": line[:240]})
    return rows


def parse_route_text(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("destination") or low.startswith("kernel") or low.startswith("table"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        rows.append({"destination": parts[0], "gateway": parts[1], "raw": line[:240]})
    return rows


def dns_lookup(name: str) -> dict:
    addrs: list[str] = []
    error = ""
    try:
        for _fam, _typ, _proto, _canon, sockaddr in socket.getaddrinfo(name, None):
            host = sockaddr[0]
            if host not in addrs:
                addrs.append(host)
    except (OSError, socket.gaierror) as exc:
        error = str(exc)
    return {"query": name, "addresses": addrs, "error": error}


def inspect_ip(ip: str, cfg=None, fetch=None, do_dns: bool = True) -> dict:
    from .allowlist import is_ip_allowed
    from .blocklist import load_blocked
    from .geoip import enrich_ip
    from .ipaddr import normalize_ip
    cfg = cfg
    nip = normalize_ip(ip)
    geo = enrich_ip(nip, fetch=fetch, do_dns=do_dns)
    blocked = load_blocked(cfg) if cfg is not None else {}
    matches = []
    for c in list_connections(cfg):
        rip, _rport = _split_hostport(c.remote)
        if normalize_ip(rip) == nip:
            matches.append(c.to_dict())
    return {
        "ip": nip,
        "geo": geo,
        "allowlisted": is_ip_allowed(cfg, nip) if cfg is not None else None,
        "blocked": blocked.get(nip),
        "connections": matches,
    }


def snapshot(cfg=None, db=None) -> dict:
    conns = list_connections(cfg, db=db)
    tools = inventory_tools()
    arp_code, arp_text = _run(["arp", "-an"], timeout=5)
    if arp_code != 0:
        arp_code, arp_text = _run(["ip", "neigh"], timeout=5)
    route_code, route_text = _run(["netstat", "-rn"], timeout=5)
    if route_code != 0:
        route_code, route_text = _run(["ip", "route"], timeout=5)
    return {
        "connections": [c.to_dict() for c in conns],
        "listeners": parse_listeners(conns),
        "suspicious_connections": [c.to_dict() for c in conns if c.suspicious],
        "arp": parse_arp_text(arp_text) if arp_text else [],
        "routes": parse_route_text(route_text) if route_text else [],
        "tools": [t.to_dict() for t in tools],
    }
