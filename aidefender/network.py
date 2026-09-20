"""Network guard: inspect connections and flag risky remote endpoints.

Portable: prefers `psutil`, falls back to `ss`/`netstat`. Ships a tiny
example blocklist; real deployments should feed it via the updater.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

EXAMPLE_BAD_IPS = {
    "127.0.0.2",  # reserved TEST-NET style placeholder; replace via updater
}
EXAMPLE_BAD_PORTS = {4444, 5555, 6666, 31337, 12345, 1337, 6667, 27374}
TOR_PORTS = {9050, 9150}
LISTEN_STATUSES = {"LISTEN", "LISTENING"}


@dataclass
class Connection:
    local: str
    remote: str
    status: str = ""
    pid: int | None = None
    suspicious: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"local": self.local, "remote": self.remote, "status": self.status,
                "pid": self.pid, "suspicious": self.suspicious, "reasons": self.reasons}


def _split_hostport(addr: str) -> tuple[str, int | None]:
    addr = (addr or "").strip()
    if not addr or addr in ("*", "0.0.0.0:*", "[::]:*"):
        return "", None
    if addr.startswith("["):
        try:
            host, rest = addr[1:].split("]", 1)
            port = int(rest.lstrip(":")) if rest.lstrip(":").isdigit() else None
            return host, port
        except ValueError:
            return addr, None
    if addr.count(":") == 1:
        host, port_s = addr.rsplit(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            return host, None
    return addr, None


def flag_connection(
    conn: Connection,
    bad_ips: set[str] | None = None,
    bad_ports: set[int] | None = None,
) -> Connection:
    bad_ips = bad_ips if bad_ips is not None else set(EXAMPLE_BAD_IPS)
    bad_ports = bad_ports if bad_ports is not None else set(EXAMPLE_BAD_PORTS)
    rip, rport = _split_hostport(conn.remote)
    _lip, lport = _split_hostport(conn.local)
    if rip in bad_ips:
        conn.suspicious = True
        conn.reasons.append(f"remote IP on blocklist: {rip}")
    if rport in bad_ports:
        conn.suspicious = True
        conn.reasons.append(f"remote port {rport} is a common malware default")
    if rport in TOR_PORTS:
        conn.suspicious = True
        conn.reasons.append(f"tor port {rport} (tunnelled traffic)")
    status = (conn.status or "").upper()
    if lport in bad_ports and status in LISTEN_STATUSES:
        conn.suspicious = True
        conn.reasons.append(f"listening on common malware port {lport}")
    return conn


def _flag(conn: Connection) -> Connection:
    return flag_connection(conn)


def _via_psutil() -> list[Connection] | None:
    try:
        import psutil  # type: ignore
    except ImportError:
        return None
    out: list[Connection] = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            remote = f"{c.raddr.ip}:{c.raddr.port}"
            out.append(_flag(Connection(local=local, remote=remote,
                                       status=str(c.status), pid=c.pid)))
    except Exception:
        return []
    return out


def _parse_table(text: str) -> list[Connection]:
    out: list[Connection] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].lower().startswith("proto"):
            continue
        # ss: Netid State Recv-Q ... Local Peer
        # netstat: Proto Recv-Q ... Local Foreign State
        local = parts[4] if parts[0].lower() in ("tcp", "udp") and len(parts) > 5 else ""
        remote = parts[5] if len(parts) > 5 else ""
        if ":" not in remote:
            continue
        out.append(_flag(Connection(local=local, remote=remote, status=parts[1] if len(parts) > 1 else "")))
    return out


def _via_ss() -> list[Connection] | None:
    if not shutil.which("ss"):
        return None
    try:
        res = subprocess.run(["ss", "-tun"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return _parse_table(res.stdout)


def _via_netstat() -> list[Connection] | None:
    if not shutil.which("netstat"):
        return None
    try:
        res = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return _parse_table(res.stdout)


def _blocklists(cfg) -> tuple[set[str], set[int]]:
    ips = set(EXAMPLE_BAD_IPS)
    ports = set(EXAMPLE_BAD_PORTS)
    if cfg is not None:
        for item in getattr(cfg, "network_bad_ips", None) or []:
            ips.add(str(item))
        for item in getattr(cfg, "network_bad_ports", None) or []:
            try:
                ports.add(int(item))
            except (TypeError, ValueError):
                continue
    return ips, ports


def list_connections(cfg=None) -> list[Connection]:
    rows: list[Connection] | None = None
    for source in (_via_psutil, _via_ss, _via_netstat):
        result = source()
        if result is not None:
            rows = result
            break
    if rows is None:
        return []
    ips, ports = _blocklists(cfg)
    out: list[Connection] = []
    for conn in rows:
        conn.suspicious = False
        conn.reasons = []
        out.append(flag_connection(conn, bad_ips=ips, bad_ports=ports))
    return out


def suspicious_connections(cfg=None) -> list[Connection]:
    return [c for c in list_connections(cfg) if c.suspicious]


def new_suspicious_connections(
    current: list[Connection],
    previous: set[tuple[str, str]],
) -> list[Connection]:
    return [
        c for c in current
        if c.suspicious and (c.local, c.remote) not in previous
    ]
