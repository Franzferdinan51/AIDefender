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
EXAMPLE_BAD_PORTS = {4444, 5555, 6666, 31337}  # common C2/crack defaults
TOR_PORTS = {9050, 9150}


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


def _flag(conn: Connection) -> Connection:
    rip = conn.remote.rsplit(":", 1)[0].strip("[]")
    port = None
    try:
        port = int(conn.remote.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        port = None
    if rip in EXAMPLE_BAD_IPS:
        conn.suspicious = True
        conn.reasons.append(f"remote IP on blocklist: {rip}")
    if port in EXAMPLE_BAD_PORTS:
        conn.suspicious = True
        conn.reasons.append(f"remote port {port} is a common malware default")
    if port in TOR_PORTS:
        conn.suspicious = True
        conn.reasons.append(f"tor port {port} (tunnelled traffic)")
    return conn


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


def list_connections() -> list[Connection]:
    for source in (_via_psutil, _via_ss):
        result = source()
        if result is not None:
            return result
    return []


def suspicious_connections() -> list[Connection]:
    return [c for c in list_connections() if c.suspicious]
