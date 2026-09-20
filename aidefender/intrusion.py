"""User-space intrusion detection: logins, inbound sessions, scans, IP intel.

Heavily defensive defaults: public remote IPs hitting login/admin ports,
failed authentications, and port-scan bursts become alerts. Caught IPs
are enriched (geo + reverse DNS) and added to a persistent blocklist that
the network guard honors. Optional OS firewall drops are best-effort.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .blocklist import block_ip, load_blocked
from .config import DefenderConfig, get_config, is_linux, is_mac, is_windows
from .events import DefenseEvent, append_event
from .geoip import enrich_ip, format_location
from .ipaddr import extract_ips, is_public_ip, normalize_ip
from .network import Connection, _split_hostport, list_connections

SENSITIVE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    88: "kerberos",
    135: "msrpc",
    139: "netbios",
    445: "smb",
    548: "afp",
    1433: "mssql",
    1521: "oracle",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-tls",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    5901: "vnc",
    5985: "winrm",
    5986: "winrm-tls",
    6379: "redis",
    6443: "k8s-api",
    9200: "elasticsearch",
    10250: "kubelet",
    27017: "mongodb",
    3283: "apple-remote-desktop",
}

INBOUND_STATUSES = {
    "ESTABLISHED", "SYN_RECV", "SYN_RCVD", "CLOSE_WAIT", "FIN_WAIT_1",
    "FIN_WAIT_2", "TIME_WAIT", "LAST_ACK",
}

AUTH_FAIL_RE = re.compile(
    r"(failed password|authentication failure|failed to authenticate|"
    r"invalid user|authentication error|logon failure|failed login|"
    r"pam: authentication error|sshd.*failed)",
    re.IGNORECASE,
)
AUTH_IP_RE = re.compile(
    r"(?:from|rhost=|source network address[:\s]+|src=)\s*(\[?[0-9a-fA-F.:]+\]?)",
    re.IGNORECASE,
)
WHO_IP_RE = re.compile(r"\(([^)]+)\)")


@dataclass
class AuthEvent:
    ip: str
    message: str
    user: str = ""
    source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IntrusionAlert:
    ip: str
    severity: str  # suspicious | malicious
    category: str  # inbound-session | brute-force | port-scan | remote-login
    evidence: list[str] = field(default_factory=list)
    local_port: int | None = None
    service: str = ""
    geo: dict = field(default_factory=dict)
    action: str = "logged"
    ts: float = 0.0

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = time.time()

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["location"] = format_location(self.geo) if self.geo else ""
        return payload


@dataclass
class IntrusionState:
    port_hits: deque = field(default_factory=deque)  # (ts, ip, local_port)
    auth_hits: deque = field(default_factory=deque)  # (ts, ip)
    seen_keys: set = field(default_factory=set)
    alerts: list = field(default_factory=list)


def parse_auth_text(text: str, source: str = "log") -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or not AUTH_FAIL_RE.search(line):
            continue
        ip = ""
        match = AUTH_IP_RE.search(line)
        if match:
            ip = normalize_ip(match.group(1))
        if not ip:
            found = extract_ips(line)
            ip = next((x for x in found if is_public_ip(x)), found[-1] if found else "")
        user = ""
        um = re.search(r"(?:for|user|account)\s+([A-Za-z0-9._\\-]+)", line, re.IGNORECASE)
        if um:
            user = um.group(1)
        if ip:
            events.append(AuthEvent(ip=ip, message=line[:400], user=user, source=source))
    return events


def parse_who_text(text: str) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for raw in (text or "").splitlines():
        match = WHO_IP_RE.search(raw)
        if not match:
            continue
        ip = normalize_ip(match.group(1))
        if is_public_ip(ip):
            user = raw.split()[0] if raw.split() else ""
            events.append(AuthEvent(ip=ip, message=raw.strip()[:400], user=user, source="who"))
    return events


def parse_windows_4625(text: str) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    chunks = re.split(r"\n(?=\s*(?:Event ID|Log Name|An account failed))", text or "")
    if len(chunks) <= 1:
        chunks = [text or ""]
    for chunk in chunks:
        if "Source Network Address" not in chunk and "source network address" not in chunk.lower():
            continue
        ip = ""
        user = ""
        for line in chunk.splitlines():
            if "source network address" in line.lower():
                ip = normalize_ip(line.split(":")[-1])
            if re.search(r"Account Name\s*:", line, re.IGNORECASE):
                user = line.split(":")[-1].strip()
        if ip:
            events.append(AuthEvent(ip=ip, message=chunk.strip()[:400], user=user, source="wevtutil-4625"))
    return events


def collect_auth_events(timeout: float = 3.0, unified_log: bool = False) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for path in ("/var/log/auth.log", "/var/log/secure"):
        p = Path(path)
        if not p.is_file():
            continue
        try:
            events.extend(parse_auth_text(p.read_text(encoding="utf-8", errors="ignore")[-200_000:], source=path))
        except OSError:
            continue
    if shutil.which("who"):
        try:
            res = subprocess.run(["who"], capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0:
                events.extend(parse_who_text(res.stdout))
        except (OSError, subprocess.SubprocessError):
            pass
    if unified_log and is_mac() and shutil.which("log"):
        try:
            res = subprocess.run(
                [
                    "log", "show", "--last", "15m", "--style", "syslog",
                    "--predicate",
                    'process == "sshd" OR eventMessage CONTAINS "Authentication failed" OR eventMessage CONTAINS "Failed to authenticate"',
                ],
                capture_output=True, text=True, timeout=timeout,
            )
            events.extend(parse_auth_text(res.stdout[-200_000:], source="log-show"))
        except (OSError, subprocess.SubprocessError):
            pass
    if is_windows() and shutil.which("wevtutil"):
        try:
            res = subprocess.run(
                ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]", "/f:text", "/c:30"],
                capture_output=True, text=True, timeout=timeout,
            )
            events.extend(parse_windows_4625(res.stdout))
        except (OSError, subprocess.SubprocessError):
            pass
    return events


def inbound_session(conn: Connection) -> tuple[bool, str, int | None, str]:
    """Return (is_inbound_sensitive, remote_ip, local_port, service)."""
    rip, rport = _split_hostport(conn.remote)
    lip, lport = _split_hostport(conn.local)
    status = (conn.status or "").upper()
    if not rip or not is_public_ip(rip):
        return False, rip, lport, ""
    service = SENSITIVE_PORTS.get(lport or -1, "")
    if lport in SENSITIVE_PORTS and status in INBOUND_STATUSES:
        return True, rip, lport, service
    if lport in SENSITIVE_PORTS and status in {"ESTABLISHED"}:
        return True, rip, lport, service
    return False, rip, lport, service


def evaluate_intrusions(
    connections: list[Connection],
    auth_events: list[AuthEvent],
    state: IntrusionState | None = None,
    cfg: DefenderConfig | None = None,
    now: float | None = None,
    enrich: bool = True,
    fetch=None,
    apply_blocks: bool = True,
) -> tuple[IntrusionState, list[IntrusionAlert]]:
    cfg = cfg or get_config()
    state = state or IntrusionState()
    now = time.time() if now is None else now
    brute_n = int(getattr(cfg, "intrusion_brute_threshold", 4) or 4)
    scan_n = int(getattr(cfg, "intrusion_scan_ports", 8) or 8)
    window = float(getattr(cfg, "intrusion_window_seconds", 300) or 300)
    allow = {normalize_ip(x) for x in (getattr(cfg, "intrusion_allow_ips", None) or [])}
    alerts: list[IntrusionAlert] = []

    def keep(dq: deque) -> None:
        while dq and now - dq[0][0] > window:
            dq.popleft()

    for ev in auth_events:
        ip = normalize_ip(ev.ip)
        if not ip or ip in allow or not is_public_ip(ip):
            continue
        key = ("auth", ip, ev.message[:80])
        if key in state.seen_keys:
            continue
        state.seen_keys.add(key)
        state.auth_hits.append((now, ip))
        keep(state.auth_hits)

    auth_counts: dict[str, int] = defaultdict(int)
    for ts, ip in state.auth_hits:
        if now - ts <= window:
            auth_counts[ip] += 1

    for conn in connections:
        inbound, rip, lport, service = inbound_session(conn)
        if not rip or rip in allow:
            continue
        if inbound:
            key = ("in", rip, lport, conn.status)
            if key not in state.seen_keys:
                state.seen_keys.add(key)
                alerts.append(
                    IntrusionAlert(
                        ip=rip,
                        severity="malicious",
                        category="inbound-session",
                        evidence=[
                            f"inbound {conn.status or 'session'} {conn.remote} -> {conn.local}",
                            f"service {service or 'unknown'} on port {lport}",
                        ],
                        local_port=lport,
                        service=service,
                        ts=now,
                    )
                )
        status = (conn.status or "").upper()
        if is_public_ip(rip) and lport and (
            inbound or lport in SENSITIVE_PORTS or status in {"SYN_RECV", "SYN_RCVD"}
        ):
            state.port_hits.append((now, rip, lport))
    keep(state.port_hits)
    ports_by_ip: dict[str, set[int]] = defaultdict(set)
    for ts, ip, port in state.port_hits:
        if now - ts <= window:
            ports_by_ip[ip].add(port)

    for ip, count in auth_counts.items():
        if count >= brute_n:
            key = ("brute", ip, int(now // window))
            if key not in state.seen_keys:
                state.seen_keys.add(key)
                alerts.append(
                    IntrusionAlert(
                        ip=ip,
                        severity="malicious",
                        category="brute-force",
                        evidence=[f"{count} failed authentications in {int(window)}s"],
                        service="auth",
                        ts=now,
                    )
                )

    for ip, ports in ports_by_ip.items():
        if len(ports) >= scan_n and is_public_ip(ip) and ip not in allow:
            key = ("scan", ip, int(now // 60))
            if key not in state.seen_keys:
                state.seen_keys.add(key)
                sample = ", ".join(str(p) for p in sorted(ports)[:12])
                alerts.append(
                    IntrusionAlert(
                        ip=ip,
                        severity="suspicious",
                        category="port-scan",
                        evidence=[f"{len(ports)} distinct local ports probed ({sample})"],
                        ts=now,
                    )
                )

    for ev in auth_events:
        if ev.source == "who" and is_public_ip(ev.ip) and ev.ip not in allow:
            key = ("who", ev.ip, ev.user)
            if key not in state.seen_keys:
                state.seen_keys.add(key)
                alerts.append(
                    IntrusionAlert(
                        ip=ev.ip,
                        severity="malicious",
                        category="remote-login",
                        evidence=[f"interactive login {ev.user or '?'} from {ev.ip}: {ev.message}"],
                        service="shell",
                        ts=now,
                    )
                )

    already = load_blocked(cfg)
    out: list[IntrusionAlert] = []
    for alert in alerts:
        if alert.ip in allow or not is_public_ip(alert.ip):
            continue
        if enrich:
            try:
                alert.geo = enrich_ip(alert.ip, fetch=fetch, do_dns=True)
            except Exception as exc:  # noqa: BLE001
                alert.geo = {"ip": alert.ip, "error": str(exc)}
            loc = format_location(alert.geo)
            alert.evidence.append(f"origin {loc}")
        if apply_blocks and getattr(cfg, "intrusion_auto_block", True):
            if alert.ip not in already or alert.severity == "malicious":
                entry = block_ip(
                    cfg,
                    alert.ip,
                    reason=f"{alert.category}: {'; '.join(alert.evidence[:2])}",
                    details=alert.to_dict(),
                    firewall=bool(getattr(cfg, "intrusion_firewall_block", False)),
                )
                fw = entry.get("firewall") or {}
                if fw.get("attempted") and fw.get("ok"):
                    alert.action = "blocked-firewall"
                else:
                    alert.action = "blocked-local"
                    if fw.get("attempted") and not fw.get("ok"):
                        alert.evidence.append(f"firewall not applied: {fw.get('detail')}")
        out.append(alert)
        append_event(
            DefenseEvent(
                kind="intrusion",
                severity=alert.severity,
                message=f"{alert.category} from {alert.ip} {format_location(alert.geo) if alert.geo else ''}".strip(),
                details=alert.to_dict(),
            ),
            cfg,
        )
    state.alerts.extend(out)
    return state, out


def run_intrusion_check(
    cfg: DefenderConfig | None = None,
    connections: list[Connection] | None = None,
    auth_events: list[AuthEvent] | None = None,
    state: IntrusionState | None = None,
    enrich: bool = True,
    fetch=None,
    apply_blocks: bool = True,
    collect: bool = True,
    unified_log: bool = False,
) -> tuple[IntrusionState, list[IntrusionAlert]]:
    cfg = cfg or get_config()
    if connections is None:
        connections = list_connections(cfg)
    if auth_events is None:
        auth_events = collect_auth_events(unified_log=unified_log) if collect else []
    return evaluate_intrusions(
        connections,
        auth_events,
        state=state,
        cfg=cfg,
        enrich=enrich,
        fetch=fetch,
        apply_blocks=apply_blocks,
    )
