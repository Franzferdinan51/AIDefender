"""Machine-readable tool catalog so agents can discover defensive actions."""
from __future__ import annotations

CATALOG = [
    {"name": "scan", "argv": ["scan", "<path>"], "json": True, "action": False, "purpose": "Scan a file or directory for malware, prompt-injection, and rogue-AI exfil signals."},
    {"name": "analyze", "argv": ["analyze", "<path>"], "json": True, "action": False, "purpose": "Local-first AI triage of scan artifacts (not a full-file upload)."},
    {"name": "protect", "argv": ["protect", "--once"], "json": True, "action": False, "purpose": "One tick of file + process + network + persistence + intrusion defense."},
    {"name": "intrusion", "argv": ["intrusion"], "json": True, "action": False, "purpose": "Detect inbound sessions, brute force, and scans; enrich IPs with geo/rDNS."},
    {"name": "diag", "argv": ["diag"], "json": True, "action": False, "purpose": "Netstat-class snapshot: connections, listeners, ARP, routes, available tools."},
    {"name": "connections", "argv": ["network"], "json": True, "action": False, "purpose": "List sockets (ss/netstat/psutil) and flag risky remotes."},
    {"name": "processes", "argv": ["processes"], "json": True, "action": False, "purpose": "List processes and flag suspicious names/cmdlines."},
    {"name": "inspect-ip", "argv": ["inspect", "ip", "<ip>"], "json": True, "action": False, "purpose": "Geo, rDNS, allow/block status, and matching live connections for one IP."},
    {"name": "capture", "argv": ["capture", "--seconds", "3", "--count", "40"], "json": True, "action": False, "purpose": "Bounded receive-only packet capture via tcpdump/tshark if installed."},
    {"name": "allow-add", "argv": ["allow", "add", "--ip", "<ip>", "--note", "<why>"], "json": True, "action": True, "purpose": "Allowlist an IP/CIDR/port/process/path/hash the user trusts."},
    {"name": "allow-remove", "argv": ["allow", "remove", "--ip", "<ip>"], "json": True, "action": True, "purpose": "Remove an allowlist entry."},
    {"name": "block-add", "argv": ["block", "add", "--ip", "<ip>"], "json": True, "action": True, "purpose": "Locally block an attacker IP. Add --firewall only with user consent."},
    {"name": "block-remove", "argv": ["block", "remove", "--ip", "<ip>"], "json": True, "action": True, "purpose": "Unblock an IP."},
    {"name": "quarantine", "argv": ["quarantine", "list"], "json": True, "action": True, "purpose": "List or restore/delete quarantined files."},
    {"name": "stop-process", "argv": ["act", "stop-process", "--pid", "<pid>"], "json": True, "action": True, "purpose": "SIGTERM a local process. Refuses pid 1 and self. Prefer --name match."},
    {"name": "update", "argv": ["update"], "json": True, "action": True, "purpose": "Refresh live malware/intel definitions."},
    {"name": "engines", "argv": ["engines"], "json": True, "action": False, "purpose": "Show which defense engines are live."},
    {"name": "events", "argv": ["events", "-n", "50"], "json": True, "action": False, "purpose": "Recent defense event log."},
]


def tool_catalog() -> list[dict]:
    return list(CATALOG)
