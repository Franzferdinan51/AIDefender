"""Bounded packet capture for diagnosis (tcpdump/tshark if installed).

Receive-only. Hard caps on duration and packet count. No injection, no
MITM, no exploit payloads. If capture tools are missing, report that
clearly so an agent can tell the user to install tcpdump/Wireshark.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

# tcpdump -nn: "12:00:00.001 IP 1.2.3.4.443 > 10.0.0.5.51234: Flags [S],"
_TCPDUMP_IP = re.compile(
    r"\bIP6?\s+(\S+)\s+>\s+(\S+):",
)
_HOSTPORT = re.compile(r"^(?P<host>.*?)(?:\.(?P<port>\d+))?$")


def capture_available() -> dict:
    tshark = shutil.which("tshark") or shutil.which("dumpcap") or ""
    tcpdump = shutil.which("tcpdump") or ""
    return {
        "tshark": tshark,
        "tcpdump": tcpdump,
        "available": bool(tshark or tcpdump),
    }


def parse_tcpdump_text(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in (text or "").splitlines():
        match = _TCPDUMP_IP.search(line)
        if not match:
            continue
        src, dst = match.group(1), match.group(2)

        def split(addr: str) -> tuple[str, str]:
            m = _HOSTPORT.match(addr.rstrip(":"))
            if not m:
                return addr, ""
            return m.group("host") or addr, m.group("port") or ""

        sh, sp = split(src)
        dh, dp = split(dst)
        rows.append({
            "src": sh,
            "sport": sp,
            "dst": dh,
            "dport": dp,
            "raw": line.strip()[:300],
        })
    return rows


def summarize_flows(packets: list[dict]) -> list[dict]:
    counts: dict[tuple[str, str, str, str], int] = {}
    for pkt in packets:
        key = (pkt.get("src") or "", pkt.get("sport") or "", pkt.get("dst") or "", pkt.get("dport") or "")
        counts[key] = counts.get(key, 0) + 1
    flows = []
    for (src, sport, dst, dport), n in sorted(counts.items(), key=lambda kv: -kv[1]):
        flows.append({"src": src, "sport": sport, "dst": dst, "dport": dport, "packets": n})
    return flows


def run_capture(
    seconds: float = 3.0,
    count: int = 40,
    bpf: str = "",
    dest_dir: str | Path | None = None,
) -> dict:
    """Run a short capture. Returns metadata + parsed flows (no full payloads)."""
    info = capture_available()
    seconds = max(0.2, min(float(seconds), 15.0))
    count = max(1, min(int(count), 200))
    if not info["available"]:
        return {
            "ok": False,
            "error": "neither tcpdump nor tshark is installed",
            "hint": "Install Wireshark (tshark) or tcpdump for packet-level diagnosis.",
            "tools": info,
            "packets": [],
            "flows": [],
        }
    dest = Path(dest_dir) if dest_dir else Path.cwd()
    dest.mkdir(parents=True, exist_ok=True)
    pcap = dest / f"aidefender-capture-{int(time.time())}.pcap"
    text = ""
    cmd: list[str] = []
    try:
        if info["tcpdump"]:
            cmd = [info["tcpdump"], "-nn", "-l", "-c", str(count)]
            if bpf:
                cmd.extend(bpf.split())
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 3)
            text = (proc.stdout or "") + (proc.stderr or "")
        elif info["tshark"]:
            cmd = [info["tshark"], "-n", "-c", str(count), "-T", "fields",
                   "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 3)
            text = proc.stdout or ""
            packets = []
            for line in text.splitlines():
                parts = line.split("\t")
                if len(parts) >= 4:
                    packets.append({"src": parts[0], "sport": parts[1], "dst": parts[2], "dport": parts[3], "raw": line[:300]})
            return {
                "ok": True,
                "tool": "tshark",
                "command": cmd,
                "pcap": "",
                "packets": packets[:count],
                "flows": summarize_flows(packets),
                "error": (proc.stderr or "")[:400],
            }
    except subprocess.TimeoutExpired as exc:
        text = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
    except OSError as exc:
        return {"ok": False, "error": str(exc), "tools": info, "packets": [], "flows": []}
    packets = parse_tcpdump_text(text)
    return {
        "ok": True,
        "tool": "tcpdump",
        "command": cmd,
        "pcap": str(pcap) if pcap.exists() else "",
        "packets": packets[:count],
        "flows": summarize_flows(packets),
        "error": "",
    }
