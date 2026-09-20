"""Process guard: list processes and flag suspicious ones.

Uses `psutil` when available; falls back to `ps` (macOS/Linux) and
`tasklist` (Windows) parsing so the command works everywhere.
"""
from __future__ import annotations

import csv
import io
import shutil
import subprocess
from dataclasses import dataclass, field

SUSPICIOUS_NAMES = {
    "mimikatz", "pwdump", "psexec", "powersploit", "empire",
    "metasploit", "meterpreter", "cobaltstrike", "beacon.exe",
    "keylogger", "njrat", "darkcomet", "remcos", "quasar",
    "lazagne", "procdump", "pypykatz", "hashcat", "minikatz",
    "xmrig", "nbminer",
}
SUSPICIOUS_CMDLINE = [
    "powershell -enc", "frombase64string", "invoke-mimikatz",
    "downloadstring", "| sh", "| bash", "/dev/tcp",
    "regsvr32", "rundll32 javascript", "schtasks /create",
    "powershell -nop", "powershell -w hidden", "-encodedcommand",
    "mshta http", "certutil -decode", "bitsadmin /transfer",
    "invoke-webrequest", "iex(", "osascript -e",
    "nc -l", "ncat -l", "socat tcp", "vssadmin delete",
]


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cmdline: str = ""
    exe: str = ""
    suspicious: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"pid": self.pid, "name": self.name, "cmdline": self.cmdline,
                "exe": self.exe, "suspicious": self.suspicious, "reasons": self.reasons}


def flag_process(
    proc: ProcessInfo,
    extra_names: dict[str, str] | None = None,
    extra_cmdline: dict[str, str] | None = None,
) -> ProcessInfo:
    lname = proc.name.lower()
    lcmd = proc.cmdline.lower()
    for bad in SUSPICIOUS_NAMES:
        if bad in lname or bad in lcmd:
            proc.suspicious = True
            proc.reasons.append(f"known-bad token: {bad}")
    for tok in SUSPICIOUS_CMDLINE:
        if tok in lcmd:
            proc.suspicious = True
            proc.reasons.append(f"suspicious cmdline: {tok}")
    from .rogue_ai import flag_cmdline
    for reason in flag_cmdline(proc.cmdline):
        proc.suspicious = True
        proc.reasons.append(reason)
    for needle, label in (extra_names or {}).items():
        n = needle.lower()
        if n and (n in lname or n in lcmd):
            proc.suspicious = True
            proc.reasons.append(f"intel process: {label}")
    for needle, label in (extra_cmdline or {}).items():
        n = needle.lower()
        if n and n in lcmd:
            proc.suspicious = True
            proc.reasons.append(f"intel cmdline: {label}")
    # Temp-location executables are a classic dropper sign.
    lexec = proc.exe.lower()
    if lexec and any(t in lexec for t in ("/tmp/", "/var/tmp/", "\\temp\\", "\\tmp\\", "appdata\\local\\temp")):
        proc.suspicious = True
        proc.reasons.append("executable running from temp directory")
    return proc


def _via_psutil() -> list[ProcessInfo] | None:
    try:
        import psutil  # type: ignore
    except ImportError:
        return None
    out: list[ProcessInfo] = []
    for p in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
        try:
            info = p.info
            cmd = " ".join(info.get("cmdline") or [])
            out.append(ProcessInfo(
                pid=int(info.get("pid", 0)),
                name=str(info.get("name") or ""),
                cmdline=cmd, exe=str(info.get("exe") or ""),
            ))
        except Exception:
            continue
    return out


def _via_ps() -> list[ProcessInfo] | None:
    if not shutil.which("ps"):
        return None
    try:
        res = subprocess.run(["ps", "-axo", "pid=,comm=,command="],
                             capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    out: list[ProcessInfo] = []
    for line in res.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        name = parts[1].split("/")[-1]
        cmd = parts[2] if len(parts) > 2 else ""
        out.append(ProcessInfo(pid=pid, name=name, cmdline=cmd))
    return out


def _via_tasklist() -> list[ProcessInfo] | None:
    if not shutil.which("tasklist"):
        return None
    try:
        res = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    out: list[ProcessInfo] = []
    try:
        for row in csv.reader(io.StringIO(res.stdout)):
            if len(row) < 2:
                continue
            name = row[0].strip('"')
            try:
                pid = int(row[1].strip('"'))
            except ValueError:
                continue
            out.append(ProcessInfo(pid=pid, name=name))
    except Exception:
        return None
    return out


def list_processes(db=None, cfg=None) -> list[ProcessInfo]:
    rows: list[ProcessInfo] | None = None
    for source in (_via_psutil, _via_ps, _via_tasklist):
        result = source()
        if result is not None:
            rows = result
            break
    if rows is None:
        return []
    extra_n = db.process_names if db is not None else None
    extra_c = db.process_cmdline if db is not None else None
    flagged = [flag_process(p, extra_names=extra_n, extra_cmdline=extra_c) for p in rows]
    if cfg is None:
        return flagged
    from .allowlist import is_process_allowed
    for proc in flagged:
        why = is_process_allowed(cfg, proc.name, proc.exe, proc.cmdline)
        if why:
            proc.suspicious = False
            proc.reasons.append(why)
    return flagged


def suspicious_processes(db=None) -> list[ProcessInfo]:
    return [p for p in list_processes(db=db) if p.suspicious]


def new_suspicious_processes(
    current: list[ProcessInfo],
    previous_pids: set[int],
) -> list[ProcessInfo]:
    """Processes that are suspicious and were not in the last snapshot."""
    return [p for p in current if p.suspicious and p.pid not in previous_pids]
