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
    "metasploit", "meterpreter", "cobaltstrike", "beacon",
    "keylogger", "njrat", "darkcomet", "remcos", "quasar",
}
SUSPICIOUS_CMDLINE = [
    "powershell -enc", "frombase64string", "invoke-mimikatz",
    "downloadstring", "| sh", "curl", "wget", "/dev/tcp",
    "regsvr32", "rundll32", "schtasks /create",
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


def _flag(proc: ProcessInfo) -> ProcessInfo:
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
            out.append(_flag(ProcessInfo(
                pid=int(info.get("pid", 0)),
                name=str(info.get("name") or ""),
                cmdline=cmd, exe=str(info.get("exe") or ""),
            )))
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
        out.append(_flag(ProcessInfo(pid=pid, name=name, cmdline=cmd)))
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
            out.append(_flag(ProcessInfo(pid=pid, name=name)))
    except Exception:
        return None
    return out


def list_processes() -> list[ProcessInfo]:
    for source in (_via_psutil, _via_ps, _via_tasklist):
        result = source()
        if result is not None:
            return result
    return []


def suspicious_processes() -> list[ProcessInfo]:
    return [p for p in list_processes() if p.suspicious]
