"""Scan running process images (the files backing live malware).

Commercial AV user-mode components hash process executables against the
definition DB. This does the same via ``scan_file`` on each unique ``exe``.
"""
from __future__ import annotations

from pathlib import Path

from .config import DefenderConfig, get_config
from .processes import ProcessInfo, list_processes
from .scanner import Finding, scan_file
from .signatures import load_db


def scan_process_images(
    cfg: DefenderConfig | None = None,
    processes: list[ProcessInfo] | None = None,
    limit: int = 120,
) -> list[Finding]:
    cfg = cfg or get_config()
    db = load_db(cfg.signatures_file)
    procs = processes if processes is not None else list_processes(db=db)
    findings: list[Finding] = []
    seen: set[str] = set()
    for proc in procs:
        exe = (proc.exe or "").strip()
        if not exe:
            cmd = (proc.cmdline or "").split()
            if cmd and cmd[0].startswith("/"):
                exe = cmd[0]
        if not exe or exe in seen:
            continue
        seen.add(exe)
        p = Path(exe)
        if not p.is_file():
            continue
        finding = scan_file(p, db=db, cfg=cfg)
        finding.reasons.append(f"running image pid={proc.pid} name={proc.name}")
        findings.append(finding)
        if len(findings) >= limit:
            break
    return findings
