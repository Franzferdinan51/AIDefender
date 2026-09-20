"""Background defense loop: periodic scans + process/network checks."""
from __future__ import annotations

import time
from pathlib import Path

from .config import DefenderConfig, get_config
from .network import suspicious_connections
from .processes import suspicious_processes
from .quarantine import quarantine_file
from .scanner import scan_path
from .signatures import load_db

DEFAULT_QUICK_PATHS: list[str] = []


def quick_scan_targets(cfg: DefenderConfig) -> list[str]:
    targets = list(cfg.watch_paths) + DEFAULT_QUICK_PATHS
    return [t for t in targets if Path(t).expanduser().exists()]


def run_daemon(cfg: DefenderConfig | None = None, interval: int = 3600, once: bool = False) -> None:
    cfg = cfg or get_config()
    cfg.ensure_dirs()
    print(f"AIDefender daemon starting (interval={interval}s, auto_quarantine={cfg.auto_quarantine})")
    while True:
        db = load_db(cfg.signatures_file)
        for target in quick_scan_targets(cfg):
            print(f"quick scan: {target}")
            for finding in scan_path(target, db=db, cfg=cfg):
                if finding.verdict in ("malicious", "suspicious"):
                    print(f"[{finding.verdict.upper()}] {finding.path} score={finding.score}")
                    if finding.verdict == "malicious" and cfg.auto_quarantine:
                        try:
                            rec = quarantine_file(finding.path, finding.sha256, finding.verdict, finding.reasons, cfg)
                            print(f"  quarantined -> {rec.stored_path}")
                        except OSError as exc:
                            print(f"  quarantine failed: {exc}")
        bad_procs = suspicious_processes()
        if bad_procs:
            print(f"suspicious processes: {len(bad_procs)}")
            for p in bad_procs[:10]:
                print(f"  pid={p.pid} {p.name} :: {'; '.join(p.reasons)}")
        bad_conns = suspicious_connections()
        if bad_conns:
            print(f"suspicious connections: {len(bad_conns)}")
            for c in bad_conns[:10]:
                print(f"  {c.local} -> {c.remote} :: {'; '.join(c.reasons)}")
        if once:
            break
        print(f"sleeping {interval}s ...")
        time.sleep(interval)
