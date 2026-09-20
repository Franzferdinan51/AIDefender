"""Background defense: real-time protect ticks + periodic directory sweeps."""
from __future__ import annotations

import threading
import time
from pathlib import Path

from .config import DefenderConfig, get_config
from .protect import ProtectionState, protection_cycle, run_protect, watch_targets
from .quarantine import quarantine_file
from .scanner import scan_path
from .signatures import load_db
from .onaccess import start_file_protection


def quick_scan_targets(cfg: DefenderConfig) -> list[str]:
    return watch_targets(cfg)


def _sweep(cfg: DefenderConfig) -> None:
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


def run_daemon(
    cfg: DefenderConfig | None = None,
    interval: int = 3600,
    once: bool = False,
    protect: bool = True,
    seconds: float | None = None,
    paths: list[str] | None = None,
) -> ProtectionState | None:
    cfg = cfg or get_config()
    cfg.ensure_dirs()
    print(
        f"AIDefender daemon starting (sweep={interval}s, protect={protect}, "
        f"auto_quarantine={cfg.auto_quarantine})"
    )
    if once:
        state = None
        if protect:
            state = protection_cycle(cfg, extra_paths=paths, scan_persist=True)
        _sweep(cfg)
        return state

    stop = threading.Event()
    file_thread = None
    if protect:
        watch = paths or watch_targets(cfg)
        file_thread = threading.Thread(
            target=start_file_protection,
            kwargs={"watch": watch, "cfg": cfg, "stop_event": stop},
            daemon=True,
            name="aidefender-files",
        )
        file_thread.start()

    state = ProtectionState()
    last_sweep = 0.0
    deadline = time.time() + seconds if seconds is not None else None
    tick = float(cfg.protect_interval_seconds or 10.0)
    try:
        while True:
            if deadline is not None and time.time() >= deadline:
                break
            if cfg.auto_update_definitions:
                from .updater import maybe_update
                maybe_update(cfg, quiet=True)
            if protect:
                state = protection_cycle(
                    cfg, state, extra_paths=paths, scan_persist=True, watch_files=False,
                )
            now = time.time()
            if now - last_sweep >= interval:
                _sweep(cfg)
                last_sweep = now
            if deadline is not None and time.time() >= deadline:
                break
            time.sleep(max(0.2, tick))
    except KeyboardInterrupt:
        print("daemon stopping")
    finally:
        stop.set()
        if file_thread is not None:
            file_thread.join(timeout=3)
    print("daemon stopped")
    return state
