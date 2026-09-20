"""Real-time protection: watch folders and auto-scan changed files.

Uses `watchdog` when installed (efficient, cross-platform) and falls back
to a portable polling watcher otherwise. No hard dependency.
"""
from __future__ import annotations

import time
from pathlib import Path

from .config import DefenderConfig, get_config
from .quarantine import quarantine_file
from .scanner import scan_file
from .signatures import load_db


def _poll_snapshot(paths: list[Path]) -> dict[str, float]:
    snap: dict[str, float] = {}
    for root in paths:
        if root.is_file():
            try:
                snap[str(root)] = root.stat().st_mtime
            except OSError:
                continue
        elif root.is_dir():
            for p in root.rglob("*"):
                if p.is_symlink():
                    continue
                try:
                    if p.is_file():
                        snap[str(p)] = p.stat().st_mtime
                except OSError:
                    continue
    return snap


def _handle_event(path: str, cfg: DefenderConfig, on_threat=None) -> None:
    db = load_db(cfg.signatures_file)
    finding = scan_file(path, db=db, cfg=cfg)
    print(f"[{finding.verdict.upper()}] {finding.path} score={finding.score} :: {'; '.join(finding.reasons)}")
    if finding.verdict == "malicious" and cfg.auto_quarantine:
        try:
            record = quarantine_file(path, finding.sha256, finding.verdict, finding.reasons, cfg)
            print(f"quarantined -> {record.stored_path}")
        except OSError as exc:
            print(f"quarantine failed for {path}: {exc}")
    if on_threat and finding.verdict in ("malicious", "suspicious"):
        try:
            on_threat(finding)
        except Exception:
            pass


def monitor_polling(watch: list[str], cfg: DefenderConfig, interval: float = 2.0, on_threat=None) -> None:
    paths = [Path(w).expanduser() for w in watch]
    print(f"AIDefender polling monitor on: {', '.join(str(p) for p in paths)} (Ctrl+C to stop)")
    snap = _poll_snapshot(paths)
    try:
        while True:
            time.sleep(interval)
            new_snap = _poll_snapshot(paths)
            for key, mtime in new_snap.items():
                if key not in snap or snap[key] != mtime:
                    _handle_event(key, cfg, on_threat)
            snap = new_snap
    except KeyboardInterrupt:
        print("monitor stopped")


def monitor(watch: list[str] | None = None, cfg: DefenderConfig | None = None, on_threat=None) -> None:
    cfg = cfg or get_config()
    watch = watch or cfg.watch_paths
    try:
        from watchdog.events import FileSystemEventHandler  # type: ignore
        from watchdog.observers import Observer  # type: ignore
    except ImportError:
        monitor_polling(watch, cfg, on_threat=on_threat)
        return

    class Handler(FileSystemEventHandler):
        def on_created(self, event):  # noqa: N802
            if not event.is_directory:
                _handle_event(event.src_path, cfg, on_threat)

        def on_modified(self, event):  # noqa: N802
            if not event.is_directory:
                _handle_event(event.src_path, cfg, on_threat)

        def on_moved(self, event):  # noqa: N802
            if not event.is_directory:
                _handle_event(getattr(event, "dest_path", event.src_path), cfg, on_threat)

    observer = Observer()
    handler = Handler()
    watched = 0
    for w in watch:
        p = Path(w).expanduser()
        if p.exists():
            observer.schedule(handler, str(p), recursive=True)
            watched += 1
        else:
            print(f"watch path missing, skipping: {p}")
    if watched == 0:
        print("no valid watch paths; falling back to polling")
        monitor_polling(watch, cfg, on_threat=on_threat)
        return
    print(f"AIDefender real-time monitor on: {', '.join(watch)} (Ctrl+C to stop)")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
    print("monitor stopped")
