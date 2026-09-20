"""Real-time file protection: watch folders and auto-scan changed files.

Uses `watchdog` when installed (efficient, cross-platform) and falls back
to a portable polling watcher otherwise. No hard dependency.

Events are settled (wait for size/mtime to stop changing), debounced, and
deduped by content hash so a download does not scan a half-written file
dozens of times. A burst of unique files in one directory is treated as a
ransomware-style signal. Partial download suffixes are ignored.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .config import DefenderConfig, get_config
from .events import DefenseEvent, append_event
from .quarantine import quarantine_file
from .scanner import Finding, scan_file, sha256_of
from .signatures import load_db

SKIP_SUFFIXES = (
    ".crdownload",
    ".part",
    ".partial",
    ".download",
    ".tmp",
    ".temp",
    ".swp",
    ".swo",
)
SKIP_NAMES = {".ds_store", "thumbs.db", "desktop.ini", ".localized"}
SKIP_DIR_NAMES = {"__pycache__", ".git", ".venv", "node_modules"}


def should_skip_path(path: str | Path, cfg: DefenderConfig | None = None) -> str | None:
    p = Path(path)
    name = p.name.lower()
    if name in SKIP_NAMES:
        return f"ignored name {p.name}"
    if name.endswith(SKIP_SUFFIXES) or name.endswith(".tmp") or name.startswith(".~"):
        return f"partial/temp name {p.name}"
    if name.endswith("~"):
        return "editor backup"
    try:
        if cfg and cfg.quarantine_dir:
            q = Path(cfg.quarantine_dir).resolve()
            if q in p.resolve().parents or p.resolve() == q:
                return "inside quarantine dir"
        if cfg and cfg.base_dir:
            b = Path(cfg.base_dir).resolve()
            # Do not scan the defender's own config/log, but do scan watch roots elsewhere.
            if p.resolve() == b or p.parent.resolve() == b and p.suffix == ".json":
                return "inside defender config dir"
    except OSError:
        return "unreadable path"
    return None


def wait_until_stable(path: Path, timeout: float, interval: float = 0.05) -> bool:
    """Return True if the file exists; wait until size/mtime stop changing."""
    if timeout <= 0:
        return path.is_file()
    deadline = time.time() + timeout
    last: tuple[float, int] | None = None
    while True:
        try:
            st = path.stat()
            sig = (st.st_mtime, st.st_size)
        except OSError:
            if time.time() >= deadline:
                return False
            time.sleep(interval)
            continue
        if last == sig:
            return True
        last = sig
        if time.time() >= deadline:
            return path.is_file()
        time.sleep(min(interval, max(0.0, deadline - time.time())))


class BurstDetector:
    """Alert when many unique files change in one directory in a short window."""

    def __init__(self, window: float = 8.0, threshold: int = 25):
        self.window = window
        self.threshold = threshold
        self._events: deque[tuple[float, str, str]] = deque()  # ts, dir, path

    def record(self, path: str) -> str | None:
        now = time.time()
        directory = str(Path(path).parent)
        self._events.append((now, directory, path))
        cutoff = now - self.window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        unique = {p for ts, d, p in self._events if d == directory}
        if len(unique) >= self.threshold:
            return (
                f"ransomware-like burst: {len(unique)} files changed under {directory} "
                f"in {self.window:.0f}s"
            )
        return None


@dataclass
class FileGuard:
    """Session state for on-access scanning (hash cache, cooldown, burst)."""

    last_fire: dict[str, float] = field(default_factory=dict)
    last_hash: dict[str, str] = field(default_factory=dict)
    burst: BurstDetector = field(default_factory=BurstDetector)
    events_emitted: int = 0

    def handle(
        self,
        path: str,
        cfg: DefenderConfig,
        action: str = "modified",
        on_threat=None,
        db=None,
        quiet: bool = False,
        record_burst: bool = True,
    ) -> Finding | None:
        skip = should_skip_path(path, cfg)
        if skip:
            return None
        p = Path(path)
        if action == "deleted":
            event = DefenseEvent(
                kind="file",
                severity="info",
                message="file disappeared from a watched path",
                path=str(p),
            )
            append_event(event, cfg)
            self.events_emitted += 1
            return None
        if not p.is_file() or p.is_symlink():
            return None

        now = time.time()
        cooldown = float(cfg.file_cooldown_seconds or 0)
        if cooldown and now - self.last_fire.get(str(p), 0) < cooldown:
            return None
        self.last_fire[str(p)] = now

        wait_until_stable(p, float(cfg.file_settle_seconds or 0))
        if not p.is_file():
            return None

        db = db or load_db(cfg.signatures_file)
        try:
            digest = sha256_of(p, max_bytes=min(cfg.max_scan_bytes, 1024 * 1024))
        except OSError:
            digest = ""
        if digest and self.last_hash.get(str(p)) == digest:
            return None
        if digest:
            self.last_hash[str(p)] = digest

        finding = scan_file(p, db=db, cfg=cfg)
        burst_reason = self.burst.record(str(p)) if record_burst else None
        if burst_reason:
            finding.reasons.append(burst_reason)
            append_event(
                DefenseEvent(
                    kind="burst",
                    severity="suspicious",
                    message=burst_reason,
                    path=str(p.parent),
                ),
                cfg,
            )
            self.events_emitted += 1

        if not quiet:
            print(f"[{finding.verdict.upper()}] {finding.path} score={finding.score} :: {'; '.join(finding.reasons)}")
        if finding.verdict in ("malicious", "suspicious"):
            append_event(
                DefenseEvent(
                    kind="file",
                    severity=finding.verdict,
                    message="; ".join(finding.reasons[:5]),
                    path=finding.path,
                    details={"score": finding.score, "sha256": finding.sha256, "action": action},
                ),
                cfg,
            )
            self.events_emitted += 1
        if finding.verdict == "malicious" and cfg.auto_quarantine:
            try:
                record = quarantine_file(path, finding.sha256, finding.verdict, finding.reasons, cfg)
                if not quiet:
                    print(f"quarantined -> {record.stored_path}")
            except OSError as exc:
                if not quiet:
                    print(f"quarantine failed for {path}: {exc}")
        if on_threat and finding.verdict in ("malicious", "suspicious"):
            try:
                on_threat(finding)
            except Exception:
                pass
        return finding


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
                if any(part in SKIP_DIR_NAMES for part in p.parts):
                    continue
                try:
                    if p.is_file():
                        snap[str(p)] = p.stat().st_mtime
                except OSError:
                    continue
    return snap


def poll_once(
    paths: list[str] | list[Path],
    prev: dict[str, float],
    cfg: DefenderConfig,
    guard: FileGuard | None = None,
    on_threat=None,
    db=None,
    quiet: bool = False,
) -> tuple[dict[str, float], list[Finding]]:
    """One polling tick. Shipped entry used by monitor, protect, and tests."""
    roots = [Path(w).expanduser() for w in paths]
    guard = guard or FileGuard(
        burst=BurstDetector(window=cfg.burst_window_seconds, threshold=int(cfg.burst_file_threshold)),
    )
    new_snap = _poll_snapshot(roots)
    findings: list[Finding] = []
    for key, mtime in new_snap.items():
        if key not in prev or prev[key] != mtime:
            finding = guard.handle(
                key, cfg, action="modified", on_threat=on_threat, db=db, quiet=quiet,
                record_burst=bool(prev),
            )
            if finding is not None:
                findings.append(finding)
    for key in list(prev):
        if key not in new_snap:
            guard.handle(key, cfg, action="deleted", on_threat=on_threat, db=db, quiet=quiet)
    return new_snap, findings


def _handle_event(path: str, cfg: DefenderConfig, on_threat=None) -> None:
    """Backward-compatible one-shot handler (no session cache)."""
    FileGuard().handle(path, cfg, on_threat=on_threat)


def _should_stop(stop_event, deadline: float | None, guard: FileGuard, max_events: int | None) -> bool:
    if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
        return True
    if deadline is not None and time.time() >= deadline:
        return True
    if max_events is not None and guard.events_emitted >= max_events:
        return True
    return False


def monitor_polling(
    watch: list[str],
    cfg: DefenderConfig,
    interval: float = 2.0,
    on_threat=None,
    stop_event=None,
    max_seconds: float | None = None,
    max_events: int | None = None,
    guard: FileGuard | None = None,
) -> FileGuard:
    paths = [Path(w).expanduser() for w in watch]
    print(f"AIDefender polling monitor on: {', '.join(str(p) for p in paths)} (Ctrl+C to stop)")
    guard = guard or FileGuard(
        burst=BurstDetector(window=cfg.burst_window_seconds, threshold=int(cfg.burst_file_threshold)),
    )
    db = load_db(cfg.signatures_file)
    snap = _poll_snapshot(paths)
    deadline = time.time() + max_seconds if max_seconds is not None else None
    try:
        while not _should_stop(stop_event, deadline, guard, max_events):
            time.sleep(max(0.05, interval))
            snap, _ = poll_once(paths, snap, cfg, guard=guard, on_threat=on_threat, db=db)
    except KeyboardInterrupt:
        print("monitor stopped")
        return guard
    print("monitor stopped")
    return guard


def monitor(
    watch: list[str] | None = None,
    cfg: DefenderConfig | None = None,
    on_threat=None,
    stop_event=None,
    max_seconds: float | None = None,
    max_events: int | None = None,
    poll_interval: float = 2.0,
    guard: FileGuard | None = None,
) -> FileGuard:
    cfg = cfg or get_config()
    watch = watch or cfg.watch_paths
    guard = guard or FileGuard(
        burst=BurstDetector(window=cfg.burst_window_seconds, threshold=int(cfg.burst_file_threshold)),
    )
    deadline = time.time() + max_seconds if max_seconds is not None else None
    try:
        from watchdog.events import FileSystemEventHandler  # type: ignore
        from watchdog.observers import Observer  # type: ignore
    except ImportError:
        return monitor_polling(
            watch, cfg, interval=poll_interval, on_threat=on_threat,
            stop_event=stop_event, max_seconds=max_seconds, max_events=max_events, guard=guard,
        )

    class Handler(FileSystemEventHandler):
        def on_created(self, event):  # noqa: N802
            if not event.is_directory:
                guard.handle(event.src_path, cfg, action="created", on_threat=on_threat)

        def on_modified(self, event):  # noqa: N802
            if not event.is_directory:
                guard.handle(event.src_path, cfg, action="modified", on_threat=on_threat)

        def on_moved(self, event):  # noqa: N802
            if not event.is_directory:
                guard.handle(getattr(event, "dest_path", event.src_path), cfg, action="moved", on_threat=on_threat)

        def on_deleted(self, event):  # noqa: N802
            if not event.is_directory:
                guard.handle(event.src_path, cfg, action="deleted", on_threat=on_threat)

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
        return monitor_polling(
            watch, cfg, interval=poll_interval, on_threat=on_threat,
            stop_event=stop_event, max_seconds=max_seconds, max_events=max_events, guard=guard,
        )
    print(f"AIDefender real-time monitor on: {', '.join(watch)} (Ctrl+C to stop)")
    observer.start()
    try:
        while not _should_stop(stop_event, deadline, guard, max_events):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join(timeout=5)
    print("monitor stopped")
    return guard
