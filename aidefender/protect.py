"""Unified user-space real-time protection cycle.

One tick scans watched files for changes, diffs process and network
snapshots for *new* suspicious items, and scans user persistence dirs.
`scan` stays offline; this module is the RTP loop used by `protect`,
`monitor`, and `daemon`.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import DefenderConfig, get_config
from .events import DefenseEvent, append_event
from .network import Connection, list_connections, new_suspicious_connections
from .persistence import scan_persistence
from .processes import ProcessInfo, list_processes, new_suspicious_processes
from .scanner import Finding
from .signatures import load_db
from .watcher import FileGuard, poll_once


@dataclass
class ProtectionState:
    file_snap: dict[str, float] = field(default_factory=dict)
    process_pids: set[int] = field(default_factory=set)
    conn_keys: set[tuple[str, str]] = field(default_factory=set)
    guard: FileGuard | None = None
    file_findings: list[Finding] = field(default_factory=list)
    new_processes: list[ProcessInfo] = field(default_factory=list)
    new_connections: list[Connection] = field(default_factory=list)
    persistence_findings: list[Finding] = field(default_factory=list)


def watch_targets(cfg: DefenderConfig, extra: list[str] | None = None) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    bases = list(extra) if extra else list(cfg.watch_paths)
    for raw in bases:
        p = str(Path(raw).expanduser())
        if p in seen:
            continue
        seen.add(p)
        if Path(p).exists():
            targets.append(p)
    return targets


def protection_cycle(
    cfg: DefenderConfig,
    state: ProtectionState | None = None,
    extra_paths: list[str] | None = None,
    on_threat=None,
    scan_persist: bool = True,
    watch_files: bool = True,
    quiet: bool = False,
) -> ProtectionState:
    """One real-time tick. Safe to call from tests; no infinite loop."""
    cfg = cfg or get_config()
    state = state or ProtectionState()
    if state.guard is None:
        from .watcher import BurstDetector
        state.guard = FileGuard(
            burst=BurstDetector(window=cfg.burst_window_seconds, threshold=int(cfg.burst_file_threshold)),
        )
    db = load_db(cfg.signatures_file)
    paths = watch_targets(cfg, extra_paths)

    if watch_files and paths:
        new_snap, findings = poll_once(
            paths, state.file_snap, cfg, guard=state.guard, on_threat=on_threat, db=db, quiet=quiet,
        )
        state.file_snap = new_snap
        state.file_findings = findings

    procs = list_processes()
    fresh_procs = new_suspicious_processes(procs, state.process_pids)
    state.process_pids = {p.pid for p in procs}
    state.new_processes = fresh_procs
    for proc in fresh_procs:
        append_event(
            DefenseEvent(
                kind="process",
                severity="suspicious",
                message="; ".join(proc.reasons[:5]) or proc.name,
                pid=proc.pid,
                details={"name": proc.name, "cmdline": proc.cmdline[:300], "exe": proc.exe},
            ),
            cfg,
        )
        if not quiet:
            print(f"[PROCESS ] pid={proc.pid} {proc.name} :: {'; '.join(proc.reasons)}")
        if on_threat:
            try:
                on_threat(proc)
            except Exception:
                pass

    conns = list_connections(cfg)
    fresh_conns = new_suspicious_connections(conns, state.conn_keys)
    state.conn_keys = {(c.local, c.remote) for c in conns}
    state.new_connections = fresh_conns
    for conn in fresh_conns:
        append_event(
            DefenseEvent(
                kind="network",
                severity="suspicious",
                message="; ".join(conn.reasons[:5]),
                details={"local": conn.local, "remote": conn.remote, "status": conn.status, "pid": conn.pid},
            ),
            cfg,
        )
        if not quiet:
            print(f"[NETWORK ] {conn.local} -> {conn.remote} :: {'; '.join(conn.reasons)}")
        if on_threat:
            try:
                on_threat(conn)
            except Exception:
                pass

    if scan_persist:
        persist = [f for f in scan_persistence(cfg, db=db) if f.verdict in ("malicious", "suspicious")]
        state.persistence_findings = persist
        for finding in persist:
            append_event(
                DefenseEvent(
                    kind="persistence",
                    severity=finding.verdict,
                    message="; ".join(finding.reasons[:5]),
                    path=finding.path,
                    details={"score": finding.score},
                ),
                cfg,
            )
            if not quiet:
                print(f"[PERSIST ] {finding.path} {finding.verdict} :: {'; '.join(finding.reasons)}")
            if on_threat:
                try:
                    on_threat(finding)
                except Exception:
                    pass
    return state


def run_protect(
    cfg: DefenderConfig | None = None,
    paths: list[str] | None = None,
    once: bool = False,
    seconds: float | None = None,
    interval: float | None = None,
    stop_event: threading.Event | None = None,
    on_threat=None,
    quiet: bool = False,
) -> ProtectionState:
    """Blocking RTP loop. `once` or `seconds` make it testable."""
    cfg = cfg or get_config()
    cfg.ensure_dirs()
    tick = float(interval if interval is not None else cfg.protect_interval_seconds or 10.0)
    if not quiet:
        print(
            "AIDefender protect: file + process + network + persistence "
            f"(interval={tick}s, auto_quarantine={cfg.auto_quarantine})"
        )
    extra = paths or None
    state = ProtectionState()
    if not once:
        from .watcher import _poll_snapshot
        roots = [Path(p) for p in watch_targets(cfg, extra)]
        state.file_snap = _poll_snapshot(roots)
        state.process_pids = {p.pid for p in list_processes()}
        state.conn_keys = {(c.local, c.remote) for c in list_connections(cfg)}
    # First cycle: `once` scans current watch contents; looping mode only diffs.
    state = protection_cycle(
        cfg, state, extra_paths=extra, on_threat=on_threat, scan_persist=True, quiet=quiet,
    )
    if once:
        return state
    deadline = time.time() + seconds if seconds is not None else None
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            if deadline is not None and time.time() >= deadline:
                break
            time.sleep(max(0.05, tick))
            state = protection_cycle(
                cfg, state, extra_paths=extra, on_threat=on_threat, scan_persist=False, quiet=quiet,
            )
    except KeyboardInterrupt:
        if not quiet:
            print("protect stopped")
        return state
    if not quiet:
        print("protect stopped")
    return state
