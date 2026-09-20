"""Command line interface for the full defense suite."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .ai import AnalysisResult, analyze_finding
from .config import get_config, save_config
from .daemon import run_daemon
from .events import load_events
from .network import list_connections
from .processes import list_processes
from .protect import run_protect
from .quarantine import delete_quarantine, list_quarantine, quarantine_file, restore_quarantine
from .scanner import scan_path
from .signatures import load_db
from .engines import engine_status
from .memory import scan_process_images
from .service import install_service, service_installed, uninstall_service
from .updater import load_intel_state, update_signatures
from .watcher import monitor


def _print_findings(findings, as_json: bool) -> int:
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        for f in findings:
            print(f"[{f.verdict.upper():10}] {f.path} score={f.score}")
            for reason in f.reasons:
                print(f"             - {reason}")
    threats = sum(1 for f in findings if f.verdict in ("malicious", "suspicious"))
    errors = sum(1 for f in findings if f.verdict == "error")
    if not as_json:
        print(f"\nscanned={len(findings)} threats={threats} errors={errors}")
    if any(f.verdict == "malicious" for f in findings):
        return 1
    if threats:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="aidefender", description="AIDefender: AI-assisted full defense suite (macOS/Linux/Windows)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--config-dir", default=None, help="override base config directory")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="scan a file or directory")
    p.add_argument("target", help="file or directory to scan")
    p.add_argument("--quarantine", action="store_true", help="quarantine malicious hits")

    p = sub.add_parser("analyze", help="local-first AI triage of scan artifacts (no full-file upload)")
    p.add_argument("target", help="file or directory to scan then analyze")
    p.add_argument("--local-url", default=None, help="override local OpenAI-compatible base URL")
    p.add_argument("--cloud-url", default=None, help="override cloud OpenAI-compatible base URL")
    p.add_argument("--model", default=None, help="override model name for the selected backend")
    p.add_argument("--timeout", type=float, default=None, help="HTTP timeout seconds")

    p = sub.add_parser("monitor", help="real-time folder protection (Ctrl+C to stop)")
    p.add_argument("paths", nargs="*", help="folders to watch (defaults to config watch_paths)")
    p.add_argument("--auto-quarantine", action="store_true", help="quarantine malicious hits")
    p.add_argument("--poll-interval", type=float, default=1.0, help="polling interval seconds")
    p.add_argument("--seconds", type=float, default=None, help="stop after N seconds (tests/debug)")
    p.add_argument("--max-events", type=int, default=None, help="stop after N threat events")

    p = sub.add_parser("protect", help="real-time file + process + network + persistence defense")
    p.add_argument("paths", nargs="*", help="folders to watch (defaults to config watch_paths)")
    p.add_argument("--auto-quarantine", action="store_true", help="quarantine malicious hits")
    p.add_argument("--once", action="store_true", help="single protection tick then exit")
    p.add_argument("--seconds", type=float, default=None, help="stop after N seconds")
    p.add_argument("--interval", type=float, default=None, help="tick interval seconds")

    p = sub.add_parser("quarantine", help="manage quarantine")
    qsub = p.add_subparsers(dest="qcommand", required=True)
    qsub.add_parser("list", help="list quarantined items")
    r = qsub.add_parser("restore", help="restore a quarantined item")
    r.add_argument("id", help="quarantine id")
    r.add_argument("--dest", default=None, help="restore destination")
    d = qsub.add_parser("delete", help="delete a quarantined item")
    d.add_argument("id", help="quarantine id")

    sub.add_parser("processes", help="list processes and flag suspicious ones")
    sub.add_parser("network", help="list network connections and flag risky ones")

    p = sub.add_parser("update", help="update malware definitions / intel feed")
    p.add_argument("--source", default=None, help="URL or local JSON file (defaults to config signatures_url)")
    p.add_argument("--force", action="store_true", help="ignore the auto-update interval")

    p = sub.add_parser("daemon", help="run periodic background defense loop")
    p.add_argument("--interval", type=int, default=3600, help="seconds between full directory sweeps")
    p.add_argument("--once", action="store_true", help="single sweep then exit")
    p.add_argument("--auto-quarantine", action="store_true", help="quarantine malicious hits during sweeps")
    p.add_argument("--seconds", type=float, default=None, help="stop after N seconds")
    p.add_argument("--no-protect", action="store_true", help="disable real-time ticks (sweeps only)")

    p = sub.add_parser("events", help="show recent real-time defense events")
    p.add_argument("-n", type=int, default=50, help="max events to show")

    p = sub.add_parser("status", help="show config and signature info")

    sub.add_parser("engines", help="show on-access, clamd, service, and definition engines")

    p = sub.add_parser("memory", help="scan executables of running processes")
    p.add_argument("--limit", type=int, default=120, help="max images to scan")

    p = sub.add_parser("service", help="install always-on protection at login")
    ssub = p.add_subparsers(dest="scommand", required=True)
    ins = ssub.add_parser("install", help="write LaunchAgent / systemd user unit / Startup script")
    ins.add_argument("--dest", default=None, help="override unit path (tests)")
    un = ssub.add_parser("uninstall", help="remove the login service unit")
    un.add_argument("--dest", default=None, help="override unit path")
    ssub.add_parser("status", help="whether the login service unit exists")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = get_config(args.config_dir)
    cfg.ensure_dirs()
    save_config(cfg)

    if args.command == "scan":
        db = load_db(cfg.signatures_file)
        findings = scan_path(args.target, db=db, cfg=cfg)
        if args.quarantine:
            for f in findings:
                if f.verdict == "malicious":
                    try:
                        rec = quarantine_file(f.path, f.sha256, f.verdict, f.reasons, cfg)
                        print(f"quarantined {f.path} -> {rec.stored_path}")
                    except OSError as exc:
                        print(f"quarantine failed for {f.path}: {exc}", file=sys.stderr)
        return _print_findings(findings, args.json)

    if args.command == "analyze":
        if args.local_url is not None:
            cfg.local_ai_base_url = args.local_url
        if args.cloud_url is not None:
            cfg.cloud_ai_base_url = args.cloud_url
        if args.model:
            cfg.local_ai_model = args.model
            if cfg.cloud_ai_model:
                cfg.cloud_ai_model = args.model
            elif args.cloud_url is not None:
                cfg.cloud_ai_model = args.model
        if args.timeout is not None:
            cfg.ai_timeout_seconds = args.timeout
        db = load_db(cfg.signatures_file)
        findings = scan_path(args.target, db=db, cfg=cfg)
        analyses = []
        for f in findings:
            if f.nested:
                continue
            try:
                result = analyze_finding(f, cfg=cfg)
            except Exception as exc:  # noqa: BLE001 — analyze must not crash scan
                result = AnalysisResult(
                    verdict="unavailable",
                    reasons=[f"analysis failed: {exc}"],
                    backend="none",
                    error=str(exc),
                )
            payload = result.to_dict()
            payload["path"] = f.path
            f.analysis = payload
            analyses.append(payload)
            if not args.json:
                print(f"[AI {result.backend:5}] {f.path} verdict={result.verdict} confidence={result.confidence}")
                for reason in result.reasons:
                    print(f"             - {reason}")
                if result.error:
                    print(f"             error: {result.error}")
        code = _print_findings(findings, args.json)
        if any(a.get("verdict") in ("malicious", "suspicious") for a in analyses):
            return 1
        return code

    if args.command == "monitor":
        if args.auto_quarantine:
            cfg.auto_quarantine = True
        monitor(
            args.paths or None,
            cfg=cfg,
            max_seconds=args.seconds,
            max_events=args.max_events,
            poll_interval=args.poll_interval,
        )
        return 0

    if args.command == "protect":
        if args.auto_quarantine:
            cfg.auto_quarantine = True
        state = run_protect(
            cfg,
            paths=args.paths or None,
            once=args.once,
            seconds=args.seconds,
            interval=args.interval,
            quiet=args.json,
        )
        threats = sum(1 for f in state.file_findings if f.verdict in ("malicious", "suspicious"))
        threats += len(state.new_processes) + len(state.new_connections)
        threats += sum(1 for f in state.persistence_findings if f.verdict in ("malicious", "suspicious"))
        if args.json:
            print(json.dumps({
                "files": [f.to_dict() for f in state.file_findings],
                "processes": [p.to_dict() for p in state.new_processes],
                "connections": [c.to_dict() for c in state.new_connections],
                "persistence": [f.to_dict() for f in state.persistence_findings],
            }, indent=2))
        return 1 if threats else 0

    if args.command == "quarantine":
        if args.qcommand == "list":
            records = list_quarantine(cfg)
            if args.json:
                print(json.dumps([r.__dict__ for r in records], indent=2))
            else:
                for r in records:
                    print(f"{r.id} <- {r.original_path} [{r.verdict}]")
                print(f"\nquarantined={len(records)} dir={cfg.quarantine_dir}")
            return 0
        if args.qcommand == "restore":
            dest = restore_quarantine(args.id, args.dest, cfg)
            print(f"restored -> {dest}")
            return 0
        if args.qcommand == "delete":
            delete_quarantine(args.id, cfg)
            print(f"deleted {args.id}")
            return 0

    if args.command == "processes":
        procs = list_processes()
        if args.json:
            print(json.dumps([p.to_dict() for p in procs], indent=2))
        else:
            for p in procs:
                flag = "!! " if p.suspicious else "   "
                print(f"{flag}pid={p.pid:6} {p.name} {p.cmdline[:120]}")
                for reason in p.reasons:
                    print(f"         - {reason}")
            bad = sum(1 for p in procs if p.suspicious)
            print(f"\nprocesses={len(procs)} suspicious={bad}")
        return 0

    if args.command == "network":
        conns = list_connections()
        if args.json:
            print(json.dumps([c.to_dict() for c in conns], indent=2))
        else:
            for c in conns:
                flag = "!! " if c.suspicious else "   "
                print(f"{flag}{c.local} -> {c.remote} {c.status}")
                for reason in c.reasons:
                    print(f"       - {reason}")
            print(f"\nconnections={len(conns)} suspicious={sum(1 for c in conns if c.suspicious)}")
        return 0

    if args.command == "update":
        result = update_signatures(args.source, cfg, quiet=args.json)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.ok else 1

    if args.command == "daemon":
        if args.auto_quarantine:
            cfg.auto_quarantine = True
        run_daemon(
            cfg,
            interval=args.interval,
            once=args.once,
            protect=not args.no_protect,
            seconds=args.seconds,
        )
        return 0

    if args.command == "events":
        rows = load_events(cfg, limit=args.n)
        if args.json:
            print(json.dumps([e.to_dict() for e in rows], indent=2))
        else:
            for e in rows:
                print(f"{e.severity:11} {e.kind:12} {e.message}")
            print(f"\nevents={len(rows)} log={cfg.log_file}")
        return 0

    if args.command == "status":
        db = load_db(cfg.signatures_file)
        info = {
            "version": __version__,
            "base_dir": cfg.base_dir,
            "quarantine_dir": cfg.quarantine_dir,
            "signatures_file": cfg.signatures_file,
            "signatures_version": db.version,
            "signatures": db.counts(),
            "intel": {
                "info": db.info,
                "updated": db.updated,
                "url": cfg.signatures_url,
                "auto_update": cfg.auto_update_definitions,
                "interval_seconds": cfg.definition_update_interval_seconds,
                **load_intel_state(cfg),
            },
            "watch_paths": cfg.watch_paths,
            "auto_quarantine": cfg.auto_quarantine,
            "ai": {
                "local_ai_base_url": cfg.local_ai_base_url,
                "local_ai_model": cfg.local_ai_model,
                "cloud_ai_base_url": cfg.cloud_ai_base_url,
                "cloud_ai_model": cfg.cloud_ai_model,
            },
            "realtime": {
                "watch_paths": cfg.watch_paths,
                "protect_interval_seconds": cfg.protect_interval_seconds,
                "file_settle_seconds": cfg.file_settle_seconds,
                "burst_file_threshold": cfg.burst_file_threshold,
                "auto_quarantine": cfg.auto_quarantine,
            },
            "engines": engine_status(cfg),
        }
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            for key, value in info.items():
                print(f"{key}: {value}")
        return 0

    if args.command == "engines":
        payload = engine_status(cfg)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"on_access: {payload['on_access']}")
            print(f"fanotify: {payload['fanotify']}")
            print(f"clamd: {payload['clamd']}")
            print(f"service: {payload['service']}")
            print(f"definitions: {payload['definitions'].get('version')}")
            print(payload["note"])
        return 0

    if args.command == "memory":
        findings = scan_process_images(cfg, limit=args.limit)
        threats = [f for f in findings if f.verdict in ("malicious", "suspicious")]
        if args.json:
            print(json.dumps({"scanned": len(findings), "threats": [f.to_dict() for f in threats]}, indent=2))
        else:
            for f in threats:
                print(f"[{f.verdict.upper()}] {f.path} :: {'; '.join(f.reasons[:4])}")
            print(f"\nimages={len(findings)} threats={len(threats)}")
        return 1 if threats else 0

    if args.command == "service":
        if args.scommand == "install":
            path = install_service(cfg, dest=args.dest)
            print(f"installed login service -> {path}")
            print("On macOS: launchctl load this plist. On Linux: systemctl --user daemon-reload && systemctl --user enable --now aidefender.service")
            return 0
        if args.scommand == "uninstall":
            removed = uninstall_service(dest=args.dest)
            print("removed" if removed else "not installed")
            return 0
        if args.scommand == "status":
            dest = None
            installed = service_installed()
            if args.json:
                print(json.dumps({"installed": installed}, indent=2))
            else:
                print(f"installed={installed}")
            return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
