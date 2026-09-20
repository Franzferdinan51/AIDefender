"""Command line interface for the full defense suite."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .config import get_config, save_config
from .daemon import run_daemon
from .network import list_connections
from .processes import list_processes
from .quarantine import delete_quarantine, list_quarantine, quarantine_file, restore_quarantine
from .scanner import scan_path
from .signatures import load_db
from .updater import update_signatures
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

    p = sub.add_parser("monitor", help="real-time folder protection (Ctrl+C to stop)")
    p.add_argument("paths", nargs="*", help="folders to watch (defaults to config watch_paths)")

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

    p = sub.add_parser("update", help="update signature database")
    p.add_argument("--source", default=None, help="URL or local JSON file (defaults to config signatures_url)")

    p = sub.add_parser("daemon", help="run periodic background defense loop")
    p.add_argument("--interval", type=int, default=3600, help="seconds between sweeps")
    p.add_argument("--once", action="store_true", help="single sweep then exit")
    p.add_argument("--auto-quarantine", action="store_true", help="quarantine malicious hits during sweeps")

    p = sub.add_parser("status", help="show config and signature info")
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

    if args.command == "monitor":
        monitor(args.paths or None, cfg=cfg)
        return 0

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
        update_signatures(args.source, cfg)
        return 0

    if args.command == "daemon":
        if args.auto_quarantine:
            cfg.auto_quarantine = True
        run_daemon(cfg, interval=args.interval, once=args.once)
        return 0

    if args.command == "status":
        db = load_db(cfg.signatures_file)
        info = {
            "version": __version__,
            "base_dir": cfg.base_dir,
            "quarantine_dir": cfg.quarantine_dir,
            "signatures_file": cfg.signatures_file,
            "signatures_version": db.version,
            "signatures": {"hashes": len(db.hashes), "strings": len(db.strings)},
            "watch_paths": cfg.watch_paths,
            "auto_quarantine": cfg.auto_quarantine,
        }
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            for key, value in info.items():
                print(f"{key}: {value}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
