"""Command line interface for the full defense suite."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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
    p.add_argument("--ai", action="store_true", help="opt-in local-first AI triage after the offline scan")

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

    sub.add_parser("ui", help="open the Electron desktop UI")

    p = sub.add_parser("intrusion", help="detect inbound access, brute-force, and port scans with IP/geo intel")
    p.add_argument("--no-geo", action="store_true", help="skip reverse-DNS and geo lookup")
    p.add_argument("--no-block", action="store_true", help="detect only; do not block")
    p.add_argument("--firewall", action="store_true", help="also drop caught public IPs in the OS firewall (opt-in)")
    p.add_argument("--deep-logs", action="store_true", help="also query macOS unified logs (slower)")
    p.add_argument("--connections-json", default=None, help="evaluate a JSON list of {local,remote,status} snapshots (DDOS/IDS)")

    p = sub.add_parser("allow", help="allowlist IPs/CIDRs/ports/processes/paths/hashes the user trusts")
    asub = p.add_subparsers(dest="alcommand", required=True)
    asub.add_parser("list", help="show allowlist")
    ad = asub.add_parser("add", help="add an allowlist entry")
    ad.add_argument("--ip", default=None)
    ad.add_argument("--cidr", default=None)
    ad.add_argument("--port", default=None)
    ad.add_argument("--process", default=None)
    ad.add_argument("--path", default=None)
    ad.add_argument("--hash", dest="file_hash", default=None)
    ad.add_argument("--note", default="")
    ar = asub.add_parser("remove", help="remove an allowlist entry")
    ar.add_argument("--ip", default=None)
    ar.add_argument("--cidr", default=None)
    ar.add_argument("--port", default=None)
    ar.add_argument("--process", default=None)
    ar.add_argument("--path", default=None)
    ar.add_argument("--hash", dest="file_hash", default=None)

    p = sub.add_parser("block", help="list/add/remove locally blocked attacker IPs")
    bsub = p.add_subparsers(dest="blcommand", required=True)
    bsub.add_parser("list", help="show blocked IPs")
    ba = bsub.add_parser("add", help="block an IP")
    ba.add_argument("--ip", required=True)
    ba.add_argument("--reason", default="operator block")
    ba.add_argument("--firewall", action="store_true", help="also drop in OS firewall (opt-in)")
    br = bsub.add_parser("remove", help="unblock an IP")
    br.add_argument("--ip", required=True)
    br.add_argument("--firewall", action="store_true")

    p = sub.add_parser("diag", help="netstat-class diagnostics: connections, listeners, ARP, routes, tools")
    p.add_argument("topic", nargs="?", default="all", help="all|connections|listen|arp|routes|tools")

    p = sub.add_parser("capture", help="bounded receive-only packet capture (tcpdump/tshark if installed)")
    p.add_argument("--seconds", type=float, default=3.0)
    p.add_argument("--count", type=int, default=40)
    p.add_argument("--filter", default="", help="BPF filter, e.g. 'port 22'")

    p = sub.add_parser("inspect", help="inspect an IP (geo, allow/block, live sockets)")
    p.add_argument("kind", choices=["ip"])
    p.add_argument("value")
    p.add_argument("--no-geo", action="store_true")

    p = sub.add_parser("act", help="take a local defensive action")
    actsub = p.add_subparsers(dest="actcommand", required=True)
    sp = actsub.add_parser("stop-process", help="SIGTERM a local process (not pid 1 or self)")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--name", default="", help="optional name check")

    p = sub.add_parser("ai", help="local AI backends: detect LM Studio/Ollama, select, test")
    aisub = p.add_subparsers(dest="aicommand", required=True)
    aisub.add_parser("status", help="probe LM Studio / Ollama / configured URL for models")
    au = aisub.add_parser("use", help="point local AI at lmstudio|ollama preset or a base URL")
    au.add_argument("target", help="lmstudio, ollama, or http(s) base URL")
    au.add_argument("--model", default="", help="model id to use")
    at = aisub.add_parser("test", help="chat roundtrip against the configured local backend")
    at.add_argument("--model", default="", help="override model id for this test")

    p = sub.add_parser("config", help="view or change settings (secrets stay in env vars)")
    csub = p.add_subparsers(dest="cfgcommand", required=True)
    cg = csub.add_parser("get", help="show settings (redacted)")
    cg.add_argument("key", nargs="?", default=None, help="single setting key (default: all settable)")
    cs = csub.add_parser("set", help="change one setting")
    cs.add_argument("key", help="setting key from `config get`")
    cs.add_argument("value", help="new value (bool/int/float/comma lists)")

    sub.add_parser("tools", help="JSON catalog of defensive tools for agents")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = get_config(args.config_dir)
    cfg.ensure_dirs()
    save_config(cfg)

    if args.command == "scan":
        db = load_db(cfg.signatures_file)
        findings = scan_path(args.target, db=db, cfg=cfg)
        if args.ai:
            from .ai import attach_ai_to_findings
            attach_ai_to_findings(findings, cfg=cfg)
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
            from .ai import merge_ai_into_finding
            merge_ai_into_finding(f, result)
            payload = (f.analysis or result.to_dict())
            payload["path"] = f.path
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
        threats += len(getattr(state, "intrusion_alerts", None) or [])
        if args.json:
            print(json.dumps({
                "files": [f.to_dict() for f in state.file_findings],
                "processes": [p.to_dict() for p in state.new_processes],
                "connections": [c.to_dict() for c in state.new_connections],
                "persistence": [f.to_dict() for f in state.persistence_findings],
                "intrusions": [a.to_dict() for a in (state.intrusion_alerts or [])],
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
        procs = list_processes(cfg=cfg)
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
        conns = list_connections(cfg)
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

    if args.command == "ui":
        from .desktop import launch_ui
        return launch_ui()

    if args.command == "intrusion":
        from .geoip import format_location
        from .intrusion import run_intrusion_check
        cfg.intrusion_geo = not args.no_geo
        if args.no_block:
            cfg.intrusion_auto_block = False
        if args.firewall:
            cfg.intrusion_firewall_block = True
        extra_conns = None
        collect = True
        if args.connections_json:
            from .network import Connection
            raw = json.loads(Path(args.connections_json).read_text(encoding="utf-8"))
            extra_conns = [
                Connection(
                    local=str(row.get("local", "")),
                    remote=str(row.get("remote", "")),
                    status=str(row.get("status", "")),
                    pid=row.get("pid"),
                )
                for row in raw
            ]
            collect = False
        _state, alerts = run_intrusion_check(
            cfg,
            connections=extra_conns,
            enrich=not args.no_geo,
            apply_blocks=not args.no_block,
            collect=collect,
            unified_log=args.deep_logs,
        )
        if args.json:
            print(json.dumps([a.to_dict() for a in alerts], indent=2))
        else:
            for a in alerts:
                loc = format_location(a.geo) if a.geo else ""
                print(f"[{a.severity.upper():10}] {a.category} {a.ip} {loc} action={a.action}")
                for ev in a.evidence:
                    print(f"             - {ev}")
            print(f"\nintrusions={len(alerts)}")
        return 1 if any(a.severity == "malicious" for a in alerts) else 0

    if args.command == "allow":
        from .allowlist import add_entry, load_allowlist, remove_entry
        if args.alcommand == "list":
            data = load_allowlist(cfg)
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                for kind, entries in data.items():
                    print(f"{kind}: {len(entries)}")
                    for key, meta in entries.items():
                        print(f"  {key}  {meta.get('note', '')}")
            return 0
        pairs = [
            ("ip", args.ip), ("cidr", args.cidr), ("port", args.port),
            ("process", args.process), ("path", args.path), ("hash", args.file_hash),
        ]
        chosen = [(k, v) for k, v in pairs if v]
        if not chosen:
            print("specify --ip/--cidr/--port/--process/--path/--hash", file=sys.stderr)
            return 2
        if args.alcommand == "add":
            out = {}
            for kind, value in chosen:
                out[kind] = add_entry(cfg, kind, value, note=getattr(args, "note", "") or "")
            if args.json:
                print(json.dumps(out, indent=2))
            else:
                print("allowlisted", ", ".join(f"{k}={v}" for k, v in chosen))
            return 0
        if args.alcommand == "remove":
            removed = {kind: remove_entry(cfg, kind, value) for kind, value in chosen}
            if args.json:
                print(json.dumps(removed, indent=2))
            else:
                print("removed", removed)
            return 0

    if args.command == "block":
        from .blocklist import block_ip, load_blocked, unblock_ip
        if args.blcommand == "list":
            data = load_blocked(cfg)
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                for ip, meta in data.items():
                    print(f"{ip}  {meta.get('reason', '')}")
                print(f"\nblocked={len(data)}")
            return 0
        if args.blcommand == "add":
            entry = block_ip(cfg, args.ip, args.reason, firewall=bool(args.firewall))
            print(json.dumps(entry, indent=2) if args.json else f"blocked {args.ip}")
            return 0
        if args.blcommand == "remove":
            entry = unblock_ip(cfg, args.ip, firewall=bool(args.firewall))
            print(json.dumps(entry, indent=2) if args.json else f"unblocked {args.ip} removed={entry['removed']}")
            return 0

    if args.command == "diag":
        from .diag import snapshot
        snap = snapshot(cfg)
        topic = (args.topic or "all").lower()
        if topic == "tools":
            payload = snap["tools"]
        elif topic in ("connections", "listen", "arp", "routes"):
            key = "listeners" if topic == "listen" else topic
            payload = snap.get(key) if key != "connections" else snap["connections"]
        else:
            payload = snap
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(json.dumps(payload, indent=2))
        return 0

    if args.command == "capture":
        from .capture import run_capture
        result = run_capture(seconds=args.seconds, count=args.count, bpf=args.filter, dest_dir=cfg.base_dir)
        print(json.dumps(result, indent=2) if args.json else json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1

    if args.command == "inspect":
        from .diag import inspect_ip
        fetch = (lambda ip, timeout=3: {"status": "success"}) if args.no_geo else None
        payload = inspect_ip(args.value, cfg, fetch=fetch, do_dns=not args.no_geo)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "act":
        if args.actcommand == "stop-process":
            from .act import stop_process
            result = stop_process(args.pid, expected_name=args.name or "")
            print(json.dumps(result, indent=2) if args.json else result)
            return 0 if result.get("ok") else 1

    if args.command == "tools":
        from .catalog import tool_catalog
        payload = tool_catalog()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for tool in payload:
                print(f"{tool['name']:16} {'ACT' if tool['action'] else 'GET'}  {tool['purpose']}")
        return 0

    if args.command == "ai":
        from .aibackends import detect_backends, test_roundtrip, use_backend
        if args.aicommand == "status":
            backends = detect_backends(cfg)
            payload = {
                "active": {"url": cfg.local_ai_base_url, "model": cfg.local_ai_model},
                "backends": [b.to_dict() for b in backends],
            }
            if args.json:
                print(json.dumps(payload, indent=2))
            else:
                print(f"active: {cfg.local_ai_base_url} model={cfg.local_ai_model or '(default)'}")
                for b in backends:
                    state = "UP " if b.reachable else "DOWN"
                    models = ", ".join(b.models[:6]) or "(no models listed)"
                    print(f"[{state}] {b.name:8} {b.base_url} {b.latency_ms}ms :: {models}")
                    if b.error:
                        print(f"         error: {b.error}")
                if not any(b.reachable for b in backends):
                    print("hint: start LM Studio server (`lms server start`) or Ollama (`ollama serve`),")
                    print("      then `aidefender ai use lmstudio --model <id>` (see `ai status` models).")
            return 0
        if args.aicommand == "use":
            try:
                use_backend(cfg, args.target, args.model)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            save_config(cfg)
            if args.json:
                print(json.dumps({"url": cfg.local_ai_base_url, "model": cfg.local_ai_model}, indent=2))
            else:
                print(f"local AI -> {cfg.local_ai_base_url} model={cfg.local_ai_model or '(default)'}")
            return 0
        if args.aicommand == "test":
            model = args.model or cfg.local_ai_model
            result = test_roundtrip(cfg.local_ai_base_url, model, cfg.local_ai_api_key,
                                    timeout=cfg.ai_timeout_seconds + 7.0)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                if result["ok"]:
                    print(f"OK {cfg.local_ai_base_url} model={model or '(default)'} {result['latency_ms']}ms")
                else:
                    print(f"FAILED: {result['error']}")
            return 0 if result["ok"] else 1

    if args.command == "config":
        from .config import SETTABLE, coerce_value, redacted_dict
        if args.cfgcommand == "get":
            data = redacted_dict(cfg)
            if args.key:
                if args.key not in SETTABLE:
                    print(f"unknown setting: {args.key}", file=sys.stderr)
                    print(f"settable: {', '.join(sorted(SETTABLE))}", file=sys.stderr)
                    return 2
                value = data[args.key]
                if args.json:
                    print(json.dumps({args.key: value}, indent=2))
                else:
                    print(f"{args.key} = {value!r}")
                return 0
            view = {key: data[key] for key in sorted(SETTABLE)}
            view["_api_key_hint"] = data["_api_key_hint"]
            if args.json:
                print(json.dumps(view, indent=2))
            else:
                for key in sorted(SETTABLE):
                    print(f"{key} = {data[key]!r}")
                print(f"\n{data['_api_key_hint']}")
            return 0
        if args.cfgcommand == "set":
            try:
                value = coerce_value(args.key, args.value)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            setattr(cfg, args.key, value)
            from .config import validate_config
            warnings = validate_config(cfg)
            save_config(cfg)
            if args.json:
                print(json.dumps({"key": args.key, "value": getattr(cfg, args.key), "warnings": warnings}, indent=2))
            else:
                print(f"{args.key} = {getattr(cfg, args.key)!r}")
                for warning in warnings:
                    print(f"warning: {warning}")
            return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
