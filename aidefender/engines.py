"""Report which protection engines are live (AVG-style multi-engine status)."""
from __future__ import annotations

from .clamd import clamd_available, clamd_endpoint
from .config import DefenderConfig, get_config
from .onaccess import fanotify_supported, on_access_mode
from .service import default_unit_path, service_installed
from .signatures import load_db
from .blocklist import load_blocked
from .updater import load_intel_state


def engine_status(cfg: DefenderConfig | None = None, local_ai_probe=None) -> dict:
    cfg = cfg or get_config()
    db = load_db(cfg.signatures_file)
    fan_ok, fan_reason = fanotify_supported()
    clam_ok, clam_reason = clamd_available(cfg) if getattr(cfg, "clamd_enable", False) else (False, "clamd_enable is false")
    try:
        import psutil  # type: ignore  # noqa: F401
        psutil_ok = True
    except ImportError:
        psutil_ok = False
    try:
        import watchdog  # type: ignore  # noqa: F401
        watchdog_ok = True
    except ImportError:
        watchdog_ok = False
    if local_ai_probe is not None:
        ai_st = local_ai_probe(cfg)
    else:
        from .aibackends import probe_backend
        ai_st = probe_backend(
            "local",
            getattr(cfg, "local_ai_base_url", "") or "",
            timeout=1.2,
        )
    ai_payload = ai_st.to_dict() if hasattr(ai_st, "to_dict") else dict(ai_st)
    return {
        "on_access": on_access_mode(),
        "fanotify": {"available": fan_ok, "detail": fan_reason},
        "watchdog": watchdog_ok,
        "psutil": psutil_ok,
        "clamd": {
            "enabled": bool(getattr(cfg, "clamd_enable", False)),
            "available": clam_ok,
            "endpoint": clamd_endpoint(cfg) if getattr(cfg, "clamd_enable", False) else "",
            "detail": clam_reason,
        },
        "service": {
            "installed": service_installed(),
            "unit": str(default_unit_path()),
        },
        "definitions": {
            "version": db.version,
            "counts": db.counts(),
            "info": db.info,
            **load_intel_state(cfg),
        },
        "local_ai": {
            "base_url": getattr(cfg, "local_ai_base_url", "") or "",
            "model": getattr(cfg, "local_ai_model", "") or "",
            "reachable": bool(ai_payload.get("reachable")),
            "models": list(ai_payload.get("models") or [])[:12],
            "error": ai_payload.get("error") or "",
            "latency_ms": ai_payload.get("latency_ms") or 0,
        },
        "intrusion": {
            "auto_block": bool(getattr(cfg, "intrusion_auto_block", True)),
            "firewall_block": bool(getattr(cfg, "intrusion_firewall_block", False)),
            "geo": bool(getattr(cfg, "intrusion_geo", True)),
            "blocked_ips": len(load_blocked(cfg)),
        },
        "kernel_minifilter": False,
        "note": (
            "Always-on user-mode protection with optional fanotify (Linux) and clamd. "
            "A signed kernel minifilter / Apple system extension is not shipped."
        ),
    }
