"""Live malware-definition / intel updater.

Fetches one or more JSON feeds (GitHub community file by default, extra
URLs, or a local path), merges them into the on-disk database, and leaves
the previous database untouched if a fetch fails. Long-running protect
and daemon loops call ``maybe_update`` on an interval so new hashes,
strings, C2 IPs, and family bulletins apply without a restart.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from . import __version__
from .config import DefenderConfig, get_config
from .events import DefenseEvent, append_event
from .signatures import SignatureDB, invalidate_cache, load_db, merge_feed, save_db

FetchFn = Callable[[str, int], dict]


@dataclass
class UpdateResult:
    ok: bool
    version: str = ""
    source: str = ""
    added: dict[str, int] = field(default_factory=dict)
    error: str = ""
    skipped: bool = False
    info: str = ""
    counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def fetch_json(source: str, timeout: int = 20) -> dict:
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(
            source, headers={"User-Agent": f"AIDefender/{__version__}"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    return json.loads(Path(source).read_text(encoding="utf-8"))


def intel_state_path(cfg: DefenderConfig) -> Path:
    return Path(cfg.base_dir) / "intel-state.json"


def load_intel_state(cfg: DefenderConfig) -> dict:
    path = intel_state_path(cfg)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_intel_state(cfg: DefenderConfig, state: dict) -> None:
    path = intel_state_path(cfg)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except OSError:
        return


def feed_sources(cfg: DefenderConfig, source: str | None = None) -> list[str]:
    if source:
        return [source]
    urls: list[str] = []
    primary = (cfg.signatures_url or "").strip()
    if primary:
        urls.append(primary)
    for extra in getattr(cfg, "signatures_urls", None) or []:
        item = str(extra).strip()
        if item and item not in urls:
            urls.append(item)
    return urls


def update_signatures(
    source: str | None = None,
    cfg: DefenderConfig | None = None,
    fetch: FetchFn | None = None,
    quiet: bool = False,
    timeout: int = 20,
) -> UpdateResult:
    """Fetch and merge feeds. On any source failure, keep the existing DB."""
    cfg = cfg or get_config()
    fetch = fetch or fetch_json
    sources = feed_sources(cfg, source)
    if not sources:
        return UpdateResult(ok=False, error="no definition sources configured")
    db = load_db(cfg.signatures_file)
    totals = {
        "hashes": 0,
        "strings": 0,
        "ips": 0,
        "ports": 0,
        "process_names": 0,
        "process_cmdline": 0,
        "families": 0,
    }
    used: list[str] = []
    errors: list[str] = []
    last_info = db.info
    for src in sources:
        try:
            data = fetch(src, timeout) if fetch is not fetch_json else fetch_json(src, timeout)
        except TypeError:
            # Custom fetch(source) without timeout.
            data = fetch(src)  # type: ignore[misc]
        except (OSError, ValueError, urllib.error.URLError, TimeoutError) as exc:
            errors.append(f"{src}: {exc}")
            continue
        if not isinstance(data, dict):
            errors.append(f"{src}: feed was not a JSON object")
            continue
        added = merge_feed(db, data)
        for key, n in added.items():
            totals[key] = totals.get(key, 0) + n
        used.append(src)
        if data.get("info"):
            last_info = str(data.get("info"))
    if not used:
        result = UpdateResult(
            ok=False,
            version=db.version,
            source="; ".join(sources),
            error="; ".join(errors) or "no usable feeds",
            counts=db.counts(),
        )
        save_intel_state(cfg, {
            "last_attempt": time.time(),
            "last_error": result.error,
            "version": db.version,
        })
        if not quiet:
            print(f"definition update failed: {result.error}")
        return result

    save_db(db, cfg.signatures_file)
    invalidate_cache(cfg.signatures_file)
    result = UpdateResult(
        ok=True,
        version=db.version,
        source="; ".join(used),
        added=totals,
        info=last_info,
        error="; ".join(errors),
        counts=db.counts(),
    )
    save_intel_state(cfg, {
        "last_attempt": time.time(),
        "last_success": time.time(),
        "last_error": result.error,
        "version": db.version,
        "info": last_info,
        "counts": db.counts(),
        "sources": used,
    })
    append_event(
        DefenseEvent(
            kind="intel",
            severity="info",
            message=f"definitions {db.version}: {totals}",
            details=result.to_dict(),
        ),
        cfg,
    )
    if not quiet:
        print(
            f"signatures updated to {db.version}: "
            f"+{totals.get('hashes', 0)} hashes, +{totals.get('strings', 0)} strings, "
            f"+{totals.get('ips', 0)} ips -> {cfg.signatures_file}"
        )
        if last_info:
            print(f"intel: {last_info}")
    return result


def maybe_update(
    cfg: DefenderConfig,
    force: bool = False,
    now: float | None = None,
    fetch: FetchFn | None = None,
    quiet: bool = True,
) -> UpdateResult:
    """Refresh definitions if the interval has elapsed. Never raises."""
    now = time.time() if now is None else now
    if not force and not getattr(cfg, "auto_update_definitions", True):
        return UpdateResult(ok=True, skipped=True, info="auto-update disabled")
    interval = float(getattr(cfg, "definition_update_interval_seconds", 900) or 900)
    state = load_intel_state(cfg)
    last = float(state.get("last_success") or 0)
    if not force and last and (now - last) < interval:
        return UpdateResult(
            ok=True,
            skipped=True,
            version=str(state.get("version") or ""),
            info="interval not elapsed",
        )
    try:
        return update_signatures(cfg=cfg, fetch=fetch, quiet=quiet)
    except Exception as exc:  # noqa: BLE001 — live loop must not die
        result = UpdateResult(ok=False, error=str(exc))
        save_intel_state(cfg, {
            "last_attempt": now,
            "last_error": str(exc),
            "version": str(state.get("version") or ""),
        })
        return result
