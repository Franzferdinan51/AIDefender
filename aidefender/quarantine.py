"""Quarantine: safely isolate threats with restore support."""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from .config import DefenderConfig, get_config


@dataclass
class QuarantineRecord:
    id: str
    original_path: str
    stored_path: str
    sha256: str
    verdict: str
    reasons: list[str]
    quarantined_at: float


def _qid(original: Path, sha256: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in original.name)[:60]
    return f"{stamp}_{sha256[:12]}_{safe}"


def quarantine_file(
    path: str | os.PathLike,
    finding_sha256: str = "",
    verdict: str = "malicious",
    reasons: list[str] | None = None,
    cfg: DefenderConfig | None = None,
) -> QuarantineRecord:
    cfg = cfg or get_config()
    qdir = Path(cfg.quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(str(src))
    qid = _qid(src, finding_sha256 or "unknown")
    dest = qdir / qid
    shutil.move(str(src), str(dest))
    # Remove execute bits on the quarantined copy (POSIX).
    try:
        if os.name == "posix":
            dest.chmod(0o600)
    except OSError:
        pass
    record = QuarantineRecord(
        id=qid,
        original_path=str(src),
        stored_path=str(dest),
        sha256=finding_sha256,
        verdict=verdict,
        reasons=reasons or [],
        quarantined_at=time.time(),
    )
    meta = dest.with_suffix(dest.suffix + ".json")
    # Avoid collision when file has no suffix: use .json appended.
    if dest.suffix == "":
        meta = Path(str(dest) + ".json")
    else:
        meta = Path(str(dest) + ".json")
    meta.write_text(json.dumps(record.__dict__, indent=2), encoding="utf-8")
    return record


def list_quarantine(cfg: DefenderConfig | None = None) -> list[QuarantineRecord]:
    cfg = cfg or get_config()
    qdir = Path(cfg.quarantine_dir)
    if not qdir.exists():
        return []
    records: list[QuarantineRecord] = []
    for meta in sorted(qdir.glob("*.json")):
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            records.append(QuarantineRecord(**data))
        except (OSError, ValueError, TypeError):
            continue
    return records


def restore_quarantine(qid: str, dest: str | os.PathLike | None = None, cfg: DefenderConfig | None = None) -> str:
    cfg = cfg or get_config()
    qdir = Path(cfg.quarantine_dir)
    stored = qdir / qid
    if not stored.exists():
        raise FileNotFoundError(f"quarantine id not found: {qid}")
    meta = Path(str(stored) + ".json")
    original = None
    if meta.exists():
        try:
            original = json.loads(meta.read_text(encoding="utf-8")).get("original_path")
        except (OSError, ValueError):
            original = None
    target = Path(dest) if dest else (Path(original) if original else Path.cwd() / qid)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), str(target))
    try:
        if meta.exists():
            meta.unlink()
    except OSError:
        pass
    return str(target)


def delete_quarantine(qid: str, cfg: DefenderConfig | None = None) -> None:
    cfg = cfg or get_config()
    qdir = Path(cfg.quarantine_dir)
    stored = qdir / qid
    meta = Path(str(stored) + ".json")
    for p in (stored, meta):
        try:
            if p.exists():
                p.unlink()
        except OSError:
            pass
