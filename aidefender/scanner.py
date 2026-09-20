"""File and directory scanner: hashes + signatures + heuristics."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from .config import DefenderConfig, get_config
from .heuristics import HeuristicResult, analyze_file
from .signatures import SignatureDB, load_db

CHUNK = 1024 * 1024


@dataclass
class Finding:
    path: str
    verdict: str  # clean | suspicious | malicious | error | skipped
    reasons: list[str] = field(default_factory=list)
    sha256: str = ""
    score: int = 0

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "sha256": self.sha256,
            "score": self.score,
        }


def sha256_of(path: Path, max_bytes: int | None = None) -> str:
    digest = hashlib.sha256()
    read = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            if max_bytes is not None and read + len(chunk) > max_bytes:
                chunk = chunk[: max_bytes - read]
                digest.update(chunk)
                break
            digest.update(chunk)
            read += len(chunk)
    return digest.hexdigest()


def _read_text_sample(path: Path, limit: int = 2 * 1024 * 1024) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", errors="ignore").lower()
    except OSError:
        return ""


def scan_file(
    path: str | os.PathLike,
    db: SignatureDB | None = None,
    cfg: DefenderConfig | None = None,
) -> Finding:
    cfg = cfg or get_config()
    db = db or load_db(cfg.signatures_file)
    p = Path(path)

    if not p.exists():
        return Finding(path=str(p), verdict="error", reasons=["path does not exist"])
    if p.is_symlink():
        return Finding(path=str(p), verdict="skipped", reasons=["symlink skipped"])
    if not p.is_file():
        return Finding(path=str(p), verdict="error", reasons=["not a regular file"])

    try:
        size = p.stat().st_size
    except OSError as exc:
        return Finding(path=str(p), verdict="error", reasons=[f"stat failed: {exc}"])

    if size > cfg.max_scan_bytes:
        # Still hash (bounded) but skip full heuristic body.
        try:
            digest = sha256_of(p, max_bytes=cfg.max_scan_bytes)
        except OSError as exc:
            return Finding(path=str(p), verdict="error", reasons=[f"read failed: {exc}"])
        hit = db.match_hash(digest)
        if hit:
            return Finding(path=str(p), verdict="malicious", reasons=[f"signature: {hit}"], sha256=digest, score=100)
        return Finding(
            path=str(p), verdict="skipped",
            reasons=[f"larger than max_scan_bytes ({size} > {cfg.max_scan_bytes}); hash-checked only"],
            sha256=digest,
        )

    try:
        digest = sha256_of(p)
    except OSError as exc:
        return Finding(path=str(p), verdict="error", reasons=[f"read failed: {exc}"])

    sig_hit = db.match_hash(digest)
    if sig_hit:
        return Finding(path=str(p), verdict="malicious", reasons=[f"signature: {sig_hit}"], sha256=digest, score=100)

    text = _read_text_sample(p)
    str_hits = db.match_strings(text) if text else []
    if str_hits:
        return Finding(
            path=str(p), verdict="malicious",
            reasons=[f"signature: {name}" for name in str_hits],
            sha256=digest, score=100,
        )

    heur: HeuristicResult = analyze_file(p)
    reasons = list(heur.reasons)
    if heur.score >= cfg.heuristic_malicious:
        verdict = "malicious"
    elif heur.score >= cfg.heuristic_suspicious:
        verdict = "suspicious"
    else:
        verdict = "clean"
        if not reasons:
            reasons = ["no signatures or heuristic signals"]
    return Finding(path=str(p), verdict=verdict, reasons=reasons, sha256=digest, score=heur.score)


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Skip common noisy dirs but keep it simple and predictable.
        dirnames[:] = [d for d in dirnames if d not in {"__pycache__", ".git", ".venv", "node_modules"}]
        for name in filenames:
            yield Path(dirpath) / name


def scan_path(
    target: str | os.PathLike,
    db: SignatureDB | None = None,
    cfg: DefenderConfig | None = None,
) -> list[Finding]:
    cfg = cfg or get_config()
    db = db or load_db(cfg.signatures_file)
    p = Path(target)
    if p.is_file() or p.is_symlink():
        return [scan_file(p, db=db, cfg=cfg)]
    if not p.is_dir():
        return [Finding(path=str(p), verdict="error", reasons=["path does not exist"])]
    findings: list[Finding] = []
    for file_path in iter_files(p):
        findings.append(scan_file(file_path, db=db, cfg=cfg))
    return findings
