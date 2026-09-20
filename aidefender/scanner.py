"""File and directory scanner: hashes + signatures + heuristics + archives."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from .archives import ArchiveLimits, archive_kind, walk_archive
from .config import DefenderConfig, get_config
from .heuristics import HeuristicResult, analyze_bytes, analyze_file
from .signatures import SignatureDB, load_db

CHUNK = 1024 * 1024


_VERDICT_RANK = {"clean": 0, "skipped": 1, "error": 2, "suspicious": 3, "malicious": 4}


@dataclass
class Finding:
    path: str
    verdict: str  # clean | suspicious | malicious | error | skipped
    reasons: list[str] = field(default_factory=list)
    sha256: str = ""
    score: int = 0
    features: dict = field(default_factory=dict)
    signature_hit: bool = False
    nested: bool = False
    analysis: dict | None = None

    def to_dict(self) -> dict:
        payload = {
            "path": self.path,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "sha256": self.sha256,
            "score": self.score,
            "features": self.features,
            "signature_hit": self.signature_hit,
            "nested": self.nested,
        }
        if self.analysis is not None:
            payload["analysis"] = self.analysis
        return payload


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
        finding = Finding(
            path=str(p),
            verdict="malicious",
            reasons=[f"signature: {sig_hit}"],
            sha256=digest,
            score=100,
            signature_hit=True,
        )
        _attach_archive_hits(finding, p, db, cfg)
        return finding

    text = _read_text_sample(p)
    str_hits = db.match_strings(text) if text else []
    if str_hits:
        finding = Finding(
            path=str(p),
            verdict="malicious",
            reasons=[f"signature: {name}" for name in str_hits],
            sha256=digest,
            score=100,
            signature_hit=True,
        )
        _attach_archive_hits(finding, p, db, cfg)
        return finding

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
    finding = Finding(
        path=str(p),
        verdict=verdict,
        reasons=reasons,
        sha256=digest,
        score=heur.score,
        features=dict(heur.features),
    )
    _attach_archive_hits(finding, p, db, cfg)
    return _enrich_clamd(finding, p, cfg)


def _enrich_clamd(finding: Finding, path: Path, cfg: DefenderConfig) -> Finding:
    if finding.verdict == "malicious":
        return finding
    if not getattr(cfg, "clamd_enable", False):
        return finding
    try:
        from .clamd import scan_path_clamd
        hit = scan_path_clamd(path, cfg)
    except Exception:
        return finding
    if hit:
        finding.verdict = "malicious"
        finding.score = max(finding.score, 100)
        finding.reasons.append(f"clamd: {hit}")
    return finding


def scan_bytes(
    virtual_path: str,
    data: bytes,
    db: SignatureDB,
    cfg: DefenderConfig,
) -> Finding:
    digest = hashlib.sha256(data).hexdigest()
    sig_hit = db.match_hash(digest)
    if sig_hit:
        return Finding(
            path=virtual_path,
            verdict="malicious",
            reasons=[f"signature: {sig_hit}"],
            sha256=digest,
            score=100,
            signature_hit=True,
            nested=True,
        )
    try:
        text = data.decode("utf-8", errors="ignore").lower()
    except Exception:
        text = ""
    str_hits = db.match_strings(text) if text else []
    if str_hits:
        return Finding(
            path=virtual_path,
            verdict="malicious",
            reasons=[f"signature: {name}" for name in str_hits],
            sha256=digest,
            score=100,
            signature_hit=True,
            nested=True,
        )
    name = virtual_path.split("!")[-1]
    heur = analyze_bytes(name, len(data), data)
    if heur.score >= cfg.heuristic_malicious:
        verdict = "malicious"
    elif heur.score >= cfg.heuristic_suspicious:
        verdict = "suspicious"
    else:
        verdict = "clean"
        if not heur.reasons:
            heur.reasons = ["no signatures or heuristic signals"]
    return Finding(
        path=virtual_path,
        verdict=verdict,
        reasons=list(heur.reasons),
        sha256=digest,
        score=heur.score,
        features=dict(heur.features),
        nested=True,
    )


def archive_limits_from_config(cfg: DefenderConfig) -> ArchiveLimits:
    return ArchiveLimits(
        max_depth=int(cfg.archive_max_depth),
        max_members=int(cfg.archive_max_members),
        max_member_bytes=int(cfg.archive_max_member_bytes),
        max_total_bytes=int(cfg.archive_max_total_bytes),
    )


def inspect_archive_members(
    path: Path,
    db: SignatureDB,
    cfg: DefenderConfig,
) -> tuple[list[Finding], list[str]]:
    """Return (non-clean nested findings, skip notes). Never extracts to disk."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read(min(path.stat().st_size, cfg.max_scan_bytes))
    except OSError as exc:
        return [], [f"archive unreadable: {exc}"]
    if not archive_kind(blob):
        return [], []
    nested: list[Finding] = []
    notes: list[str] = []
    for member in walk_archive(blob, str(path), archive_limits_from_config(cfg)):
        if member.skipped:
            notes.append(f"archive skipped {member.path}: {member.skipped}")
            continue
        if member.data is None:
            continue
        finding = scan_bytes(member.path, member.data, db, cfg)
        if finding.verdict in ("malicious", "suspicious"):
            nested.append(finding)
    return nested, notes


def _attach_archive_hits(finding: Finding, path: Path, db: SignatureDB, cfg: DefenderConfig) -> None:
    nested, notes = inspect_archive_members(path, db, cfg)
    finding.reasons.extend(notes)
    for child in nested:
        finding.reasons.append(f"nested {child.verdict}: {child.path} ({'; '.join(child.reasons[:3])})")
        finding.score = max(finding.score, child.score)
        if child.signature_hit:
            finding.signature_hit = True
        if _VERDICT_RANK.get(child.verdict, 0) > _VERDICT_RANK.get(finding.verdict, 0):
            finding.verdict = child.verdict
    if nested and finding.verdict == "clean":
        finding.verdict = max(nested, key=lambda f: _VERDICT_RANK.get(f.verdict, 0)).verdict


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
        parent = scan_file(p, db=db, cfg=cfg)
        extra, _ = inspect_archive_members(p, db, cfg) if p.is_file() else ([], [])
        return [parent] + extra
    if not p.is_dir():
        return [Finding(path=str(p), verdict="error", reasons=["path does not exist"])]
    findings: list[Finding] = []
    for file_path in iter_files(p):
        parent = scan_file(file_path, db=db, cfg=cfg)
        findings.append(parent)
        extra, _ = inspect_archive_members(file_path, db, cfg)
        findings.extend(extra)
    return findings
