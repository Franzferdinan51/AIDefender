"""Explainable AI-style heuristics: features + weighted risk score (0-100).

No heavy ML dependency. Scores are deterministic, versioned, and every
point is traceable to a named reason so users can audit decisions.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .binary import analyze_binary

MODEL_VERSION = "aidefender-heuristics-3"

# Magic prefixes.
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}
ZIP_MAGIC = b"PK\x03\x04"

EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"}
SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".py", ".ps1", ".vbs", ".js", ".cmd", ".bat", ".hta"}
SCRIPT_SHEBANGS = (b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env", b"#!/bin/zsh")
OLE_MAGIC = b"\xd0\xcf\x11\xe0"

SUSPICIOUS_TOKENS = [
    "powershell", "frombase64string", "-encodedcommand", "-enc ",
    "mimikatz", "invoke-expression", "iex(", "downloadstring",
    "bitstransfer", "regsvr32", "rundll32", "schtasks",
    "curl", "wget", "| sh", "| bash", "chmod +x",
    "all your files have been encrypted", "decrypt instructions",
    "keylogger", "reverse shell", "/dev/tcp/", "ncat", "netcat",
    # Droppers / LOLBins
    "invoke-webrequest", "net.webclient", "downloadfile(",
    "certutil -decode", "bitsadmin /transfer", "start-bitstransfer",
    "wscript.shell", "mshta http", "regsvr32 /s /n /u /i:",
    "powershell -nop", "powershell -w hidden",
    # Family / post-ex
    "cobalt strike", "cobaltstrike", "meterpreter", "sekurlsa",
    "invoke-mimikatz", "lazagne", "vssadmin delete shadows",
    "bcdedit /set", "wevtutil cl", "disable-windowsdefender",
    "add-mppreference", "set-mppreference",
    # Script / web droppers
    "eval(atob", "fromcharcode", "document.write(unescape",
    "osascript -e",
    # Persistence droppers (path-like tokens inside scripts, not plist filenames)
    "currentversion\\run", "library/launchagents", "library/launchdaemons",
    # Macro autoexec
    "auto_open", "document_open", "workbook_open",
]

DOUBLE_EXT_RE = re.compile(r"\.(doc|pdf|txt|jpg|png|xls|csv)\.(exe|bat|cmd|ps1|vbs|js|scr|com)$", re.IGNORECASE)


@dataclass
class HeuristicResult:
    score: int
    reasons: list[str] = field(default_factory=list)
    features: dict = field(default_factory=dict)
    model_version: str = MODEL_VERSION


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _magic_kind(head: bytes) -> str:
    if head.startswith(PE_MAGIC):
        return "pe"
    if head.startswith(ELF_MAGIC):
        return "elf"
    if head[:4] in MACHO_MAGICS:
        return "macho"
    if head.startswith(ZIP_MAGIC):
        return "zip"
    if head.startswith(OLE_MAGIC):
        return "ole"
    if head.startswith(b"#!"):
        return "script"
    return "unknown"


def analyze_bytes(name: str, size: int, sample: bytes, head: bytes | None = None) -> HeuristicResult:
    """Score a named byte buffer. Used for files and in-memory archive members."""
    reasons: list[str] = []
    features: dict = {}
    score = 0
    head = head if head is not None else sample[:8192]

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(f"+{points}: {reason}")

    features["size"] = size
    suffix = Path(name).suffix.lower()
    features["extension"] = suffix
    features["name"] = name

    # Double-extension trick: invoice.pdf.exe
    if DOUBLE_EXT_RE.search(name):
        add(30, f"double extension masquerade ({name})")
        features["double_ext"] = True

    # Hidden + executable-ish on unix/mac.
    if Path(name).name.startswith(".") and suffix in EXECUTABLE_EXTS:
        add(10, "hidden executable-style file")

    kind = _magic_kind(head)
    features["magic"] = kind

    # Extension/content mismatch.
    if kind in ("pe", "elf", "macho") and suffix in {".txt", ".pdf", ".doc", ".docx", ".jpg", ".png", ".csv"}:
        add(35, f"executable {kind.upper()} content with document extension {suffix}")
        features["ext_mismatch"] = True
    if kind == "pe" and suffix not in EXECUTABLE_EXTS and suffix not in ("", ".bin", ".dat"):
        add(10, f"PE binary with unusual extension {suffix or '(none)'}")

    # Scripts that fetch + execute.
    lowered = sample.lower()
    if kind == "script" or suffix in SCRIPT_EXTS:
        if b"curl" in lowered and (b"| sh" in lowered or b"| bash" in lowered):
            add(30, "shell script pipes remote download into shell (curl|sh)")
        elif b"wget" in lowered and (b"| sh" in lowered or b"| bash" in lowered):
            add(30, "shell script pipes remote download into shell (wget|sh)")
        if head.startswith(SCRIPT_SHEBANGS) and b"base64 -d" in lowered:
            add(10, "script decodes base64 payload")
        if lowered.count(b"\\x") >= 20:
            add(10, "heavy hex-escaped payload in script")
            features["hex_escaped"] = True

    if kind == "ole":
        add(5, "OLE compound document (legacy Office); inspect macros")
        features["ole"] = True

    # Entropy: packed/encrypted payloads.
    if sample:
        ent = shannon_entropy(sample[:65536])
        features["entropy"] = round(ent, 3)
        if len(sample) > 1024 and ent >= 7.6:
            add(20, f"very high entropy ({ent:.2f}) suggests packing/encryption")
        elif len(sample) > 1024 and ent >= 7.2:
            add(10, f"high entropy ({ent:.2f})")

    # Suspicious token hits (cap contribution so one file can't explode).
    try:
        text = sample.decode("utf-8", errors="ignore").lower()
    except Exception:
        text = ""
    hits = [tok for tok in SUSPICIOUS_TOKENS if tok in text]
    if hits:
        features["tokens"] = hits[:10]
        add(min(35, 10 + 5 * len(hits)), f"suspicious keywords: {', '.join(hits[:5])}")

    # Tiny dropper + huge blob heuristics.
    if kind in ("pe", "elf", "macho") and 0 < size < 16 * 1024 and hits:
        add(10, "tiny executable with malicious keywords (possible dropper)")
    delta, bin_reasons, bin_feat = analyze_binary(sample, kind)
    if delta:
        score += delta
        reasons.extend(bin_reasons)
        features.update(bin_feat)
    if size > 100 * 1024 * 1024:
        features["huge"] = True  # not scored; scanner may skip body

    return HeuristicResult(score=min(100, score), reasons=reasons, features=features)


def analyze_file(path: str | os.PathLike, max_bytes: int = 2 * 1024 * 1024) -> HeuristicResult:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        return HeuristicResult(score=0, reasons=[f"unreadable: {exc}"], features={"error": str(exc)})

    try:
        with open(p, "rb") as fh:
            head = fh.read(8192)
            fh.seek(0)
            sample = fh.read(max_bytes)
    except OSError as exc:
        return HeuristicResult(
            score=0,
            reasons=[f"read error: {exc}"],
            features={"size": size, "name": p.name, "error": str(exc)},
        )

    return analyze_bytes(p.name, size, sample, head=head)
