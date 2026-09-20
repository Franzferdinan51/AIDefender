"""Signature / malware-intel database.

Exact SHA-256 hashes, portable string rules, C2 hints, process tokens,
and family bulletins. Ships a built-in set (including the harmless EICAR
test signature) and merges live updater JSON on top.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
# Well-known SHA-256 of the EICAR test file.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

_CACHE: dict[str, tuple[float, "SignatureDB"]] = {}


@dataclass
class SignatureDB:
    hashes: dict[str, str] = field(default_factory=dict)  # sha256 -> name
    strings: dict[str, str] = field(default_factory=dict)  # lowercase substring -> name
    ips: dict[str, str] = field(default_factory=dict)  # ip -> name
    ports: dict[int, str] = field(default_factory=dict)  # port -> name
    process_names: dict[str, str] = field(default_factory=dict)
    process_cmdline: dict[str, str] = field(default_factory=dict)
    families: dict[str, dict] = field(default_factory=dict)
    info: str = ""
    updated: str = ""
    version: str = "builtin-1"

    def match_hash(self, sha256: str) -> str | None:
        return self.hashes.get(sha256.lower())

    def match_strings(self, text_lower: str) -> list[str]:
        hits: list[str] = []
        for needle, name in self.strings.items():
            if needle and needle in text_lower:
                hits.append(name)
        return hits

    def counts(self) -> dict[str, int]:
        return {
            "hashes": len(self.hashes),
            "strings": len(self.strings),
            "ips": len(self.ips),
            "ports": len(self.ports),
            "process_names": len(self.process_names),
            "process_cmdline": len(self.process_cmdline),
            "families": len(self.families),
        }


def builtin_db() -> SignatureDB:
    return SignatureDB(
        hashes={
            EICAR_SHA256: "EICAR-Test-File (harmless test signature)",
        },
        strings={
            "eicar-standard-antivirus-test-file": "EICAR-Test-File (harmless test signature)",
            "mimikatz": "HackTool:Mimikatz-String",
            "frombase64string": "Suspicious:PowerShell-FromBase64String",
            "powershell -enc": "Suspicious:PowerShell-Encoded",
            "powershell -encodedcommand": "Suspicious:PowerShell-Encoded",
            "invoke-mimikatz": "HackTool:Invoke-Mimikatz",
            "ransom": "Suspicious:Ransom-Keyword",
            "all your files have been encrypted": "Ransom:Generic-Note",
            "your files have been encrypted": "Ransom:Generic-Note",
            "eval($_post": "WebShell:PHP-Eval-POST",
            "eval(base64_decode": "WebShell:PHP-Eval-Base64",
            "wannadecryptor": "Ransom:WannaCry-String",
            "redline stealer": "Stealer:RedLine-String",
            "lumma stealer": "Stealer:Lumma-String",
            "asyncrat": "RemoteAccess:AsyncRAT-String",
            "nanocore": "RemoteAccess:NanoCore-String",
            "agenttesla": "Stealer:AgentTesla-String",
        },
        families={
            "eicar": {"severity": "malicious", "kind": "test", "info": "Industry test signature, not malware."},
            "mimikatz": {"severity": "malicious", "kind": "credential-dumper"},
            "ransomware": {"severity": "malicious", "kind": "ransom"},
        },
        info="Built-in malware signatures. Merge the live community feed with `aidefender update`.",
        version="builtin-2",
    )


def invalidate_cache(signatures_file: str | None = None) -> None:
    if signatures_file:
        _CACHE.pop(str(Path(signatures_file)), None)
        _CACHE.pop(str(Path(signatures_file).resolve()) if Path(signatures_file).exists() else "", None)
    else:
        _CACHE.clear()


def merge_feed(db: SignatureDB, data: dict) -> dict[str, int]:
    """Merge a feed dict into db. Returns newly-added key counts."""
    added = {
        "hashes": 0,
        "strings": 0,
        "ips": 0,
        "ports": 0,
        "process_names": 0,
        "process_cmdline": 0,
        "families": 0,
    }
    if not isinstance(data, dict):
        return added
    for digest, name in (data.get("hashes") or {}).items():
        key = str(digest).lower()
        if key not in db.hashes:
            added["hashes"] += 1
        db.hashes[key] = str(name)
    for needle, name in (data.get("strings") or {}).items():
        key = str(needle).lower()
        if key not in db.strings:
            added["strings"] += 1
        db.strings[key] = str(name)
    network = data.get("network") or {}
    for ip, name in (network.get("ips") or {}).items():
        key = str(ip).strip()
        if key not in db.ips:
            added["ips"] += 1
        db.ips[key] = str(name)
    for port, name in (network.get("ports") or {}).items():
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        if p not in db.ports:
            added["ports"] += 1
        db.ports[p] = str(name)
    procs = data.get("processes") or {}
    for needle, name in (procs.get("names") or {}).items():
        key = str(needle).lower()
        if key not in db.process_names:
            added["process_names"] += 1
        db.process_names[key] = str(name)
    for needle, name in (procs.get("cmdline") or {}).items():
        key = str(needle).lower()
        if key not in db.process_cmdline:
            added["process_cmdline"] += 1
        db.process_cmdline[key] = str(name)
    for fam, meta in (data.get("families") or {}).items():
        key = str(fam).lower()
        if key not in db.families:
            added["families"] += 1
        db.families[key] = meta if isinstance(meta, dict) else {"info": str(meta)}
    if data.get("version"):
        db.version = str(data["version"])
    if data.get("info"):
        db.info = str(data["info"])
    if data.get("updated"):
        db.updated = str(data["updated"])
    return added


def load_db(signatures_file: str | None = None) -> SignatureDB:
    db = builtin_db()
    if not signatures_file:
        return db
    path = Path(signatures_file)
    key = str(path)
    if not path.exists():
        return db
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return db
    cached = _CACHE.get(key)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return db
    try:
        merge_feed(db, data)
    except AttributeError:
        return db
    _CACHE[key] = (mtime, db)
    return db


def save_db(db: SignatureDB, signatures_file: str) -> Path:
    path = Path(signatures_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": db.version,
        "updated": db.updated,
        "info": db.info,
        "hashes": db.hashes,
        "strings": db.strings,
        "network": {
            "ips": db.ips,
            "ports": {str(k): v for k, v in db.ports.items()},
        },
        "processes": {
            "names": db.process_names,
            "cmdline": db.process_cmdline,
        },
        "families": db.families,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    invalidate_cache(str(path))
    return path
