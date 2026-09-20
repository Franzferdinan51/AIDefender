"""Signature database: exact hashes + portable string/behavior rules.

Ships with a small built-in set (including the harmless EICAR test
signature) and merges user/updater-provided JSON on top.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
# Well-known SHA-256 of the EICAR test file.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@dataclass
class SignatureDB:
    hashes: dict[str, str] = field(default_factory=dict)  # sha256 -> name
    strings: dict[str, str] = field(default_factory=dict)  # lowercase substring -> name
    version: str = "builtin-1"

    def match_hash(self, sha256: str) -> str | None:
        return self.hashes.get(sha256.lower())

    def match_strings(self, text_lower: str) -> list[str]:
        hits: list[str] = []
        for needle, name in self.strings.items():
            if needle and needle in text_lower:
                hits.append(name)
        return hits


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
        },
        version="builtin-1",
    )


def load_db(signatures_file: str | None = None) -> SignatureDB:
    db = builtin_db()
    if not signatures_file:
        return db
    path = Path(signatures_file)
    if not path.exists():
        return db
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return db
    try:
        hashes = data.get("hashes", {}) or {}
        strings = data.get("strings", {}) or {}
        for digest, name in hashes.items():
            db.hashes[str(digest).lower()] = str(name)
        for needle, name in strings.items():
            db.strings[str(needle).lower()] = str(name)
        if data.get("version"):
            db.version = str(data["version"])
    except AttributeError:
        return db
    return db


def save_db(db: SignatureDB, signatures_file: str) -> Path:
    path = Path(signatures_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": db.version, "hashes": db.hashes, "strings": db.strings}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
