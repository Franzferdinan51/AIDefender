"""Signature updater: fetch merged JSON from a URL or local file."""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from .config import DefenderConfig, get_config
from .signatures import SignatureDB, load_db, save_db


def fetch_json(source: str, timeout: int = 20) -> dict:
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"User-Agent": "AIDefender/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    return json.loads(Path(source).read_text(encoding="utf-8"))


def update_signatures(source: str | None = None, cfg: DefenderConfig | None = None) -> SignatureDB:
    cfg = cfg or get_config()
    src = source or cfg.signatures_url
    data = fetch_json(src)
    db = load_db(cfg.signatures_file)
    hashes = data.get("hashes", {}) or {}
    strings = data.get("strings", {}) or {}
    added_h = added_s = 0
    for digest, name in hashes.items():
        key = str(digest).lower()
        if key not in db.hashes:
            added_h += 1
        db.hashes[key] = str(name)
    for needle, name in strings.items():
        key = str(needle).lower()
        if key not in db.strings:
            added_s += 1
        db.strings[key] = str(name)
    if data.get("version"):
        db.version = str(data["version"])
    save_db(db, cfg.signatures_file)
    print(f"signatures updated to {db.version}: +{added_h} hashes, +{added_s} strings -> {cfg.signatures_file}")
    return db
