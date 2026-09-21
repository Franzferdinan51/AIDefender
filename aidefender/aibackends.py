"""Local AI backend discovery and connection management.

Probes OpenAI-compatible endpoints (LM Studio, Ollama, llama.cpp, custom)
for reachability and loaded models, and persists the operator's choice to
config. All network access is injectable so tests never bind sockets.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Callable

from .ai import _chat_complete, stdlib_post
from .config import DefenderConfig, get_config

# Well-known local runtimes. LM Studio serves OpenAI-compatible HTTP on
# :1234/v1; Ollama serves OpenAI-compat on :11434/v1 (plus native /api/tags).
KNOWN_LOCALS: tuple[tuple[str, str], ...] = (
    ("lmstudio", "http://127.0.0.1:1234/v1"),
    ("ollama", "http://127.0.0.1:11434/v1"),
)

JsonGetter = Callable[[str, float], dict]


@dataclass
class BackendStatus:
    name: str
    base_url: str
    reachable: bool = False
    models: list[str] = field(default_factory=list)
    error: str = ""
    latency_ms: int = 0
    source: str = "probe"  # probe | lms | config

    def to_dict(self) -> dict:
        return asdict(self)


def models_url(base_url: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith("/models"):
        return base
    return base + "/models"


def stdlib_get_json(url: str, timeout: float = 3.0) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        text = resp.read().decode(charset, errors="replace")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("model list endpoint returned non-object JSON")
    return data


def parse_model_ids(payload: dict) -> list[str]:
    """Accept OpenAI-style {data:[{id}]} plus common variants."""
    ids: list[str] = []
    data = payload.get("data")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("id"):
                ids.append(str(item["id"]))
            elif isinstance(item, str) and item.strip():
                ids.append(item.strip())
    # Ollama native /api/tags shape, tolerated if ever probed.
    models = payload.get("models")
    if isinstance(models, list):
        for item in models:
            if isinstance(item, dict) and item.get("name"):
                ids.append(str(item["name"]))
    seen: set[str] = set()
    out: list[str] = []
    for ident in ids:
        if ident not in seen:
            seen.add(ident)
            out.append(ident)
    return out


def probe_backend(
    name: str,
    base_url: str,
    timeout: float = 3.0,
    getter: JsonGetter | None = None,
) -> BackendStatus:
    url = models_url(base_url)
    status = BackendStatus(name=name, base_url=(base_url or "").strip())
    if not url:
        status.error = "empty base url"
        return status
    get = getter or stdlib_get_json
    started = time.monotonic()
    try:
        payload = get(url, timeout)
    except Exception as exc:  # noqa: BLE001 — probe must never raise
        status.error = str(exc)[:300]
        return status
    status.latency_ms = int((time.monotonic() - started) * 1000)
    try:
        status.models = parse_model_ids(payload)
    except Exception as exc:  # noqa: BLE001
        status.error = f"unparsable model list: {exc}"
        return status
    status.reachable = True
    return status


def lms_loaded_models(timeout: float = 8.0) -> tuple[list[str], str]:
    """Models LM Studio has loaded (`lms ps`). Returns (models, error)."""
    lms = shutil.which("lms")
    if not lms:
        return [], "lms CLI not installed"
    try:
        res = subprocess.run([lms, "ps"], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], str(exc)[:200]
    text = (res.stdout or "").strip()
    if res.returncode != 0:
        return [], (res.stderr or text or f"lms ps exited {res.returncode}")[:200]
    models: list[str] = []
    for line in text.splitlines():
        line = line.strip().strip("|").strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith(("model", "loaded", "id ", "no models", "you have", "there are")):
            continue
        if set(line) <= set("-+= "):
            continue
        token = line.split()[0].strip(",")
        if "/" in token or "." in token or "-" in token or len(token) > 2:
            models.append(token)
    return models, ""


def detect_backends(
    cfg: DefenderConfig | None = None,
    timeout: float = 3.0,
    getter: JsonGetter | None = None,
    include_lms: bool = True,
) -> list[BackendStatus]:
    """Probe known locals plus the configured URL. Never raises."""
    cfg = cfg or get_config()
    targets: list[tuple[str, str]] = list(KNOWN_LOCALS)
    custom = (cfg.local_ai_base_url or "").strip()
    if custom and all(custom.rstrip("/") != url for _, url in targets):
        targets.append(("custom", custom))
    results = [probe_backend(name, url, timeout=timeout, getter=getter) for name, url in targets]
    if include_lms:
        try:
            loaded, err = lms_loaded_models()
        except Exception:  # noqa: BLE001
            loaded, err = [], "lms probe failed"
        for status in results:
            if status.name == "lmstudio" and loaded:
                merged = list(status.models)
                for model in loaded:
                    if model not in merged:
                        merged.append(model)
                status.models = merged
                status.source = "probe+lms"
                if not status.reachable:
                    status.error = (status.error + "; " if status.error else "") + (
                        "HTTP unreachable but lms reports loaded models — start the LM Studio server"
                    )
            elif status.name == "lmstudio" and err and not status.reachable and err != "lms CLI not installed":
                status.error = (status.error + "; " if status.error else "") + f"lms: {err}"
    # Mark which entry the current config points at.
    for status in results:
        if custom and status.base_url.rstrip("/") == custom.rstrip("/"):
            status.source = status.source + "+active" if status.source != "probe" else "active"
    return results


def use_backend(
    cfg: DefenderConfig,
    url_or_preset: str,
    model: str = "",
) -> DefenderConfig:
    """Point local AI at a preset (lmstudio|ollama) or explicit base URL."""
    key = (url_or_preset or "").strip().lower()
    presets = {name: url for name, url in KNOWN_LOCALS}
    if key in presets:
        cfg.local_ai_base_url = presets[key]
        if model:
            cfg.local_ai_model = model
        elif key == "lmstudio" and cfg.local_ai_model in ("llama3.2", ""):
            # LM Studio serves whatever is loaded; keep any explicit model.
            pass
    elif url_or_preset and url_or_preset.strip():
        cfg.local_ai_base_url = url_or_preset.strip().rstrip("/")
        if model:
            cfg.local_ai_model = model
    else:
        raise ValueError("need a preset (lmstudio|ollama) or a base URL")
    return cfg


def test_roundtrip(
    base_url: str,
    model: str,
    api_key: str = "",
    timeout: float = 15.0,
    poster=None,
) -> dict:
    """Minimal chat roundtrip proving the backend answers. Never raises."""
    started = time.monotonic()
    try:
        content = _chat_complete(
            base_url, api_key, model or "aidefender",
            {"ping": "reply with {}"},
            timeout, poster or stdlib_post,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:400], "latency_ms": int((time.monotonic() - started) * 1000)}
    return {
        "ok": True,
        "latency_ms": int((time.monotonic() - started) * 1000),
        "reply_preview": (content or "")[:200],
    }
