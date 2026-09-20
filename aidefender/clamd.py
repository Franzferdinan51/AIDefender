"""Optional local ClamAV daemon (clamd) engine.

Talks the clamd INSTREAM protocol over a UNIX socket or TCP localhost.
Never sends samples to the cloud. Disabled unless configured or a well-known
local socket exists and ``clamd_enable`` is true.
"""
from __future__ import annotations

import socket
from pathlib import Path

from .config import DefenderConfig

DEFAULT_SOCKETS = (
    "/var/run/clamav/clamd.ctl",
    "/run/clamav/clamd.ctl",
    "/opt/homebrew/var/run/clamav/clamd.sock",
    "/usr/local/var/run/clamav/clamd.sock",
)


def clamd_endpoint(cfg: DefenderConfig | None = None) -> str:
    if cfg and (cfg.clamd_socket or "").strip():
        return cfg.clamd_socket.strip()
    for path in DEFAULT_SOCKETS:
        if Path(path).exists():
            return path
    return ""


def clamd_available(cfg: DefenderConfig | None = None) -> tuple[bool, str]:
    endpoint = clamd_endpoint(cfg)
    if not endpoint:
        return False, "no local clamd socket"
    try:
        sock = _connect(endpoint, timeout=1.0)
    except OSError as exc:
        return False, f"clamd unreachable: {exc}"
    try:
        sock.sendall(b"PING\n")
        reply = sock.recv(64).decode("utf-8", errors="replace").strip()
    except OSError as exc:
        return False, f"clamd ping failed: {exc}"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if reply.upper().startswith("PONG"):
        return True, endpoint
    return False, f"clamd unexpected ping: {reply[:40]}"


def _connect(endpoint: str, timeout: float) -> socket.socket:
    if endpoint.startswith("/") or endpoint.startswith("\\"):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(endpoint)
        return sock
    host, _, port_s = endpoint.rpartition(":")
    host = host.strip() or "127.0.0.1"
    port = int(port_s or "3310")
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def scan_bytes_clamd(
    data: bytes,
    endpoint: str,
    timeout: float = 8.0,
    max_bytes: int = 10 * 1024 * 1024,
) -> str | None:
    """Return a ClamAV signature name if FOUND, None if OK/unavailable."""
    blob = data[:max_bytes]
    try:
        sock = _connect(endpoint, timeout=timeout)
    except OSError:
        return None
    try:
        sock.sendall(b"zINSTREAM\0")
        offset = 0
        chunk_size = 2048
        while offset < len(blob):
            chunk = blob[offset : offset + chunk_size]
            sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
            offset += len(chunk)
        sock.sendall((0).to_bytes(4, "big"))
        reply = b""
        while True:
            piece = sock.recv(4096)
            if not piece:
                break
            reply += piece
            if b"\0" in reply or b"\n" in reply:
                break
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    text = reply.decode("utf-8", errors="replace").strip().strip("\0")
    # e.g. "stream: Eicar-Test-Signature FOUND"
    if "FOUND" in text.upper():
        label = text.split(":", 1)[-1].replace("FOUND", "").strip()
        return label or "ClamAV-Detection"
    return None


def scan_path_clamd(path: str | Path, cfg: DefenderConfig) -> str | None:
    if not getattr(cfg, "clamd_enable", False):
        return None
    endpoint = clamd_endpoint(cfg)
    if not endpoint:
        return None
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    return scan_bytes_clamd(data, endpoint, timeout=float(getattr(cfg, "clamd_timeout_seconds", 8) or 8))
