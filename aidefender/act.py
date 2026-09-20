"""Local remediation actions for operators and agents.

Stop a process on this machine only. Refuses pid 1, negative pids, and
the defender's own PID. No remote exploitation.
"""
from __future__ import annotations

import os
import signal


def stop_process(pid: int, expected_name: str = "") -> dict:
    pid = int(pid)
    if pid <= 1:
        return {"ok": False, "error": "refusing to signal pid <= 1"}
    if pid == os.getpid():
        return {"ok": False, "error": "refusing to stop the running aidefender process"}
    if expected_name:
        # Best-effort name check via /proc or ps is platform-specific; skip if unavailable.
        try:
            comm = PathProcName(pid)
        except Exception:
            comm = ""
        if comm and expected_name.lower() not in comm.lower():
            return {"ok": False, "error": f"pid {pid} name {comm!r} does not match {expected_name!r}"}
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return {"ok": False, "error": f"pid {pid} not found"}
    except PermissionError as exc:
        return {"ok": False, "error": str(exc)}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "pid": pid, "signal": "SIGTERM"}


def PathProcName(pid: int) -> str:
    proc = f"/proc/{pid}/comm"
    try:
        with open(proc, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""
