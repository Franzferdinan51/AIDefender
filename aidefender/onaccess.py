"""OS-level on-access hooks.

Linux: fanotify in *notification* mode (CLOSE_WRITE/MODIFY) — the same
class of API ClamAV's clamonacc uses. Permission-blocking FAN_OPEN_PERM
is not used here because a slow Python reply would freeze the machine.

macOS/Windows: report capability and fall back to watchdog/polling
(FSEvents / ReadDirectoryChanges). Signed kernel minifilters and Apple
Endpoint Security system extensions are out of scope without vendor
notarization.
"""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

# fanotify_event_metadata on 64-bit Linux (24 bytes).
_FAN_META = struct.Struct("IBBHQii")
FAN_CLOEXEC = 0x00000001
FAN_CLASS_NOTIF = 0x00000000
FAN_NONBLOCK = 0x00000002
FAN_MARK_ADD = 0x00000001
FAN_MARK_FILESYSTEM = 0x00000100
FAN_MARK_MOUNT = 0x00000010
FAN_MODIFY = 0x00000002
FAN_CLOSE_WRITE = 0x00000008
FAN_ONDIR = 0x40000000
FAN_EVENT_ON_CHILD = 0x08000000


def parse_fanotify_metadata(blob: bytes) -> dict | None:
    if len(blob) < _FAN_META.size:
        return None
    event_len, vers, _res, meta_len, mask, fd, pid = _FAN_META.unpack_from(blob, 0)
    return {
        "event_len": event_len,
        "vers": vers,
        "metadata_len": meta_len,
        "mask": mask,
        "fd": fd,
        "pid": pid,
    }


def fanotify_supported() -> tuple[bool, str]:
    if not sys.platform.startswith("linux"):
        return False, f"fanotify is Linux-only; this OS uses {sys.platform} file notifications"
    try:
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        if not getattr(libc, "fanotify_init", None):
            return False, "libc has no fanotify_init"
    except (OSError, AttributeError) as exc:
        return False, str(exc)
    return True, "fanotify notification mode"


def on_access_mode() -> str:
    ok, _ = fanotify_supported()
    if ok:
        return "fanotify"
    if sys.platform == "darwin":
        return "fsevents-or-polling"
    if sys.platform.startswith("win"):
        return "readdirectorychanges-or-polling"
    return "polling"


def run_fanotify(watch: list[str], cfg, handler, stop_event=None, max_events: int | None = None) -> int:
    """Block until stop_event. ``handler(path)`` is invoked for each file event."""
    import ctypes
    import ctypes.util
    import select
    import time

    ok, reason = fanotify_supported()
    if not ok:
        raise RuntimeError(reason)
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    libc.fanotify_init.restype = ctypes.c_int
    libc.fanotify_mark.argtypes = [
        ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p,
    ]
    libc.fanotify_mark.restype = ctypes.c_int

    fd = libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, os.O_RDONLY)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "fanotify_init failed")
    mask = FAN_CLOSE_WRITE | FAN_MODIFY | FAN_EVENT_ON_CHILD | FAN_ONDIR
    marked = 0
    for raw in watch:
        path = str(Path(raw).expanduser())
        if not Path(path).exists():
            continue
        rc = libc.fanotify_mark(fd, FAN_MARK_ADD, mask, -100, path.encode("utf-8"))
        if rc == 0:
            marked += 1
    if marked == 0:
        os.close(fd)
        raise OSError("fanotify_mark failed for all watch paths (need privileges?)")

    seen = 0
    try:
        while True:
            if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                break
            if max_events is not None and seen >= max_events:
                break
            ready, _, _ = select.select([fd], [], [], 0.25)
            if not ready:
                continue
            try:
                buf = os.read(fd, 4096)
            except BlockingIOError:
                continue
            offset = 0
            while offset + _FAN_META.size <= len(buf):
                meta = parse_fanotify_metadata(buf[offset:])
                if not meta:
                    break
                event_len = meta["event_len"] or _FAN_META.size
                ev_fd = meta["fd"]
                offset += event_len
                if ev_fd < 0:
                    continue
                try:
                    path = os.readlink(f"/proc/self/fd/{ev_fd}")
                except OSError:
                    path = ""
                try:
                    os.close(ev_fd)
                except OSError:
                    pass
                if path:
                    handler(path)
                    seen += 1
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return seen


def start_file_protection(watch: list[str], cfg, stop_event=None, **monitor_kwargs):
    """Prefer fanotify; fall back to the portable folder monitor."""
    from .watcher import FileGuard, monitor

    ok, _reason = fanotify_supported()
    if ok:
        guard = FileGuard()

        def handler(path: str) -> None:
            guard.handle(path, cfg)

        try:
            run_fanotify(watch, cfg, handler, stop_event=stop_event)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"fanotify unavailable ({exc}); using folder monitor")
    monitor(watch=watch, cfg=cfg, stop_event=stop_event, **monitor_kwargs)
