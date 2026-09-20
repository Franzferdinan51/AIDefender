"""Nested zip/tar inspection with zip-bomb guards.

Members are scanned in memory. Nothing is extracted to disk. Depth,
member count, per-member size, and total decompressed size are all
hard-capped so a bomb cannot hang the scan.
"""
from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass
from typing import Iterator

ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"


@dataclass
class ArchiveLimits:
    max_depth: int = 3
    max_members: int = 256
    max_member_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024


@dataclass
class ArchiveMember:
    path: str
    data: bytes | None = None
    skipped: str = ""


@dataclass
class _Counters:
    members: int = 0
    total: int = 0
    stopped: str = ""


def archive_kind(data: bytes) -> str | None:
    if not data:
        return None
    if data.startswith(ZIP_MAGIC) or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "zip"
    if data.startswith(GZIP_MAGIC):
        return "tar"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def walk_archive(data: bytes, prefix: str, limits: ArchiveLimits, depth: int = 1) -> list[ArchiveMember]:
    """Walk nested zip/tar bytes. ``depth`` is 1 for the first inner layer."""
    counters = _Counters()
    return list(_walk(data, prefix, limits, depth, counters))


def _walk(
    data: bytes,
    prefix: str,
    limits: ArchiveLimits,
    depth: int,
    counters: _Counters,
) -> Iterator[ArchiveMember]:
    if counters.stopped:
        return
    if depth > limits.max_depth:
        yield ArchiveMember(path=prefix, skipped=f"archive depth limit ({limits.max_depth})")
        return
    kind = archive_kind(data)
    if kind == "zip":
        yield from _walk_zip(data, prefix, limits, depth, counters)
    elif kind == "tar":
        yield from _walk_tar(data, prefix, limits, depth, counters)


def _budget_ok(info_size: int, path: str, limits: ArchiveLimits, counters: _Counters) -> ArchiveMember | None:
    counters.members += 1
    if counters.members > limits.max_members:
        counters.stopped = "archive member count limit"
        return ArchiveMember(path=path, skipped=f"archive member count limit ({limits.max_members})")
    if info_size > limits.max_member_bytes:
        return ArchiveMember(
            path=path,
            skipped=f"member uncompressed size {info_size} exceeds {limits.max_member_bytes}",
        )
    if counters.total + info_size > limits.max_total_bytes:
        counters.stopped = "archive decompressed size limit"
        return ArchiveMember(
            path=path,
            skipped=f"archive decompressed size limit ({limits.max_total_bytes})",
        )
    return None


def _walk_zip(
    data: bytes,
    prefix: str,
    limits: ArchiveLimits,
    depth: int,
    counters: _Counters,
) -> Iterator[ArchiveMember]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        yield ArchiveMember(path=prefix, skipped=f"invalid zip: {exc}")
        return
    with zf:
        for info in zf.infolist():
            if counters.stopped:
                yield ArchiveMember(path=prefix, skipped=counters.stopped)
                return
            if info.is_dir():
                continue
            vpath = f"{prefix}!{info.filename}"
            blocked = _budget_ok(int(info.file_size or 0), vpath, limits, counters)
            if blocked:
                yield blocked
                if counters.stopped:
                    return
                continue
            try:
                payload = zf.read(info.filename)
            except RuntimeError as exc:
                yield ArchiveMember(path=vpath, skipped=f"unreadable zip member: {exc}")
                continue
            except Exception as exc:  # noqa: BLE001 — keep scan alive
                yield ArchiveMember(path=vpath, skipped=f"unreadable zip member: {exc}")
                continue
            if len(payload) > limits.max_member_bytes:
                yield ArchiveMember(
                    path=vpath,
                    skipped=f"member read size {len(payload)} exceeds {limits.max_member_bytes}",
                )
                continue
            counters.total += len(payload)
            yield ArchiveMember(path=vpath, data=payload)
            if archive_kind(payload) and depth < limits.max_depth:
                yield from _walk(payload, vpath, limits, depth + 1, counters)
            elif archive_kind(payload) and depth >= limits.max_depth:
                yield ArchiveMember(path=vpath, skipped=f"archive depth limit ({limits.max_depth})")


def _walk_tar(
    data: bytes,
    prefix: str,
    limits: ArchiveLimits,
    depth: int,
    counters: _Counters,
) -> Iterator[ArchiveMember]:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as exc:
        yield ArchiveMember(path=prefix, skipped=f"invalid tar: {exc}")
        return
    with tf:
        for info in tf.getmembers():
            if counters.stopped:
                yield ArchiveMember(path=prefix, skipped=counters.stopped)
                return
            if not info.isfile():
                continue
            vpath = f"{prefix}!{info.name}"
            blocked = _budget_ok(int(info.size or 0), vpath, limits, counters)
            if blocked:
                yield blocked
                if counters.stopped:
                    return
                continue
            try:
                fh = tf.extractfile(info)
                if fh is None:
                    yield ArchiveMember(path=vpath, skipped="tar member not extractable")
                    continue
                payload = fh.read(limits.max_member_bytes + 1)
            except Exception as exc:  # noqa: BLE001 — keep scan alive
                yield ArchiveMember(path=vpath, skipped=f"unreadable tar member: {exc}")
                continue
            if len(payload) > limits.max_member_bytes:
                yield ArchiveMember(
                    path=vpath,
                    skipped=f"member read size exceeds {limits.max_member_bytes}",
                )
                continue
            counters.total += len(payload)
            yield ArchiveMember(path=vpath, data=payload)
            if archive_kind(payload) and depth < limits.max_depth:
                yield from _walk(payload, vpath, limits, depth + 1, counters)
            elif archive_kind(payload) and depth >= limits.max_depth:
                yield ArchiveMember(path=vpath, skipped=f"archive depth limit ({limits.max_depth})")
