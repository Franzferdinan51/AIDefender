"""Static binary analysis used by commercial AV user-mode engines.

Looks for PE/ELF/Mach-O injection APIs, packer stamps, and download
helpers in the file bytes. No full unpacker — explainable hits only.
"""
from __future__ import annotations

PE_INJECTION = (
    b"VirtualAlloc",
    b"VirtualProtect",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"NtUnmapViewOfSection",
    b"QueueUserAPC",
    b"SetWindowsHookEx",
    b"RtlCreateUserThread",
)
PE_DOWNLOAD = (
    b"URLDownloadToFile",
    b"InternetOpen",
    b"WinHttpOpen",
    b"InternetReadFile",
)
PE_PACKERS = (
    b"UPX0",
    b"UPX1",
    b"UPX!",
    b"UPX2",
    b".packed",
    b"Themida",
    b"ASPack",
    b"PECompact",
    b"MPRESS",
)
ELF_HOOKS = (
    b"ptrace",
    b"mprotect",
    b"dlopen",
    b"memfd_create",
    b"/proc/self/mem",
)


def analyze_binary(sample: bytes, kind: str) -> tuple[int, list[str], dict]:
    """Return (score_delta, reasons, extra_features)."""
    if not sample or kind not in ("pe", "elf", "macho"):
        return 0, [], {}
    reasons: list[str] = []
    features: dict = {}
    score = 0

    if kind == "pe":
        inj = [n.decode("ascii") for n in PE_INJECTION if n in sample]
        if inj:
            features["pe_injection_apis"] = inj[:8]
            bump = min(40, 10 + 8 * len(inj))
            score += bump
            reasons.append(f"+{bump}: PE process-injection APIs: {', '.join(inj[:5])}")
        dl = [n.decode("ascii") for n in PE_DOWNLOAD if n in sample]
        if dl:
            features["pe_download_apis"] = dl
            score += 15
            reasons.append(f"+15: PE download APIs: {', '.join(dl[:4])}")
        pack = [n.decode("ascii", errors="ignore") for n in PE_PACKERS if n in sample]
        if pack:
            features["packer"] = pack
            score += 20
            reasons.append(f"+20: packer stamp: {', '.join(pack[:3])}")

    if kind == "elf":
        hooks = [n.decode("ascii", errors="ignore") for n in ELF_HOOKS if n in sample]
        if len(hooks) >= 2:
            features["elf_hooks"] = hooks
            bump = min(30, 8 * len(hooks))
            score += bump
            reasons.append(f"+{bump}: ELF runtime hooks: {', '.join(hooks[:5])}")

    if kind == "macho" and b"ptrace" in sample and b"DYLD_INSERT_LIBRARIES" in sample:
        score += 20
        reasons.append("+20: Mach-O ptrace + DYLD_INSERT_LIBRARIES (inject/hide)")
        features["macho_inject"] = True

    return score, reasons, features
