"""IP classification helpers for intrusion detection."""
from __future__ import annotations

import ipaddress
import re

_IP_RE = re.compile(
    r"(?:(?:\d{1,3}\.){3}\d{1,3})|(?:\[[0-9a-fA-F:]+\]|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})"
)


def normalize_ip(raw: str) -> str:
    text = (raw or "").strip().strip("[]")
    if "%" in text:
        text = text.split("%", 1)[0]
    return text


def parse_ip(raw: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(normalize_ip(raw))
    except ValueError:
        return None


_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def _is_documentation(addr: ipaddress._BaseAddress) -> bool:
    return any(addr in net for net in _DOC_NETS)


def is_non_routable(ip: str) -> bool:
    """True for LAN/loopback/link-local. TEST-NET docs IPs count as external."""
    addr = parse_ip(ip)
    if addr is None:
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return True
    if _is_documentation(addr):
        return False
    return bool(addr.is_private)


def is_public_ip(ip: str) -> bool:
    return parse_ip(ip) is not None and not is_non_routable(ip)


def extract_ips(text: str) -> list[str]:
    found: list[str] = []
    for match in _IP_RE.findall(text or ""):
        ip = normalize_ip(match)
        if parse_ip(ip) is not None:
            found.append(ip)
    return found
