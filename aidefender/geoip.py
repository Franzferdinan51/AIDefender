"""IP enrichment: reverse DNS + optional public geo lookup (ip-api.com).

Detection never depends on geo succeeding. Lookups are injectable so tests
use a stub and production failures become empty fields, not crashes.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Callable

from . import __version__
from .ipaddr import is_public_ip, normalize_ip

GeoFetch = Callable[[str, float], dict]


def reverse_dns(ip: str, timeout: float = 1.5) -> str:
    ip = normalize_ip(ip)
    prev = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _alias, _addrs = socket.gethostbyaddr(ip)
        return name or ""
    except (OSError, socket.herror, socket.gaierror, socket.timeout, ValueError):
        return ""
    finally:
        socket.setdefaulttimeout(prev)


def fetch_ip_api(ip: str, timeout: float = 3.0) -> dict:
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon,query,reverse"
    req = urllib.request.Request(
        url, headers={"User-Agent": f"AIDefender/{__version__}"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def enrich_ip(
    ip: str,
    timeout: float = 3.0,
    fetch: GeoFetch | None = None,
    do_dns: bool = True,
) -> dict:
    ip = normalize_ip(ip)
    info = {
        "ip": ip,
        "rdns": "",
        "country": "",
        "region": "",
        "city": "",
        "isp": "",
        "org": "",
        "asn": "",
        "lat": None,
        "lon": None,
        "source": "",
        "error": "",
    }
    if not ip:
        info["error"] = "empty ip"
        return info
    if do_dns:
        info["rdns"] = reverse_dns(ip, timeout=min(timeout, 1.5))
    if not is_public_ip(ip):
        info["source"] = "private"
        return info
    getter = fetch or fetch_ip_api
    try:
        payload = getter(ip, timeout)
    except (OSError, ValueError, urllib.error.URLError, TimeoutError) as exc:
        info["error"] = str(exc)
        return info
    if not isinstance(payload, dict):
        info["error"] = "geo payload not an object"
        return info
    if str(payload.get("status", "success")).lower() == "fail":
        info["error"] = str(payload.get("message") or "geo lookup failed")
        return info
    info["country"] = str(payload.get("country") or "")
    info["region"] = str(payload.get("regionName") or payload.get("region") or "")
    info["city"] = str(payload.get("city") or "")
    info["isp"] = str(payload.get("isp") or "")
    info["org"] = str(payload.get("org") or "")
    info["asn"] = str(payload.get("as") or payload.get("asn") or "")
    info["lat"] = payload.get("lat")
    info["lon"] = payload.get("lon")
    if payload.get("reverse") and not info["rdns"]:
        info["rdns"] = str(payload.get("reverse"))
    info["source"] = "ip-api"
    return info


def format_location(info: dict) -> str:
    parts = [p for p in (info.get("city"), info.get("region"), info.get("country")) if p]
    loc = ", ".join(parts) or "unknown location"
    isp = info.get("isp") or info.get("org") or ""
    rdns = info.get("rdns") or ""
    extra = []
    if isp:
        extra.append(isp)
    if rdns:
        extra.append(rdns)
    if extra:
        return f"{loc} ({'; '.join(extra)})"
    return loc
