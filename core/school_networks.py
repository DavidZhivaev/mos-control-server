import ipaddress
import json
from functools import lru_cache

from core.config import settings


@lru_cache
def _parsed_networks() -> tuple[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, int], ...]:
    try:
        data = json.loads(settings.SCHOOL_NETWORKS_JSON)
    except json.JSONDecodeError:
        return ()
    out: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, int]] = []
    for row in data:
        cidr = row.get("cidr")
        building = row.get("building")
        if cidr is None or building is None:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            out.append((net, int(building)))
        except ValueError:
            continue
    return tuple(out)


def client_ip_as_address(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not ip:
        return None
    raw = ip.strip()
    if raw.startswith("["):
        raw = raw.strip("[]")
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def building_for_school_ip(ip: str) -> int | None:
    addr = client_ip_as_address(ip)
    if addr is None:
        return None
    for net, building in _parsed_networks():
        if addr in net:
            return building
    return None


def is_school_ip(ip: str) -> bool:
    return building_for_school_ip(ip) is not None
