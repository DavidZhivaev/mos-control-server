import ipaddress
from fastapi import Request

from core.config import settings


PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def _is_trusted_proxy(ip_str: str) -> bool:
    if not settings.TRUST_PROXY:
        return False
    
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    
    trusted_ips = settings.TRUSTED_PROXY_IPS.split(",")
    
    for trusted in trusted_ips:
        trusted = trusted.strip()
        try:
            if "/" in trusted:
                network = ipaddress.ip_network(trusted, strict=False)
                if ip in network:
                    return True
            else:
                if ip == ipaddress.ip_address(trusted):
                    return True
        except ValueError:
            continue
    
    return False


def _parse_forwarded_for(forwarded_header: str) -> list[str]:
    if not forwarded_header:
        return []

    ips = []
    for part in forwarded_header.split(","):
        ip = part.strip()
        if ":" in ip and not ip.startswith("["):
            ip = ip.split(":")[0]
        elif ip.startswith("["):
            ip = ip.strip("[]")
            if "]" in ip:
                ip = ip.split("]")[0] + "]"
        if ip:
            ips.append(ip)
    return ips


def _get_rightmost_trusted_ip(
    forwarded_ips: list[str],
    remote_addr: str | None
) -> str | None:
    for ip in reversed(forwarded_ips):
        if not _is_private_ip(ip):
            return ip
    return remote_addr


def client_ip(request: Request) -> str:
    remote_addr = request.client.host if request.client else ""

    if not settings.TRUST_PROXY:
        return remote_addr

    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return remote_addr

    forwarded_ips = _parse_forwarded_for(forwarded)
    if not forwarded_ips:
        return remote_addr

    if _is_trusted_proxy(remote_addr):
        client = _get_rightmost_trusted_ip(forwarded_ips, remote_addr)
        return client or remote_addr

    return remote_addr


def client_ip_list(request: Request) -> list[str]:
    remote_addr = request.client.host if request.client else ""
    forwarded = request.headers.get("x-forwarded-for", "")
    forwarded_ips = _parse_forwarded_for(forwarded)

    if forwarded_ips:
        return forwarded_ips + [remote_addr] if remote_addr else forwarded_ips
    return [remote_addr] if remote_addr else []
