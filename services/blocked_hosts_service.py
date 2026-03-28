from __future__ import annotations

from fastapi import HTTPException

from models.global_blocked_host import GlobalBlockedHost, UserHostOverride
from models.user import User


def normalize_hostname(raw: str) -> str:
    h = (raw or "").strip().lower()
    for prefix in ("https://", "http://"):
        if h.startswith(prefix):
            h = h[len(prefix) :]
    h = h.split("/")[0]
    if ":" in h:
        h = h.split(":", 1)[0]
    while h.startswith("www."):
        h = h[4:]
    if not h or len(h) > 253:
        raise HTTPException(status_code=400, detail="Некорректное имя хоста")
    return h


async def effective_blocked_hosts(user: User) -> list[str]:
    global_rows = await GlobalBlockedHost.filter(is_active=True).values_list(
        "hostname", flat=True
    )
    base = set(global_rows)
    overrides = await UserHostOverride.filter(user=user)
    allows = {o.hostname for o in overrides if o.effect == "allow"}
    denies = {o.hostname for o in overrides if o.effect == "deny"}
    effective = (base - allows) | denies
    return sorted(effective)
