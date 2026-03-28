from datetime import datetime
from typing import Optional
from models.session import Session
from models.user import User
from tortoise.expressions import Q


async def get_user_sessions(user_id: int, active_only: bool = True) -> list[Session]:
    qs = Session.filter(user_id=user_id).order_by("-created_at")
    if active_only:
        qs = qs.filter(is_active=True)
    return await qs


async def get_session_by_id(session_id: str, user_id: Optional[int] = None) -> Optional[Session]:
    qs = Session.filter(id=session_id)
    if user_id is not None:
        qs = qs.filter(user_id=user_id)
    return await qs.first()


async def revoke_session(session_id: str, user_id: Optional[int] = None) -> bool:
    qs = Session.filter(id=session_id, is_active=True)
    if user_id is not None:
        qs = qs.filter(user_id=user_id)

    updated = await qs.update(is_active=False)
    return updated > 0


async def revoke_all_user_sessions(user_id: int, exclude_session_id: Optional[str] = None) -> int:
    qs = Session.filter(user_id=user_id, is_active=True)
    if exclude_session_id:
        qs = qs.exclude(id=exclude_session_id)

    return await qs.update(is_active=False)


async def get_all_active_sessions(
    building: Optional[int] = None,
    limit: int = 100,
    offset: int = 0
) -> tuple[list[Session], int]:
    qs = Session.filter(is_active=True).order_by("-created_at")

    if building is not None:
        qs = qs.filter(user__building=building)

    total = await qs.count()
    rows = await qs.offset(offset).limit(min(limit, 500))

    return rows, total


async def count_user_active_sessions(user_id: int) -> int:
    return await Session.filter(user_id=user_id, is_active=True).count()


async def get_active_sessions_by_building(building: int) -> list[Session]:
    return await Session.filter(is_active=True, user__building=building).order_by("-created_at")
