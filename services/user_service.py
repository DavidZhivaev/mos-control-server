from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException
from tortoise.expressions import Q

from core.role_defs import (
    ROLE_OPERATOR,
    ROLE_STUDENT,
    BUILDING_SCOPED_ROLES,
    building_scope_allows,
    role_at_least,
)
from models.user import User
from services.last_edit_display import attach_last_editor_fields
from services.user_present import present_user
from utils.sessions_extra import invalidate_all_sessions


def can_view_user_profile(viewer: User, target: User) -> bool:
    if viewer.id == target.id:
        return True
    if viewer.role == ROLE_STUDENT:
        return viewer.building == target.building
    if not building_scope_allows(viewer.role, viewer.building, target):
        return False
    return True


def apply_search_scope(qs, viewer: User):
    if viewer.role == ROLE_STUDENT:
        return qs.filter(building=viewer.building)
    if viewer.role in BUILDING_SCOPED_ROLES:
        return qs.filter(
            Q(building=viewer.building) | ~Q(role=ROLE_STUDENT)
        )
    return qs


async def search_users(
    viewer: User,
    *,
    text: str | None,
    mode: str,
    building: int | None,
    role_id: int | None,
    limit: int,
    offset: int,
) -> tuple[list[dict], int]:
    if mode == "full" and not role_at_least(viewer.role, ROLE_OPERATOR):
        raise HTTPException(
            status_code=403,
            detail="Полный поиск доступен с роли оператор и выше",
        )

    qs = User.all()
    qs = apply_search_scope(qs, viewer)

    if building is not None:
        qs = qs.filter(building=building)
    if role_id is not None:
        qs = qs.filter(role=role_id)

    if text:
        q_parts = (
            Q(first_name__icontains=text)
            | Q(last_name__icontains=text)
            | Q(login__icontains=text)
        )
        if mode == "full" and role_at_least(viewer.role, ROLE_OPERATOR):
            q_parts |= Q(contact_method__icontains=text)
        qs = qs.filter(q_parts)

    total = await qs.count()
    rows = await qs.order_by("id").offset(offset).limit(limit)
    include_system = mode == "full"
    items = [present_user(u, viewer, include_system=include_system) for u in rows]
    return items, total


async def get_user_for_viewer(viewer: User, user_id: int, *, mode: str) -> dict:
    if mode == "full" and not role_at_least(viewer.role, ROLE_OPERATOR):
        raise HTTPException(
            status_code=403,
            detail="Полная карточка доступна с роли оператор и выше",
        )
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if not can_view_user_profile(viewer, target):
        raise HTTPException(status_code=403, detail="Нет доступа к этому пользователю")

    include_system = mode == "full"
    out = present_user(target, viewer, include_system=include_system)
    if include_system:
        await attach_last_editor_fields(out, target)
    return out


async def ban_user(target: User, *, actor: User, reason: str | None) -> None:
    if target.id == actor.id:
        raise HTTPException(status_code=400, detail="Нельзя заблокировать себя")
    target.is_banned = True
    target.ban_reason = reason
    target.banned_at = datetime.utcnow()
    target.banned_by = actor
    await target.save()
    await invalidate_all_sessions(target)


async def unban_user(target: User) -> None:
    target.is_banned = False
    target.ban_reason = None
    target.banned_at = None
    target.banned_by = None
    await target.save()


async def list_banned(*, building: int | None, limit: int, offset: int):
    qs = User.filter(is_banned=True).order_by("-id")
    if building is not None:
        qs = qs.filter(building=building)
    total = await qs.count()
    rows = await qs.offset(offset).limit(limit)
    return rows, total
