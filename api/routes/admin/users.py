from fastapi import APIRouter, Depends, HTTPException, Request
from tortoise.transactions import in_transaction

from core.ip import client_ip
from core.permissions import require_min_role
from core.role_defs import ROLE_META, ROLE_OPERATOR, ROLE_STUDENT
from models.session import Session
from models.user import User
from schemas.admin_ops import ClassTransferBody
from schemas.user import BanRequest, UserAdminUpdate
from services.audit_service import write_audit
from services.last_edit_display import attach_last_editor_fields
from services.user_present import present_user
from services.user_service import (
    ban_user,
    can_view_user_profile,
    list_banned,
    unban_user,
)
from services.user_staff_edit import mark_staff_edit
from utils.sessions_extra import invalidate_all_sessions

router = APIRouter(prefix="/users", tags=["admin-users"])


@router.get("/banned")
async def banned_users(
    building: int | None = None,
    limit: int = 50,
    offset: int = 0,
    viewer: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    rows, total = await list_banned(building=building, limit=limit, offset=offset)
    items = [present_user(u, viewer, include_system=True) for u in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/{user_id}/ban")
async def ban_user_route(
    user_id: int,
    body: BanRequest,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    mark_staff_edit(target, actor)
    await ban_user(target, actor=actor, reason=body.reason)
    await write_audit(
        "user.ban",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"reason": body.reason},
    )
    return {"status": "banned"}


@router.post("/{user_id}/unban")
async def unban_user_route(
    user_id: int,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    mark_staff_edit(target, actor)
    await unban_user(target)
    await write_audit(
        "user.unban",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"status": "unbanned"}


@router.patch("/{user_id}")
async def admin_update_user(
    user_id: int,
    body: UserAdminUpdate,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    data = body.model_dump(exclude_unset=True)
    if "role" in data and data["role"] is not None:
        if data["role"] not in ROLE_META:
            raise HTTPException(status_code=400, detail="Неизвестная роль")
    if "login" in data and data["login"]:
        taken = (
            await User.filter(login=data["login"])
            .exclude(id=target.id)
            .exists()
        )
        if taken:
            raise HTTPException(status_code=409, detail="Логин занят")
    if "class_letter" in data and data["class_letter"]:
        data["class_letter"] = data["class_letter"][:1]
    mark_staff_edit(target, actor)
    for k, v in data.items():
        setattr(target, k, v)
    await target.save()
    await write_audit(
        "user.admin_update",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"fields": list(data.keys())},
    )
    out = present_user(target, actor, include_system=True)
    return await attach_last_editor_fields(out, target)


@router.post("/{user_id}/class")
async def admin_transfer_class(
    user_id: int,
    body: ClassTransferBody,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if target.role != ROLE_STUDENT:
        raise HTTPException(
            status_code=400,
            detail="Перевод между классами только для учащихся",
        )
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")

    mark_staff_edit(target, actor)
    target.class_number = body.class_number
    target.class_letter = body.class_letter.strip().upper()[:1]
    if body.building is not None:
        target.building = body.building
    await target.save()
    await write_audit(
        "user.class_transfer",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={
            "class_number": body.class_number,
            "class_letter": target.class_letter,
        },
    )
    out = present_user(target, actor, include_system=True)
    return await attach_last_editor_fields(out, target)


@router.delete("/{user_id}")
async def admin_remove_user(
    user_id: int,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    """Удаление учётной записи учащегося. Сессии удаляются."""
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if target.id == actor.id:
        raise HTTPException(status_code=400, detail="Нельзя удалить себя")
    if target.role != ROLE_STUDENT:
        raise HTTPException(
            status_code=400,
            detail="Удаление через этот метод только для учащихся",
        )
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")

    await write_audit(
        "user.deleted",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"login": target.login},
    )

    uid = target.id
    async with in_transaction():
        await Session.filter(user_id=uid).delete()
        await target.delete()

    return {"status": "deleted", "id": uid}
