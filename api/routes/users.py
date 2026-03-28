from fastapi import APIRouter, Depends, HTTPException, Request
from tortoise.transactions import in_transaction

from core.auth import get_current_user
from core.ip import client_ip
from core.permissions import require_min_role
from core.role_defs import ROLE_OPERATOR
from models.session import Session
from models.user import User
from services.audit_service import write_audit
from services.auth_service import hash_password, verify_password, get_password_hash, set_password_hash
from services.blocked_hosts_service import effective_blocked_hosts
from services.last_edit_display import attach_last_editor_fields
from services.user_present import present_me
from services.user_service import can_view_user_profile, get_user_for_viewer, search_users
from schemas.user import UserPasswordChange, UserSearchRequest, UserSelfUpdate

router = APIRouter(tags=["users"])


@router.get("/me")
async def read_me(user: User = Depends(get_current_user)):
    out = present_me(user)
    return await attach_last_editor_fields(out, user)


@router.get("/me/internet/blocked")
async def my_blocked_hosts(user: User = Depends(get_current_user)):
    hosts = await effective_blocked_hosts(user)
    return {"blocked_hosts": hosts, "count": len(hosts)}


@router.patch("/me")
async def update_me(
    request: Request,
    body: UserSelfUpdate,
    user: User = Depends(get_current_user),
):
    data = body.model_dump(exclude_unset=True)
    if not data:
        out = present_me(user)
        return await attach_last_editor_fields(out, user)
    if "login" in data and data["login"]:
        taken = await User.filter(login=data["login"]).exclude(id=user.id).exists()
        if taken:
            raise HTTPException(status_code=409, detail="Логин занят")
    for k, v in data.items():
        setattr(user, k, v)
    await user.save()
    await write_audit(
        "user.self_update",
        actor=user,
        target_type="user",
        target_id=str(user.id),
        building=user.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"fields": list(data.keys())},
    )
    out = present_me(user)
    return await attach_last_editor_fields(out, user)


@router.post("/me/password")
async def change_password(
    request: Request,
    body: UserPasswordChange,
    user: User = Depends(get_current_user),
):
    current_hash = await get_password_hash(user)
    
    if not current_hash or not verify_password(body.old_password, current_hash):
        raise HTTPException(status_code=400, detail="Неверный текущий пароль")
    
    new_hash = hash_password(body.new_password)
    await set_password_hash(user, new_hash)
    
    await write_audit(
        "user.password_change",
        actor=user,
        target_type="user",
        target_id=str(user.id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"status": "ok"}


@router.post("/search")
async def user_search(body: UserSearchRequest, viewer: User = Depends(get_current_user)):
    items, total = await search_users(
        viewer,
        text=body.query,
        mode=body.mode,
        building=body.building,
        role_id=body.role_id,
        limit=body.limit,
        offset=body.offset,
    )
    return {"items": items, "total": total, "limit": body.limit, "offset": body.offset}


@router.get("/{user_id}")
async def read_user(
    user_id: int,
    mode: str = "short",
    viewer: User = Depends(get_current_user),
):
    if mode not in ("short", "full"):
        raise HTTPException(status_code=400, detail="mode: short или full")
    return await get_user_for_viewer(viewer, user_id, mode=mode)


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    viewer: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if target.id == viewer.id:
        raise HTTPException(status_code=400, detail="Нельзя удалить свой аккаунт")
    if not can_view_user_profile(viewer, target):
        raise HTTPException(status_code=403, detail="Нет доступа")

    await write_audit(
        "user.deleted",
        actor=viewer,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"login": target.login},
    )

    async with in_transaction():
        await Session.filter(user_id=target.id).delete()
        await target.delete()

    return {"status": "deleted", "id": target.id}
