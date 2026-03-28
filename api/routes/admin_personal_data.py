from fastapi import APIRouter, Depends, HTTPException, Request
from core.ip import client_ip
from core.permissions import require_personal_data_access
from models.user import User
from services.audit_service import write_audit
from services.personal_data_service import (
    grant_personal_data_access,
    revoke_personal_data_access,
    get_personal_data_access_status,
)
from services.user_service import can_view_user_profile

router = APIRouter(prefix="/admin/users", tags=["admin-users-personal-data"])


@router.get("/{user_id}/personal-data-access")
async def get_personal_data_access(
    user_id: int,
    actor: User = Depends(require_personal_data_access),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    
    return get_personal_data_access_status(target)


@router.post("/{user_id}/personal-data-access")
async def grant_personal_data_access_route(
    user_id: int,
    request: Request,
    actor: User = Depends(require_personal_data_access),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    if target.id == actor.id:
        raise HTTPException(status_code=400, detail="Нельзя выдать доступ самому себе")
    
    await grant_personal_data_access(target, actor)
    
    await write_audit(
        "user.personal_data_access_granted",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    
    return {
        "status": "granted",
        "user_id": target.id,
        "user_login": target.login,
        "can_access_personal_data": True,
    }


@router.delete("/{user_id}/personal-data-access")
async def revoke_personal_data_access_route(
    user_id: int,
    request: Request,
    actor: User = Depends(require_personal_data_access),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    if target.id == actor.id:
        raise HTTPException(status_code=400, detail="Нельзя отозвать доступ у самого себя")
    
    await revoke_personal_data_access(target, actor)
    
    await write_audit(
        "user.personal_data_access_revoked",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    
    return {
        "status": "revoked",
        "user_id": target.id,
        "user_login": target.login,
        "can_access_personal_data": False,
    }
