from fastapi import APIRouter, Depends, HTTPException, Request

from core.ip import client_ip
from core.permissions import require_admin_school_or_above
from models.global_blocked_host import GlobalBlockedHost, UserHostOverride
from models.user import User
from schemas.admin_ops import GlobalBlockCreate, GlobalBlockPatch, UserHostOverrideBody
from services.audit_service import write_audit
from services.blocked_hosts_service import normalize_hostname
from services.user_service import can_view_user_profile

router = APIRouter(prefix="/internet", tags=["admin-internet"])


@router.get("/global-blocks")
async def list_global_blocks(
    include_inactive: bool = False,
    limit: int = 200,
    offset: int = 0,
    _: User = Depends(require_admin_school_or_above()),
):
    qs = GlobalBlockedHost.all().order_by("hostname")
    if not include_inactive:
        qs = qs.filter(is_active=True)
    total = await qs.count()
    rows = await qs.offset(offset).limit(min(limit, 500))
    return {
        "items": [
            {
                "id": r.id,
                "hostname": r.hostname,
                "note": r.note,
                "is_active": r.is_active,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "total": total,
    }


@router.post("/global-blocks")
async def create_global_block(
    body: GlobalBlockCreate,
    request: Request,
    actor: User = Depends(require_admin_school_or_above()),
):
    host = normalize_hostname(body.hostname)
    if await GlobalBlockedHost.filter(hostname=host).exists():
        raise HTTPException(status_code=409, detail="Хост уже в списке")
    row = await GlobalBlockedHost.create(
        hostname=host,
        note=body.note,
        created_by=actor,
    )
    await write_audit(
        "internet.global_block_create",
        actor=actor,
        target_type="global_block",
        target_id=str(row.id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"hostname": host},
    )
    return {"id": row.id, "hostname": row.hostname}


@router.patch("/global-blocks/{block_id}")
async def patch_global_block(
    block_id: int,
    body: GlobalBlockPatch,
    request: Request,
    actor: User = Depends(require_admin_school_or_above()),
):
    row = await GlobalBlockedHost.get_or_none(id=block_id)
    if not row:
        raise HTTPException(status_code=404, detail="Не найдено")
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(row, k, v)
    await row.save()
    await write_audit(
        "internet.global_block_patch",
        actor=actor,
        target_type="global_block",
        target_id=str(row.id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta=data,
    )
    return {"id": row.id, "hostname": row.hostname, "is_active": row.is_active}


@router.delete("/global-blocks/{block_id}")
async def delete_global_block(
    block_id: int,
    request: Request,
    actor: User = Depends(require_admin_school_or_above()),
):
    row = await GlobalBlockedHost.get_or_none(id=block_id)
    if not row:
        raise HTTPException(status_code=404, detail="Не найдено")
    host = row.hostname
    await row.delete()
    await write_audit(
        "internet.global_block_delete",
        actor=actor,
        target_type="global_block",
        target_id=str(block_id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"hostname": host},
    )
    return {"status": "deleted"}


@router.get("/users/{user_id}/overrides")
async def list_user_overrides(
    user_id: int,
    actor: User = Depends(require_admin_school_or_above()),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    rows = await UserHostOverride.filter(user=target).order_by("hostname")
    return {
        "items": [
            {
                "id": r.id,
                "hostname": r.hostname,
                "effect": r.effect,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    }


@router.post("/users/{user_id}/overrides")
async def upsert_user_override(
    user_id: int,
    body: UserHostOverrideBody,
    request: Request,
    actor: User = Depends(require_admin_school_or_above()),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    host = normalize_hostname(body.hostname)
    row = await UserHostOverride.get_or_none(user=target, hostname=host)
    if row:
        row.effect = body.effect
        row.created_by = actor
        await row.save()
    else:
        row = await UserHostOverride.create(
            user=target,
            hostname=host,
            effect=body.effect,
            created_by=actor,
        )
    await write_audit(
        "internet.user_override_upsert",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"hostname": host, "effect": body.effect},
    )
    return {"id": row.id, "hostname": row.hostname, "effect": row.effect}


@router.delete("/users/{user_id}/overrides/{override_id}")
async def delete_user_override(
    user_id: int,
    override_id: int,
    request: Request,
    actor: User = Depends(require_admin_school_or_above()),
):
    target = await User.get_or_none(id=user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Не найден")
    if not can_view_user_profile(actor, target):
        raise HTTPException(status_code=403, detail="Нет доступа")
    row = await UserHostOverride.get_or_none(id=override_id, user=target)
    if not row:
        raise HTTPException(status_code=404, detail="Не найдено")
    await row.delete()
    await write_audit(
        "internet.user_override_delete",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        building=target.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"override_id": override_id},
    )
    return {"status": "deleted"}
