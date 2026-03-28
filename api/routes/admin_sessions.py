from fastapi import APIRouter, Depends, HTTPException, Request
from core.ip import client_ip
from core.permissions import require_min_role
from core.role_defs import ROLE_OPERATOR
from models.user import User
from models.session import Session
from schemas.storage import SessionResponse
from services.session_service import (
    get_all_active_sessions,
    revoke_session,
)
from services.audit_service import write_audit
from tortoise.expressions import Q

router = APIRouter(prefix="/admin/sessions", tags=["admin-sessions"])


@router.get("")
async def list_all_sessions(
    building: int | None = None,
    limit: int = 100,
    offset: int = 0,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    qs = Session.filter(is_active=True).order_by("-created_at")

    if building is not None:
        qs = qs.filter(user__building=building)

    total = await qs.count()
    sessions = await qs.offset(offset).limit(min(limit, 500)).select_related("user")

    items = []
    for s in sessions:
        items.append({
            "id": str(s.id),
            "ip": s.ip,
            "user_agent": s.user_agent[:200],
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            "is_active": s.is_active,
            "user": {
                "id": s.user_id,
                "login": s.user.login if s.user else None,
                "building": s.user.building if s.user else None,
            },
        })

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.delete("/{session_id}")
async def revoke_session_admin(
    session_id: str,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    session = await revoke_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Сессия не найдена")

    await write_audit(
        "session.revoke_admin",
        actor=actor,
        target_type="session",
        target_id=session_id,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    return {"status": "revoked", "session_id": session_id}
