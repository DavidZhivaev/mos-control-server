from fastapi import APIRouter, Depends, HTTPException, Request
from core.auth import get_current_user
from core.ip import client_ip
from core.permissions import require_min_role
from core.role_defs import ROLE_OPERATOR
from models.user import User
from schemas.storage import SessionResponse, SessionRevokeResponse
from services.session_service import (
    get_user_sessions,
    revoke_session,
    revoke_all_user_sessions,
    get_all_active_sessions,
    get_session_by_id,
)
from services.audit_service import write_audit

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("/me")
async def list_my_sessions(
    user: User = Depends(get_current_user),
):
    sessions = await get_user_sessions(user.id, active_only=True)
    return {
        "items": [
            SessionResponse(
                id=str(s.id),
                ip=s.ip,
                user_agent=s.user_agent[:200],
                created_at=s.created_at.isoformat() if s.created_at else None,
                expires_at=s.expires_at.isoformat() if s.expires_at else None,
                is_active=s.is_active,
            ).model_dump()
            for s in sessions
        ],
        "count": len(sessions),
    }


@router.delete("/me/{session_id}")
async def revoke_my_session(
    session_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    session = await get_session_by_id(session_id, user_id=user.id)
    if not session:
        raise HTTPException(status_code=404, detail="Сессия не найдена")

    if str(session.id) == session_id:
        await revoke_session(session_id, user_id=user.id)

        await write_audit(
            "session.revoke_self",
            actor=user,
            target_type="session",
            target_id=session_id,
            building=user.building,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

        return SessionRevokeResponse(status="revoked", message="Сессия завершена")

    return SessionRevokeResponse(status="success")


@router.post("/me/revoke-all")
async def revoke_all_my_sessions(
    request: Request,
    user: User = Depends(get_current_user),
):
    current_session_id = None

    count = await revoke_all_user_sessions(user.id, exclude_session_id=current_session_id)

    await write_audit(
        "session.revoke_all_self",
        actor=user,
        target_type="user",
        target_id=str(user.id),
        building=user.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"revoked_count": count},
    )

    return {"status": "success", "revoked_count": count}
