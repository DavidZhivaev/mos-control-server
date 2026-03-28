from fastapi import APIRouter, Depends, HTTPException, Request
from core.ip import client_ip
from core.permissions import require_min_role
from core.role_defs import ROLE_OPERATOR
from models.user import User
from schemas.notifications import NotificationBroadcast
from services.notification_service import broadcast_notification
from services.audit_service import write_audit

router = APIRouter(prefix="/admin/notifications", tags=["admin-notifications"])


@router.post("/broadcast")
async def broadcast_notifications(
    body: NotificationBroadcast,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    count = await broadcast_notification(
        title=body.title,
        message=body.message,
        is_system=body.is_system,
        created_by_id=actor.id,
        building=body.building,
        role_id=body.role_id,
    )

    await write_audit(
        "notification.broadcast",
        actor=actor,
        target_type="notification",
        target_id="broadcast",
        building=actor.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={
            "title": body.title,
            "building": body.building,
            "role_id": body.role_id,
            "recipients_count": count,
        },
    )

    return {"status": "sent", "recipients_count": count}
