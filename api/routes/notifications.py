from fastapi import APIRouter, Depends, HTTPException, Request
from core.auth import get_current_user
from core.ip import client_ip
from models.user import User
from schemas.notifications import NotificationResponse
from services.notification_service import (
    get_user_notifications,
    mark_notification_read,
    get_unread_count,
    delete_notification,
)
from services.audit_service import write_audit

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
async def list_notifications(
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0,
    user: User = Depends(get_current_user),
):
    notifications, total = await get_user_notifications(
        user.id,
        unread_only=unread_only,
        limit=limit,
        offset=offset,
    )

    items = [
        NotificationResponse(
            id=n.id,
            title=n.title,
            message=n.message,
            is_read=n.is_read,
            is_system=n.is_system,
            created_at=n.created_at.isoformat() if n.created_at else None,
            read_at=n.read_at.isoformat() if n.read_at else None,
            created_by_id=n.created_by_id,
        ).model_dump()
        for n in notifications
    ]

    return {
        "items": items,
        "total": total,
        "unread_count": await get_unread_count(user.id),
        "limit": limit,
        "offset": offset,
    }


@router.get("/unread-count")
async def get_unread_count_endpoint(
    user: User = Depends(get_current_user),
):
    count = await get_unread_count(user.id)
    return {"unread_count": count}


@router.patch("/{notification_id}/read")
async def mark_as_read(
    notification_id: int,
    request: Request,
    user: User = Depends(get_current_user),
):
    notification = await mark_notification_read(notification_id, user_id=user.id)
    if not notification:
        raise HTTPException(status_code=404, detail="Уведомление не найдено или уже прочитано")

    await write_audit(
        "notification.mark_read",
        actor=user,
        target_type="notification",
        target_id=str(notification_id),
        building=user.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    return {"status": "read", "id": notification_id}


@router.delete("/{notification_id}")
async def delete_notification_endpoint(
    notification_id: int,
    request: Request,
    user: User = Depends(get_current_user),
):
    deleted = await delete_notification(notification_id, user_id=user.id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Уведомление не найдено")

    await write_audit(
        "notification.deleted",
        actor=user,
        target_type="notification",
        target_id=str(notification_id),
        building=user.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    return {"status": "deleted", "id": notification_id}
