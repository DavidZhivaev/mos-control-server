from datetime import datetime
from typing import Optional
from models.notification import Notification
from models.user import User
from tortoise.expressions import Q


async def get_user_notifications(
    user_id: int,
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0
) -> tuple[list[Notification], int]:
    qs = Notification.filter(user_id=user_id).order_by("-created_at")

    if unread_only:
        qs = qs.filter(is_read=False)

    total = await qs.count()
    rows = await qs.offset(offset).limit(min(limit, 200))

    return rows, total


async def mark_notification_read(
    notification_id: int,
    user_id: Optional[int] = None
) -> Optional[Notification]:
    qs = Notification.filter(id=notification_id, is_read=False)
    if user_id is not None:
        qs = qs.filter(user_id=user_id)

    notification = await qs.first()
    if notification:
        notification.is_read = True
        notification.read_at = datetime.now()
        await notification.save()

    return notification


async def create_notification(
    user_id: int,
    title: str,
    message: str,
    is_system: bool = False,
    created_by_id: Optional[int] = None
) -> Notification:
    return await Notification.create(
        user_id=user_id,
        title=title,
        message=message,
        is_system=is_system,
        created_by_id=created_by_id,
    )


async def broadcast_notification(
    title: str,
    message: str,
    is_system: bool = True,
    created_by_id: Optional[int] = None,
    building: Optional[int] = None,
    role_id: Optional[int] = None
) -> int:
    qs = User.filter(is_active=True)

    if building is not None:
        qs = qs.filter(building=building)

    if role_id is not None:
        qs = qs.filter(role=role_id)

    users = await qs

    count = 0
    for user in users:
        await Notification.create(
            user_id=user.id,
            title=title,
            message=message,
            is_system=is_system,
            created_by_id=created_by_id,
        )
        count += 1

    return count


async def get_unread_count(user_id: int) -> int:
    return await Notification.filter(user_id=user_id, is_read=False).count()


async def delete_notification(
    notification_id: int,
    user_id: Optional[int] = None
) -> bool:
    qs = Notification.filter(id=notification_id)
    if user_id is not None:
        qs = qs.filter(user_id=user_id)

    deleted = await qs.delete()
    return deleted > 0
