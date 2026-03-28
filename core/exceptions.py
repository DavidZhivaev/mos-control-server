from fastapi import HTTPException

from core.config import settings


def banned_exception(reason: str | None = None) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={
            "code": "USER_BANNED",
            "message": (
                "Доступ заблокирован. Для разблокировки напишите на почту администратора информационной безопасности."
            ),
            "support_email": settings.SUPPORT_EMAIL,
            "reason": reason,
        },
    )
