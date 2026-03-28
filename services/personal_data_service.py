from datetime import datetime
from typing import Optional
from models.user import User
from services.user_staff_edit import mark_staff_edit


async def grant_personal_data_access(
    target: User,
    granted_by: User
) -> None:
    target.can_access_personal_data = True
    target.updated_at = datetime.now()
    mark_staff_edit(target, granted_by)
    await target.save()


async def revoke_personal_data_access(
    target: User,
    revoked_by: User
) -> None:
    target.can_access_personal_data = False
    target.updated_at = datetime.now()
    mark_staff_edit(target, revoked_by)
    await target.save()


async def get_personal_data_access_status(user: User) -> dict:
    return {
        "can_access_personal_data": user.can_access_personal_data,
        "user_id": user.id,
        "user_login": user.login,
    }
