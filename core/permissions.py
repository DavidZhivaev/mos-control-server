from fastapi import Depends, HTTPException

from core.auth import get_current_user
from core.role_defs import ROLE_ADMIN_SCHOOL, ROLE_DEVELOPER, ROLE_OPERATOR, role_at_least
from models.user import User


def require_min_role(minimum_role_id: int):
    async def _dep(user: User = Depends(get_current_user)) -> User:
        if not role_at_least(user.role, minimum_role_id):
            raise HTTPException(status_code=403, detail="Недостаточно прав. Доступ ограничен.")
        return user

    return _dep


def require_operator_or_above():
    return require_min_role(ROLE_OPERATOR)


def require_admin_security_or_above():
    from core.role_defs import ROLE_ADMIN_SECURITY

    return require_min_role(ROLE_ADMIN_SECURITY)


def require_admin_school_or_above():
    return require_min_role(ROLE_ADMIN_SCHOOL)


def require_personal_data_access():
    async def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in (ROLE_DEVELOPER, ROLE_ADMIN_SCHOOL):
            raise HTTPException(
                status_code=403,
                detail="Доступ только для разработчиков и администраторов школы"
            )
        return user

    return _dep
