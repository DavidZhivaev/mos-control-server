from __future__ import annotations

from models.user import User

ROLE_STUDENT = 1
ROLE_TEACHER = 2
ROLE_OPERATOR = 3
ROLE_ADMIN_SECURITY = 4
ROLE_ADMIN_SCHOOL = 5
ROLE_DEVELOPER = 6

ROLE_ORDER: list[int] = [
    ROLE_STUDENT,
    ROLE_TEACHER,
    ROLE_OPERATOR,
    ROLE_ADMIN_SECURITY,
    ROLE_ADMIN_SCHOOL,
    ROLE_DEVELOPER,
]

BUILDING_SCOPED_ROLES = frozenset({ROLE_TEACHER, ROLE_OPERATOR})

ROLE_META: dict[int, dict[str, str]] = {
    ROLE_STUDENT: {"code_en": "student", "name_ru": "Учащийся"},
    ROLE_TEACHER: {"code_en": "teacher", "name_ru": "Учитель"},
    ROLE_OPERATOR: {"code_en": "operator", "name_ru": "Оператор"},
    ROLE_ADMIN_SECURITY: {"code_en": "admin_security", "name_ru": "Администратор ИБ"},
    ROLE_ADMIN_SCHOOL: {"code_en": "admin_school", "name_ru": "Администратор школы"},
    ROLE_DEVELOPER: {"code_en": "developer", "name_ru": "Разработчик"},
}


def role_rank(role_id: int) -> int:
    try:
        return ROLE_ORDER.index(role_id)
    except ValueError:
        return -1


def role_at_least(user_role: int, minimum_role: int) -> bool:
    return role_rank(user_role) >= role_rank(minimum_role)


def role_label(role_id: int) -> dict[str, str]:
    meta = ROLE_META.get(role_id)
    if not meta:
        return {"id": str(role_id), "code_en": "unknown", "name_ru": "неизвестно"}
    return {
        "id": role_id,
        "code_en": meta["code_en"],
        "name_ru": meta["name_ru"],
    }


def building_scope_allows(actor_role: int, actor_building: int, target: User) -> bool:
    if target.role == ROLE_STUDENT and actor_role in BUILDING_SCOPED_ROLES:
        return actor_building == target.building
    return True
