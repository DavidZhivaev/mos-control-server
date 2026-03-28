from __future__ import annotations

from core.role_defs import role_label
from models.user import User


def _class_label(u: User) -> str | None:
    if u.class_number is None:
        return None
    letter = u.class_letter or ""
    return f"{u.class_number}{letter}"


def names_fully_visible(viewer: User, target: User) -> bool:
    if viewer.id == target.id:
        return True
    return bool(viewer.can_access_personal_data)


def present_user(
    target: User,
    viewer: User,
    *,
    include_system: bool,
) -> dict:
    role = role_label(target.role)
    full_name = names_fully_visible(viewer, target)

    out: dict = {
        "id": target.id,
        "login": target.login,
        "first_name": target.first_name,
        "role": role,
        "building": target.building,
        "class_label": _class_label(target),
    }

    if full_name:
        out["last_name"] = target.last_name
        out["middle_name"] = target.middle_name
    else:
        ln = (target.last_name or "").strip()
        out["last_redacted"] = True
        out["last_name"] = (ln[0] + ".") if ln else ""
        out["middle_name"] = None

    if include_system:
        out["contact_method"] = target.contact_method
        out["is_active"] = target.is_active
        out["is_banned"] = target.is_banned
        out["ban_reason"] = target.ban_reason
        out["can_access_personal_data"] = target.can_access_personal_data
        out["internet_overrides"] = target.internet_overrides
        out["storage_quota"] = target.storage_quota
        if target.created_at:
            out["created_at"] = target.created_at.isoformat()
        if target.updated_at:
            out["updated_at"] = target.updated_at.isoformat()

    return out


def present_me(user: User) -> dict:
    role = role_label(user.role)
    return {
        "id": user.id,
        "login": user.login,
        "contact_method": user.contact_method,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "middle_name": user.middle_name,
        "role": role,
        "building": user.building,
        "class_label": _class_label(user),
        "is_active": user.is_active,
        "is_banned": user.is_banned,
        "ban_reason": user.ban_reason,
        "can_access_personal_data": user.can_access_personal_data,
        "internet_overrides": user.internet_overrides,
        "storage_quota": user.storage_quota,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }
