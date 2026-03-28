from fastapi import APIRouter

from core.role_defs import ROLE_OPERATOR, role_label
from models.user import User

router = APIRouter(prefix="/public", tags=["public"])


@router.get("/admins")
async def list_public_staff():
    rows = (
        await User.filter(role__gte=ROLE_OPERATOR, is_active=True, is_banned=False)
        .order_by("building", "role", "last_name", "first_name")
        .all()
    )
    return {
        "items": [
            {
                "id": u.id,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "middle_name": u.middle_name,
                "role": role_label(u.role),
                "building": u.building,
                "class_label": None
                if u.class_number is None
                else f"{u.class_number}{u.class_letter or ''}",
            }
            for u in rows
        ],
        "count": len(rows),
    }
