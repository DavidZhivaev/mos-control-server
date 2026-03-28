from fastapi import APIRouter, Depends, Query
from core.permissions import require_min_role
from core.role_defs import ROLE_OPERATOR
from models.user import User
from services.stats_extra_service import (
    get_buildings_stats,
    get_active_users_stats,
    get_audit_actions_list,
)

router = APIRouter(prefix="/admin/stats", tags=["admin-stats"])


@router.get("/buildings")
async def get_buildings_statistics(
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    buildings = await get_buildings_stats()
    return {"items": buildings, "count": len(buildings)}


@router.get("/active-users")
async def get_active_users(
    limit: int = Query(default=50, ge=1, le=200),
    building: int | None = None,
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    users = await get_active_users_stats(limit=limit, building=building)
    return {"items": users, "count": len(users)}


@router.get("/audit/actions")
async def get_audit_actions(
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    actions = await get_audit_actions_list()
    return {"actions": actions, "count": len(actions)}
