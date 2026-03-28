from fastapi import APIRouter, Depends

from core.permissions import require_min_role
from core.role_defs import ROLE_OPERATOR
from models.user import User
from services.stats_service import (
    audit_actions_aggregate,
    registration_series,
    summary_snapshot,
)

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/dashboard")
async def stats_dashboard(_: User = Depends(require_min_role(ROLE_OPERATOR))):
    return {
        "summary": await summary_snapshot(),
        "audit_by_action_7d": await audit_actions_aggregate(7),
        "registrations_14d": await registration_series(14),
    }


@router.get("/summary")
async def stats_summary(_: User = Depends(require_min_role(ROLE_OPERATOR))):
    return await summary_snapshot()


@router.get("/audit/by-action")
async def stats_audit_by_action(
    days: int = 7,
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    return await audit_actions_aggregate(days=min(days, 90))


@router.get("/registrations/series")
async def stats_registrations_series(
    days: int = 14,
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    return await registration_series(days=min(days, 90))
