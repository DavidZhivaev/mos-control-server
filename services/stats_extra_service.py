from typing import Optional
from datetime import datetime, timedelta
from models.user import User
from models.session import Session
from models.audit_log import AuditLog
from tortoise.expressions import Q
from tortoise.functions import Count, Max


async def get_buildings_stats() -> list[dict]:
    buildings = await User.filter(is_active=True).values("building").annotate(
        user_count=Count("id")
    ).order_by("building")

    result = []
    for b in buildings:
        building = b["building"]
        active_count = await User.filter(
            building=building,
            is_active=True,
            updated_at__gte=datetime.now() - timedelta(days=7)
        ).count()

        result.append({
            "building": building,
            "name": None,
            "user_count": b["user_count"],
            "active_user_count": active_count,
        })

    return result


async def get_active_users_stats(
    limit: int = 50,
    building: Optional[int] = None
) -> list[dict]:
    qs = User.filter(is_active=True)

    if building is not None:
        qs = qs.filter(building=building)

    users = await qs.annotate(
        sessions_count=Count("sessions", distinct=True, _filter=Q(sessions__is_active=True))
    ).order_by("-sessions_count", "-updated_at").limit(limit)

    result = []
    for user in users:
        last_audit = await AuditLog.filter(
            actor_id=user.id
        ).order_by("-created_at").first()

        last_activity = None
        if last_audit and last_audit.created_at:
            last_activity = last_audit.created_at.isoformat()

        result.append({
            "user_id": user.id,
            "login": user.login,
            "full_name": f"{user.last_name} {user.first_name}",
            "building": user.building,
            "role": user.role,
            "sessions_count": user.sessions_count,
            "last_activity": last_activity,
        })

    return result


async def get_audit_actions_list() -> list[str]:
    actions = await AuditLog.all().values_list("action", flat=True).distinct()
    return sorted(actions)
