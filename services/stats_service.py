from collections import defaultdict
from datetime import datetime, timedelta

from core.role_defs import ROLE_META, ROLE_ORDER
from models.audit_log import AuditLog
from models.user import User
from models.verification_request import VerificationRequest


async def summary_snapshot() -> dict:
    by_role = {rid: await User.filter(role=rid).count() for rid in ROLE_ORDER}
    by_building: dict[int, int] = defaultdict(int)
    for row in await User.all().values("building"):
        by_building[row["building"]] += 1

    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    new_users_week = await User.filter(created_at__gte=week_ago).count()
    total_users = await User.all().count()
    banned = await User.filter(is_banned=True).count()
    pending_verifications = await VerificationRequest.filter(status="pending").count()

    log_week = await AuditLog.filter(created_at__gte=week_ago).count()

    role_key_counts = {
        ROLE_META.get(r, {}).get("code_en", str(r)): by_role[r] for r in ROLE_ORDER
    }
    return {
        "total_users": total_users,
        "new_users_last_7_days": new_users_week,
        "users_by_role": role_key_counts,
        "users_by_building": dict(sorted(by_building.items())),
        "banned_users": banned,
        "pending_verification_requests": pending_verifications,
        "audit_events_last_7_days": log_week,
    }


async def audit_actions_aggregate(days: int = 7) -> dict:
    since = datetime.utcnow() - timedelta(days=days)
    rows = await AuditLog.filter(created_at__gte=since).values("action")
    counts: dict[str, int] = defaultdict(int)
    for r in rows:
        counts[r["action"]] += 1
    return {
        "period_days": days,
        "by_action": dict(sorted(counts.items(), key=lambda x: -x[1])),
        "total": sum(counts.values()),
    }


async def registration_series(days: int = 14) -> list[dict]:
    since_date = datetime.utcnow().date() - timedelta(days=days - 1)
    cut = datetime.combine(since_date, datetime.min.time())
    rows = await User.filter(created_at__gte=cut).all()
    by_day: dict[str, int] = defaultdict(int)
    for u in rows:
        if u.created_at:
            d = u.created_at.date().isoformat()
            by_day[d] += 1
    out = []
    for i in range(days):
        d = (since_date + timedelta(days=i)).isoformat()
        out.append({"date": d, "registrations": by_day.get(d, 0)})
    return out
