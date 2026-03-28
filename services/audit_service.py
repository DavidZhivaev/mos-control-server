from typing import Any

from models.audit_log import AuditLog
from models.user import User


async def write_audit(
    action: str,
    *,
    actor: User | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    building: int | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    success: bool = True,
    meta: dict[str, Any] | None = None,
) -> AuditLog:
    return await AuditLog.create(
        action=action,
        actor=actor,
        actor_email_snapshot=actor.login if actor else None,
        target_type=target_type,
        target_id=target_id,
        building=building,
        ip=ip,
        user_agent=user_agent,
        success=success,
        meta=meta or {},
    )
