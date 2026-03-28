from typing import Any

from models.audit_log import AuditLog
from models.user import User
from core.logging_config import get_audit_logger


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
    log_entry = await AuditLog.create(
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
    
    audit_logger = get_audit_logger()
    audit_logger.log(
        event=action,
        actor_id=actor.id if actor else None,
        actor_login=actor.login if actor else None,
        target_type=target_type or "unknown",
        target_id=target_id,
        action=action.split(".")[-1] if "." in action else action,
        ip=ip or "",
        user_agent=user_agent or "",
        building=building,
        success=success,
        meta=meta or {},
    )
    
    return log_entry
