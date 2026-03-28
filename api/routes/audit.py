import json
from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from core.auth import get_current_user
from core.permissions import require_min_role
from core.role_defs import ROLE_OPERATOR
from models.audit_log import AuditLog
from models.user import User

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs")
async def list_audit_logs(
    action: str | None = None,
    actor_id: int | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    building: int | None = None,
    success: bool | None = None,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    cursor_after_id: int | None = None,
    limit: int = 100,
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    qs = AuditLog.all().order_by("-id")
    if action:
        qs = qs.filter(action=action)
    if actor_id is not None:
        qs = qs.filter(actor_id=actor_id)
    if target_type:
        qs = qs.filter(target_type=target_type)
    if target_id:
        qs = qs.filter(target_id=target_id)
    if building is not None:
        qs = qs.filter(building=building)
    if success is not None:
        qs = qs.filter(success=success)
    if from_ts:
        qs = qs.filter(created_at__gte=from_ts)
    if to_ts:
        qs = qs.filter(created_at__lte=to_ts)
    if cursor_after_id is not None:
        qs = qs.filter(id__lt=cursor_after_id)

    rows = await qs.limit(min(limit, 500))
    next_cursor = rows[-1].id if rows else None

    out = []
    for r in rows:
        out.append(
            {
                "id": r.id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "action": r.action,
                "actor_id": r.actor_id,
                "actor_email_snapshot": r.actor_email_snapshot,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "building": r.building,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "success": r.success,
                "meta": r.meta,
            }
        )
    return {
        "items": out,
        "next_cursor_after_id": next_cursor,
        "count": len(out),
    }


@router.get("/export.ndjson")
async def export_logs_ndjson(
    from_ts: datetime | None = None,
    limit: int = 5000,
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    qs = AuditLog.all().order_by("-id")
    if from_ts:
        qs = qs.filter(created_at__gte=from_ts)
    rows = await qs.limit(min(limit, 50_000))
    lines = []
    for r in rows:
        lines.append(
            json.dumps(
                {
                    "id": r.id,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "action": r.action,
                    "actor_id": r.actor_id,
                    "target_id": r.target_id,
                    "building": r.building,
                    "success": r.success,
                    "meta": r.meta,
                },
                ensure_ascii=False,
            )
        )
    body = "\n".join(lines)
    return PlainTextResponse(body, media_type="application/x-ndjson")
