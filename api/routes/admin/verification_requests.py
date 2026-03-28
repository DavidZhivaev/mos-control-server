from fastapi import APIRouter, Depends, HTTPException, Request

from core.ip import client_ip
from core.permissions import require_min_role
from core.role_defs import ROLE_OPERATOR
from models.user import User
from models.verification_request import VerificationRequest
from schemas.verification import VerificationApproveRequest, VerificationRejectRequest
from services.audit_service import write_audit
from services.verification_service import approve_request, list_requests, reject_request

router = APIRouter(
    prefix="/verification-requests",
    tags=["admin-verification"],
)


def _to_public(r: VerificationRequest) -> dict:
    return {
        "id": r.id,
        "status": r.status,
        "login": r.login,
        "first_name": r.first_name,
        "last_name": r.last_name,
        "class_number": r.class_number,
        "class_letter": r.class_letter,
        "building": r.building,
        "contact_method": r.contact_method,
        "submitter_ip": r.submitter_ip,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "processed_at": r.processed_at.isoformat() if r.processed_at else None,
        "reject_reason": r.reject_reason,
        "created_user_id": r.created_user_id,
    }


@router.get("/")
async def verification_list(
    status: str | None = "pending",
    limit: int = 50,
    offset: int = 0,
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    rows, total = await list_requests(status=status, limit=limit, offset=offset)
    return {
        "items": [_to_public(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{request_id}")
async def verification_get(
    request_id: int,
    _: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    r = await VerificationRequest.get_or_none(id=request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Не найдено")
    return _to_public(r)


@router.post("/{request_id}/approve")
async def verification_approve(
    request_id: int,
    body: VerificationApproveRequest,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    r = await VerificationRequest.get_or_none(id=request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Не найдено")
    user = await approve_request(
        r,
        actor=actor,
        middle_name=body.middle_name,
        contact_method=body.contact_method,
        building=body.building,
        role=body.role,
        can_access_personal_data=body.can_access_personal_data,
        storage_quota=body.storage_quota,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"status": "approved", "user_id": user.id, "login": user.login}


@router.post("/{request_id}/reject")
async def verification_reject(
    request_id: int,
    body: VerificationRejectRequest,
    request: Request,
    actor: User = Depends(require_min_role(ROLE_OPERATOR)),
):
    r = await VerificationRequest.get_or_none(id=request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Не найдено")
    if r.status != "pending":
        raise HTTPException(status_code=400, detail="Заявка уже обработана")
    await reject_request(r, actor=actor, reason=body.reason)
    await write_audit(
        "verification.rejected",
        actor=actor,
        target_type="verification_request",
        target_id=str(r.id),
        building=r.building,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        meta={"reason": body.reason, "login": r.login},
    )
    return {"status": "rejected"}
