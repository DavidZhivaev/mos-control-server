from datetime import datetime

from fastapi import HTTPException
from tortoise.transactions import in_transaction

from core.config import settings
from core.role_defs import ROLE_META, ROLE_STUDENT
from core.school_networks import building_for_school_ip
from models.user import User
from models.verification_request import VerificationRequest
from services.audit_service import write_audit
from services.auth_service import hash_password, set_password_hash


async def submit_request(
    *,
    login: str,
    password: str,
    first_name: str,
    last_name: str,
    class_number: int,
    class_letter: str,
    contact_method: str | None,
    submitter_ip: str,
) -> VerificationRequest:
    ln = login.strip().lower()

    if await User.filter(login=ln).exists():
        raise HTTPException(status_code=409, detail="Логин уже занят")

    if await VerificationRequest.filter(login=ln, status="pending").exists():
        raise HTTPException(
            status_code=409,
            detail="По этому логину уже есть активная заявка",
        )

    building = building_for_school_ip(submitter_ip)
    if building is None:
        if settings.ALLOW_VERIFICATION_OUTSIDE_SCHOOL:
            building = settings.DEFAULT_BUILDING_WHEN_OUTSIDE_NETWORK
        else:
            raise HTTPException(
                status_code=403,
                detail="Подача заявки возможна только из сети школы",
            )

    return await VerificationRequest.create(
        status="pending",
        login=ln,
        password_hash=hash_password(password),
        first_name=first_name,
        last_name=last_name,
        class_number=class_number,
        class_letter=class_letter.strip().upper()[:1],
        building=building,
        contact_method=contact_method.strip()[:500] if contact_method else None,
        submitter_ip=submitter_ip,
    )


async def list_requests(*, status: str | None, limit: int, offset: int):
    qs = VerificationRequest.all().order_by("-id")
    if status:
        qs = qs.filter(status=status)
    total = await qs.count()
    rows = await qs.offset(offset).limit(limit)
    return rows, total


async def reject_request(
    req: VerificationRequest, *, actor: User, reason: str | None
) -> None:
    req.status = "rejected"
    req.processed_at = datetime.utcnow()
    req.processed_by = actor
    req.reject_reason = reason
    await req.save()


async def approve_request(
    req: VerificationRequest,
    *,
    actor: User,
    middle_name: str | None,
    contact_method: str | None,
    building: int | None,
    role: int | None,
    can_access_personal_data: bool | None,
    storage_quota: float | None,
    ip: str | None,
    user_agent: str | None,
) -> User:
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Заявка уже обработана")

    rid = role if role is not None else ROLE_STUDENT
    if rid not in ROLE_META:
        raise HTTPException(status_code=400, detail="Неизвестная роль")

    if await User.filter(login=req.login).exists():
        raise HTTPException(status_code=409, detail="Логин уже занят в учётных записях")

    b = building if building is not None else req.building

    if contact_method is not None:
        cm = contact_method.strip()
        cm = cm[:500] if cm else None
    else:
        cm = req.contact_method

    mid = middle_name.strip()[:100] if middle_name and middle_name.strip() else None

    async with in_transaction():
        user = await User.create(
            login=req.login,
            password_hash=None,
            last_name=req.last_name,
            first_name=req.first_name,
            middle_name=mid,
            class_number=req.class_number,
            class_letter=req.class_letter,
            building=b,
            contact_method=cm,
            role=rid,
            can_access_personal_data=bool(can_access_personal_data)
            if can_access_personal_data is not None
            else False,
            storage_quota=storage_quota
            if storage_quota is not None
            else 0.25,
        )
        
        await set_password_hash(user, req.password_hash)
        
        req.status = "approved"
        req.processed_at = datetime.utcnow()
        req.processed_by = actor
        req.created_user = user
        await req.save()

    await write_audit(
        "verification.approved",
        actor=actor,
        target_type="user",
        target_id=str(user.id),
        building=user.building,
        ip=ip,
        user_agent=user_agent,
        meta={"request_id": req.id, "login": user.login},
    )
    return user
