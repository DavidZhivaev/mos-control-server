from fastapi import APIRouter, Depends, HTTPException, Request

from core.auth import get_access_payload
from core.client_ip import client_ip
from core.rate_limit import (
    is_auth_blocked_async,
    register_auth_attempt_async,
    check_refresh_rate_async,
    verification_request_allowed_async,
)
from core.school_networks import is_school_ip
from models.session import Session
from models.user import User
from schemas.auth import LoginRequest, RefreshRequest
from schemas.verification import VerificationSubmitRequest
from services.audit_service import write_audit
from services.auth_service import login_user, rotate_tokens, user_by_login
from services.verification_service import submit_request

from core.exceptions import banned_exception

router = APIRouter()


@router.post("/verification-request")
async def request_account(data: VerificationSubmitRequest, request: Request):
    ip = client_ip(request)
    from_school = is_school_ip(ip)

    if not await verification_request_allowed_async(ip, data.login, from_school):
        raise HTTPException(
            status_code=429,
            detail="Слишком много заявок. Попробуйте позже.",
        )

    req = await submit_request(
        login=data.login,
        password=data.password,
        first_name=data.first_name,
        last_name=data.last_name,
        class_number=data.class_number,
        class_letter=data.class_letter,
        contact_method=data.contact_method,
        submitter_ip=ip,
    )
    await write_audit(
        "verification.submitted",
        actor=None,
        target_type="verification_request",
        target_id=str(req.id),
        building=req.building,
        ip=ip,
        user_agent=request.headers.get("user-agent", ""),
        meta={"login": req.login},
    )
    return {
        "status": "pending",
        "id": req.id,
        "login": req.login,
        "building": req.building,
        "message": "Заявка принята. Доступ откроется после проверки оператором.",
    }


@router.post("/login")
async def login(data: LoginRequest, request: Request):
    ip = client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    from_school = is_school_ip(ip)

    if await is_auth_blocked_async(ip, data.login, from_school):
        raise HTTPException(status_code=429, detail="Too many attempts")

    result = await login_user(data.login, data.password, ip, user_agent)

    if result == "banned":
        u = await user_by_login(data.login)
        await write_audit(
            "user.login_denied_banned",
            actor=None,
            target_type="user",
            target_id=str(u.id) if u else None,
            ip=ip,
            user_agent=user_agent,
            success=False,
            meta={"login": data.login},
        )
        raise banned_exception(u.ban_reason if u else None)

    if not result:
        await register_auth_attempt_async(ip, data.login, success=False, from_school=from_school)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    await register_auth_attempt_async(ip, data.login, success=True, from_school=from_school)

    access, refresh, session = result

    u = await User.get_or_none(id=session.user_id)
    if not u:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    await write_audit(
        "user.login",
        actor=u,
        target_type="user",
        target_id=str(u.id),
        building=u.building,
        ip=ip,
        user_agent=user_agent,
    )

    return {
        "access_token": access,
        "refresh_token": refresh,
    }


@router.post("/refresh")
async def refresh(request: Request, data: RefreshRequest):
    ip = client_ip(request)
    from_school = is_school_ip(ip)

    if not await check_refresh_rate_async(ip, from_school):
        raise HTTPException(
            status_code=429,
            detail="Слишком много запросов. Попробуйте позже.",
        )

    tokens = await rotate_tokens(data.refresh_token)
    if not tokens:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired refresh token",
        )
    access, refresh = tokens
    return {
        "access_token": access,
        "refresh_token": refresh,
    }


@router.post("/logout")
async def logout(payload: dict = Depends(get_access_payload)):
    session = await Session.get_or_none(id=payload["sid"])

    if session:
        session.is_active = False
        await session.save()

    return {"status": "logged_out"}
