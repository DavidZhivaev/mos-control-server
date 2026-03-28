from fastapi import APIRouter, Request, HTTPException, Depends
from schemas.auth import LoginRequest
from services.auth_service import login_user
from core.rate_limit import rate_limiter
from core.auth import get_current_user
from models.session import Session
from jose import jwt
from core.config import settings
from utils.sessions import enforce_session_limit

router = APIRouter()


@router.post("/login")
async def login(data: LoginRequest, request: Request):
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    if rate_limiter.is_blocked(ip, data.email):
        raise HTTPException(status_code=429, detail="Too many attempts")

    result = await login_user(data.email, data.password, ip, user_agent)

    if not result:
        rate_limiter.register_attempt(ip, data.email, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    rate_limiter.register_attempt(ip, data.email, success=True)

    access, refresh, session = result

    return {
        "access_token": access,
        "refresh_token": refresh,
        "session_id": str(session.id)
    }

@router.post("/logout")
async def logout(token: str, user=Depends(get_current_user)):
    try:
        payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
        session_id = payload["sid"]
    except:
        raise HTTPException(status_code=401)

    session = await Session.get_or_none(id=session_id)

    if session:
        session.is_active = False
        await session.save()

    return {"status": "logged_out"}