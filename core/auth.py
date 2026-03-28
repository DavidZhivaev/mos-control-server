from datetime import datetime

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose.exceptions import JWTError

from core.exceptions import banned_exception
from core.security import decode_jwt
from models.session import Session
from models.user import User

security = HTTPBearer()


async def get_access_payload(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    try:
        payload = decode_jwt(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload


async def get_current_user(payload: dict = Depends(get_access_payload)) -> User:
    user_id = int(payload["sub"])
    session_id = payload["sid"]
    token_rv = int(payload.get("rv", -1))

    session = await Session.get_or_none(id=session_id)

    if not session:
        raise HTTPException(status_code=401, detail="Session not found")

    if not session.is_active:
        raise HTTPException(status_code=401, detail="Session inactive")

    if token_rv != session.refresh_version:
        raise HTTPException(status_code=401, detail="Token no longer valid")

    now = datetime.utcnow()

    if session.max_expires_at < now:
        session.is_active = False
        await session.save()
        raise HTTPException(status_code=401, detail="Session expired (max lifetime)")

    if session.expires_at < now:
        raise HTTPException(status_code=401, detail="Session expired")

    user = await User.get_or_none(id=user_id)

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if user.is_banned:
        raise banned_exception(user.ban_reason)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User disabled")

    return user
