from datetime import datetime
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer
from jose import jwt
from core.config import settings
from models.session import Session
from models.user import User
from tortoise.exceptions import DoesNotExist

security = HTTPBearer()


async def get_current_user(token=Depends(security)):
    try:
        payload = jwt.decode(
            token.credentials,
            settings.JWT_PUBLIC_KEY,
            algorithms=["RS256"]
        )
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = int(payload["sub"])
    session_id = payload["sid"]

    try:
        session = await Session.get_or_none(id=session_id)

        if not session:
            raise HTTPException(status_code=401, detail="Session not found")
        
        if not session.is_active:
            raise HTTPException(status_code=401, detail="Session inactive")

        if session.max_expires_at < datetime.utcnow():
            session.is_active = False
            await session.save()

            raise HTTPException(status_code=401, detail="Session expired (max lifetime)")
    except DoesNotExist:
        raise HTTPException(status_code=401, detail="Session invalid")

    if session.expires_at.timestamp() < datetime.utcnow().timestamp():
        raise HTTPException(status_code=401, detail="Session expired")

    user = await User.get(id=user_id)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User disabled")

    return user