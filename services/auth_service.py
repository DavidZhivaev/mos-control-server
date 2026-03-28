from jose import jwt
from datetime import datetime, timedelta
from core.config import settings
from core.security import ALGORITHM, create_tokens
from passlib.context import CryptContext
from datetime import datetime, timedelta
from uuid import uuid4
from models.user import User
from models.session import Session
from utils.sessions import enforce_session_limit

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def refresh_token(refresh_token: str):
    payload = jwt.decode(refresh_token, settings.JWT_PUBLIC_KEY, algorithms=[ALGORITHM])

    if payload["type"] != "refresh":
        raise Exception("Invalid token type")

    now = datetime.utcnow().timestamp()

    if now > payload["max_exp"]:
        raise Exception("Max lifetime exceeded")

    new_payload = payload.copy()
    new_payload["exp"] = now + settings.ACCESS_TOKEN_TTL
    new_payload["type"] = "access"

    return jwt.encode(new_payload, settings.JWT_PRIVATE_KEY, algorithm=ALGORITHM)


async def login_user(email: str, password: str, ip: str, user_agent: str):
    user = await User.filter(email=email).first()

    if not user:
        return None

    if not pwd_context.verify(password, user.password_hash):
        return None

    if not user.is_active:
        return None

    await enforce_session_limit(user)

    session_id = str(uuid4())

    now = datetime.utcnow()

    session = await Session.create(
        id=session_id,
        user=user,
        ip=ip,
        user_agent=user_agent,
        expires_at=now + timedelta(seconds=settings.REFRESH_TOKEN_TTL),
        max_expires_at=now + timedelta(seconds=settings.MAX_TOKEN_LIFETIME)
    )

    access, refresh = create_tokens(user.id, session_id)

    return access, refresh, session