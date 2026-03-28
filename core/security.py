from jose import jwt
from datetime import datetime, timedelta
from core.config import settings
import uuid

ALGORITHM = "RS256"


def create_tokens(user_id: int, session_id: str):
    now = datetime.utcnow()

    access_exp = now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)
    refresh_exp = now + timedelta(seconds=settings.REFRESH_TOKEN_TTL)
    max_exp = now + timedelta(seconds=settings.MAX_TOKEN_LIFETIME)

    payload = {
        "sub": str(user_id),
        "sid": session_id,
        "iat": now.timestamp(),
        "exp": access_exp.timestamp(),
        "max_exp": max_exp.timestamp(),
        "type": "access"
    }

    access_token = jwt.encode(payload, settings.JWT_PRIVATE_KEY, algorithm=ALGORITHM)

    refresh_payload = payload.copy()
    refresh_payload["exp"] = refresh_exp.timestamp()
    refresh_payload["type"] = "refresh"

    refresh_token = jwt.encode(refresh_payload, settings.JWT_PRIVATE_KEY, algorithm=ALGORITHM)

    return access_token, refresh_token