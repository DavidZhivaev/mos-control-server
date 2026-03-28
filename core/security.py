from datetime import datetime, timedelta, timezone

from jose import jwt

from core.config import settings

ALGORITHM = "RS256"


def create_tokens(user_id: int, session_id: str, refresh_version: int):
    now = datetime.now(timezone.utc)

    access_exp = now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)
    refresh_exp = now + timedelta(seconds=settings.REFRESH_TOKEN_TTL)
    max_exp = now + timedelta(seconds=settings.MAX_TOKEN_LIFETIME)

    base = {
        "sub": str(user_id),
        "sid": session_id,
        "rv": refresh_version,
        "iat": int(now.timestamp()),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "max_exp": int(max_exp.timestamp()),
    }

    access_payload = {
        **base,
        "exp": int(access_exp.timestamp()),
        "type": "access",
    }
    access_token = jwt.encode(
        access_payload, settings.JWT_PRIVATE_KEY, algorithm=ALGORITHM
    )

    refresh_payload = {
        **base,
        "exp": int(refresh_exp.timestamp()),
        "type": "refresh",
    }
    refresh_token = jwt.encode(
        refresh_payload, settings.JWT_PRIVATE_KEY, algorithm=ALGORITHM
    )

    return access_token, refresh_token

def decode_jwt(token: str) -> dict:
    return jwt.decode(
        token,
        settings.JWT_PUBLIC_KEY,
        algorithms=[ALGORITHM],
        audience=settings.JWT_AUDIENCE,
        issuer=settings.JWT_ISSUER,
    )
