from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt
from jose.exceptions import JWTError

from core.config import settings
from core.jwt_key_manager import get_jwt_key_manager

ALGORITHM = "RS256"


def create_tokens(user_id: int, session_id: str, refresh_version: int):
    key_manager = get_jwt_key_manager()
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
        "kid": key_manager.key_id,
    }

    access_payload = {
        **base,
        "exp": int(access_exp.timestamp()),
        "type": "access",
    }
    access_token = jwt.encode(
        access_payload, key_manager.current_private_key, algorithm=ALGORITHM
    )

    refresh_payload = {
        **base,
        "exp": int(refresh_exp.timestamp()),
        "type": "refresh",
    }
    refresh_token = jwt.encode(
        refresh_payload, key_manager.current_private_key, algorithm=ALGORITHM
    )

    return access_token, refresh_token


def decode_jwt(token: str) -> dict:
    key_manager = get_jwt_key_manager()

    try:
        return jwt.decode(
            token,
            key_manager.current_public_key,
            algorithms=[ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
    except JWTError:
        pass

    if key_manager.previous_public_key:
        try:
            return jwt.decode(
                token,
                key_manager.previous_public_key,
                algorithms=[ALGORITHM],
                audience=settings.JWT_AUDIENCE,
                issuer=settings.JWT_ISSUER,
            )
        except JWTError:
            pass

    try:
        unverified = jwt.get_unverified_claims(token)
        kid = unverified.get("kid")

        if kid and kid != key_manager.key_id:
            pass
    except Exception:
        pass

    return jwt.decode(
        token,
        key_manager.current_public_key,
        algorithms=[ALGORITHM],
        audience=settings.JWT_AUDIENCE,
        issuer=settings.JWT_ISSUER,
    )
