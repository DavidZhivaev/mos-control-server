from datetime import datetime, timedelta
from typing import Literal
from uuid import uuid4

import bcrypt
from jose.exceptions import JWTError

from core.config import settings
from core.security import create_tokens, decode_jwt
from models.session import Session
from models.user import User
from models.user_credentials import UserCredentials
from utils.sessions import enforce_session_limit

_dummy_digest: bytes | None = None

LoginResult = tuple[str, str, Session] | Literal["banned"] | None


def _password_bytes(password: str) -> bytes:
    return password.encode("utf-8")[:72]


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(
        _password_bytes(plain_password), bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            _password_bytes(plain_password), password_hash.encode("utf-8")
        )
    except ValueError:
        return False


def _timing_check_unknown_user(password: str) -> None:
    global _dummy_digest
    if _dummy_digest is None:
        _dummy_digest = bcrypt.hashpw(b"timing", bcrypt.gensalt())
    try:
        bcrypt.checkpw(_password_bytes(password), _dummy_digest)
    except ValueError:
        pass


async def get_password_hash(user: User) -> str | None:
    credentials = await UserCredentials.filter(user=user).first()
    
    if credentials:
        return credentials.password_hash
    
    return user.password_hash


async def set_password_hash(user: User, password_hash: str) -> None:
    credentials = await UserCredentials.filter(user=user).first()
    
    if credentials:
        if credentials.password_hash and credentials.password_hash not in credentials.password_history:
            credentials.password_history.append(credentials.password_hash)
            if len(credentials.password_history) > 5:
                credentials.password_history = credentials.password_history[-5:]
        
        credentials.password_hash = password_hash
        credentials.password_changed_at = datetime.utcnow()
        await credentials.save()
    else:
        await UserCredentials.create(
            user=user,
            password_hash=password_hash,
            password_changed_at=datetime.utcnow(),
            password_history=[],
        )
    
    if user.password_hash:
        user.password_hash = None
        await user.save()


async def check_password_history(user: User, new_hash: str) -> bool:
    credentials = await UserCredentials.filter(user=user).first()
    if not credentials:
        return True
    
    return new_hash not in credentials.password_history


async def rotate_tokens(refresh_jwt: str):
    try:
        payload = decode_jwt(refresh_jwt)
    except JWTError:
        return None

    if payload.get("type") != "refresh":
        return None

    session_id = payload["sid"]
    token_rv = int(payload.get("rv", -1))
    user_id = int(payload["sub"])

    now = datetime.utcnow()
    now_ts = now.timestamp()

    if now_ts > payload["max_exp"]:
        return None

    session = await Session.get_or_none(id=session_id)

    if not session or not session.is_active:
        return None

    if token_rv != session.refresh_version:
        if token_rv < session.refresh_version:
            session.is_active = False
            await session.save()
        return None

    if session.max_expires_at < now:
        session.is_active = False
        await session.save()
        return None

    if session.expires_at < now:
        return None

    user = await User.get_or_none(id=user_id)
    if not user or not user.is_active:
        return None
    if user.is_banned:
        session.is_active = False
        await session.save()
        return None

    session.refresh_version += 1
    session.expires_at = now + timedelta(seconds=settings.REFRESH_TOKEN_TTL)
    await session.save()

    access, refresh = create_tokens(
        user.id, str(session.id), session.refresh_version
    )
    return access, refresh


async def user_by_login(identifier: str) -> User | None:
    return await User.filter(login=identifier.strip().lower()).first()


async def login_user(
    identifier: str, password: str, ip: str, user_agent: str
) -> LoginResult:
    user = await user_by_login(identifier)

    if not user:
        _timing_check_unknown_user(password)
        return None

    password_hash = await get_password_hash(user)
    
    if not password_hash:
        _timing_check_unknown_user(password)
        return None

    try:
        valid = bcrypt.checkpw(
            _password_bytes(password), password_hash.encode("utf-8")
        )
    except ValueError:
        return None

    if not valid:
        return None

    if user.is_banned:
        return "banned"

    if not user.is_active:
        return None
    
    if user.password_hash:
        from services.user_service import migrate_password_to_credentials
        await migrate_password_to_credentials(user)

    await enforce_session_limit(user)

    session_id = str(uuid4())

    now = datetime.utcnow()

    session = await Session.create(
        id=session_id,
        user=user,
        ip=ip,
        user_agent=user_agent,
        expires_at=now + timedelta(seconds=settings.REFRESH_TOKEN_TTL),
        max_expires_at=now + timedelta(seconds=settings.MAX_TOKEN_LIFETIME),
        refresh_version=0,
    )

    access, refresh = create_tokens(user.id, session_id, session.refresh_version)

    return access, refresh, session