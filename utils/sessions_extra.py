from models.session import Session
from models.user import User


async def invalidate_all_sessions(user: User) -> int:
    return await Session.filter(user=user, is_active=True).update(is_active=False)
