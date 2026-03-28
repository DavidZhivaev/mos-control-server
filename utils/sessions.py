from models.session import Session

MAX_SESSIONS = 3


async def enforce_session_limit(user):
    sessions = await Session.filter(user=user, is_active=True).order_by("created_at")

    if len(sessions) >= MAX_SESSIONS:
        to_remove = len(sessions) - MAX_SESSIONS + 1

        for s in sessions[:to_remove]:
            s.is_active = False
            await s.save()
