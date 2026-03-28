from models.user import User


async def attach_last_editor_fields(payload: dict, subject: User) -> dict:
    if subject.last_edited_at:
        payload["last_edited_at"] = subject.last_edited_at.isoformat()
    else:
        payload["last_edited_at"] = None

    if subject.last_edited_by_id:
        ed = await User.get_or_none(id=subject.last_edited_by_id)
        if ed:
            payload["last_edited_by"] = {
                "id": ed.id,
                "login": ed.login,
                "first_name": ed.first_name,
                "last_name": ed.last_name,
            }
        else:
            payload["last_edited_by"] = None
    else:
        payload["last_edited_by"] = None
    return payload
