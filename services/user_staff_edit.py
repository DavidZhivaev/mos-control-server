from datetime import datetime
from models.user import User


def mark_staff_edit(target: User, actor: User) -> None:
    if actor.id == target.id:
        return
    target.last_edited_by = actor
    target.last_edited_at = datetime.utcnow()
