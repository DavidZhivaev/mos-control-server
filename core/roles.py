from fastapi import Depends, HTTPException, status
from core.auth import get_current_user

def require_roles(*roles):
    async def checker(user=Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(403, "Forbidden")
        return user
    return checker