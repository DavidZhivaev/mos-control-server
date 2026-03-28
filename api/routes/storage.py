from fastapi import APIRouter, Depends
from core.auth import get_current_user
from models.user import User
from services.storage_service import get_user_storage_quota, get_user_storage_usage

router = APIRouter(prefix="/storage", tags=["storage"])


@router.get("/quota")
async def get_storage_quota(
    user: User = Depends(get_current_user),
):
    return await get_user_storage_quota(user)


@router.get("/usage")
async def get_storage_usage(
    user: User = Depends(get_current_user),
):
    return await get_user_storage_usage(user)
