from typing import Optional
from models.user import User


async def get_user_storage_quota(user: User) -> dict:
    quota_gb = user.storage_quota

    used_gb = 0.0

    available_gb = max(0, quota_gb - used_gb)
    usage_percent = (used_gb / quota_gb * 100) if quota_gb > 0 else 0

    return {
        "quota_gb": quota_gb,
        "used_gb": used_gb,
        "available_gb": available_gb,
        "usage_percent": round(usage_percent, 2),
    }


async def get_user_storage_usage(user: User) -> dict:
    details = [
        {"category": "documents", "used_gb": 0.0, "file_count": 0},
        {"category": "images", "used_gb": 0.0, "file_count": 0},
        {"category": "other", "used_gb": 0.0, "file_count": 0},
    ]

    total_used_gb = sum(d["used_gb"] for d in details)

    return {
        "total_used_gb": total_used_gb,
        "quota_gb": user.storage_quota,
        "details": details,
    }
