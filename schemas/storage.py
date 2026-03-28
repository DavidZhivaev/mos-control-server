from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime


class SessionResponse(BaseModel):
    id: str
    ip: str
    user_agent: str
    created_at: str
    expires_at: str
    is_active: bool


class SessionRevokeResponse(BaseModel):
    status: Literal["revoked", "success"]
    message: str | None = None


class StorageQuotaResponse(BaseModel):
    quota_gb: float
    used_gb: float
    available_gb: float
    usage_percent: float


class StorageUsageDetail(BaseModel):
    category: str
    used_gb: float
    file_count: int


class StorageUsageResponse(BaseModel):
    total_used_gb: float
    quota_gb: float
    details: list[StorageUsageDetail]


class BuildingStats(BaseModel):
    building: int
    name: str | None = None
    user_count: int
    active_user_count: int


class ActiveUserStats(BaseModel):
    user_id: int
    login: str
    full_name: str
    building: int
    role: int
    sessions_count: int
    last_activity: str | None = None
