from pydantic import BaseModel, Field
from typing import Literal


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


class NotificationCreate(BaseModel):
    user_id: int | None = None
    title: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=2000)
    is_system: bool = False


class NotificationBroadcast(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=2000)
    building: int | None = None
    role_id: int | None = None


class NotificationResponse(BaseModel):
    id: int
    title: str
    message: str
    is_read: bool
    is_system: bool
    created_at: str
    read_at: str | None = None


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
