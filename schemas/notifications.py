from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime


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
    is_system: bool = True


class NotificationResponse(BaseModel):
    id: int
    title: str
    message: str
    is_read: bool
    is_system: bool
    created_at: str
    read_at: str | None = None
    created_by_id: int | None = None
