from typing import Literal

from pydantic import BaseModel, Field, field_validator

from core.login_validate import parse_strict_login


class UserSearchRequest(BaseModel):
    query: str | None = Field(default=None, max_length=200)
    mode: Literal["short", "full"] = "short"
    building: int | None = None
    role_id: int | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class UserSelfUpdate(BaseModel):
    login: str | None = Field(default=None, min_length=3, max_length=32)
    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    middle_name: str | None = Field(default=None, max_length=100)
    contact_method: str | None = Field(default=None, max_length=500)

    @field_validator("login", mode="before")
    @classmethod
    def validate_login_optional(cls, v):
        if v is None or v == "":
            return None
        if isinstance(v, str):
            return parse_strict_login(v)
        return v


class UserPasswordChange(BaseModel):
    old_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=8, max_length=1024)


class UserAdminUpdate(BaseModel):
    login: str | None = Field(default=None, min_length=3, max_length=32)
    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    middle_name: str | None = Field(default=None, max_length=100)
    contact_method: str | None = Field(default=None, max_length=500)
    role: int | None = None
    building: int | None = Field(default=None, ge=1)
    class_number: int | None = Field(default=None, ge=1, le=12)
    class_letter: str | None = Field(default=None, max_length=1)
    is_active: bool | None = None
    can_access_personal_data: bool | None = None
    storage_quota: float | None = Field(default=None, gt=0)

    @field_validator("login", mode="before")
    @classmethod
    def validate_login_optional_admin(cls, v):
        if v is None or v == "":
            return None
        if isinstance(v, str):
            return parse_strict_login(v)
        return v


class BanRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)
