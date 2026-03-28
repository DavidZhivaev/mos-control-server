from pydantic import BaseModel, Field, field_validator

from core.login_validate import parse_strict_login


class VerificationSubmitRequest(BaseModel):
    login: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=1024)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    class_number: int = Field(ge=1, le=12)
    class_letter: str = Field(min_length=1, max_length=1)
    contact_method: str | None = Field(default=None, max_length=500)

    @field_validator("login", mode="before")
    @classmethod
    def validate_login(cls, v):
        if isinstance(v, str):
            return parse_strict_login(v)
        return v

    @field_validator("class_letter", mode="before")
    @classmethod
    def upper_letter(cls, v):
        if isinstance(v, str):
            return v.strip().upper()[:1]
        return v


class VerificationApproveRequest(BaseModel):
    middle_name: str | None = Field(default=None, max_length=100)
    contact_method: str | None = Field(default=None, max_length=500)
    building: int | None = Field(default=None, ge=1)
    role: int | None = None
    can_access_personal_data: bool | None = None
    storage_quota: float | None = Field(default=None, gt=0)


class VerificationRejectRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)
