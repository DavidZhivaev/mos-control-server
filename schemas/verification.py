import re
from pydantic import BaseModel, Field, field_validator, model_validator

from utils.sanitizers import (
    sanitize_login,
    sanitize_name,
    sanitize_class_letter,
    sanitize_contact_method,
    validate_email,
    validate_phone,
)
from core.password_strength import check_password_strength


MAX_PASSWORD_LENGTH = 128


class VerificationSubmitRequest(BaseModel):
    login: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=MAX_PASSWORD_LENGTH)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    class_number: int = Field(ge=1, le=12)
    class_letter: str = Field(min_length=1, max_length=1)
    contact_method: str | None = Field(default=None, max_length=500)

    @field_validator("login", mode="before")
    @classmethod
    def validate_login(cls, v):
        if isinstance(v, str):
            try:
                return sanitize_login(v)
            except ValueError as e:
                raise ValueError(str(e))
        return v

    @field_validator("first_name", mode="before")
    @classmethod
    def validate_first_name(cls, v):
        if isinstance(v, str):
            return sanitize_name(v, max_length=100)
        return v

    @field_validator("last_name", mode="before")
    @classmethod
    def validate_last_name(cls, v):
        if isinstance(v, str):
            return sanitize_name(v, max_length=100)
        return v

    @field_validator("class_letter", mode="before")
    @classmethod
    def validate_class_letter(cls, v):
        if isinstance(v, str):
            result = sanitize_class_letter(v)
            if not result:
                raise ValueError("Буква класса должна быть от А до Я")
            return result
        return v

    @field_validator("contact_method", mode="before")
    @classmethod
    def validate_contact_method(cls, v):
        if isinstance(v, str):
            v = sanitize_contact_method(v)
            if v and '@' in v:
                if not validate_email(v):
                    raise ValueError("Некорректный email формат")
            elif v and re.match(r'^[\d\s()+-]+$', v):
                if not validate_phone(v):
                    raise ValueError("Некорректный телефон")
        return v

    @model_validator(mode='after')
    def check_password_strength(self):
        result = check_password_strength(self.password)
        if not result.is_valid:
            raise ValueError(result.errors[0])
        return self


class VerificationApproveRequest(BaseModel):
    middle_name: str | None = Field(default=None, max_length=100)
    contact_method: str | None = Field(default=None, max_length=500)
    building: int | None = Field(default=None, ge=1)
    role: int | None = None
    can_access_personal_data: bool | None = None
    storage_quota: float | None = Field(default=None, gt=0)
    
    @field_validator("middle_name", mode="before")
    @classmethod
    def validate_middle_name(cls, v):
        if isinstance(v, str):
            return sanitize_name(v, max_length=100) or None
        return v
    
    @field_validator("contact_method", mode="before")
    @classmethod
    def validate_contact_method(cls, v):
        if isinstance(v, str):
            v = sanitize_contact_method(v)
            if v and '@' in v:
                if not validate_email(v):
                    raise ValueError("Некорректный email формат")
            elif v and re.match(r'^[\d\s()+-]+$', v):
                if not validate_phone(v):
                    raise ValueError("Некорректный телефон")
        return v


class VerificationRejectRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)
    
    @field_validator("reason", mode="before")
    @classmethod
    def sanitize_reason(cls, v):
        if isinstance(v, str):
            return re.sub(r'<[^>]+>', '', v)
        return v
