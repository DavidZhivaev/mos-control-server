import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from utils.sanitizers import (
    sanitize_login,
    sanitize_name,
    sanitize_class_letter,
    sanitize_contact_method,
    validate_email,
    validate_phone,
)


MAX_PASSWORD_LENGTH = 128


class UserSearchRequest(BaseModel):
    query: str | None = Field(default=None, max_length=200)
    mode: Literal["short", "full"] = "short"
    building: int | None = None
    role_id: int | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
    
    @field_validator("query", mode="before")
    @classmethod
    def sanitize_query(cls, v):
        if isinstance(v, str):
            v = re.sub(r'<[^>]+>', '', v)
            return v[:200]
        return v


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
            try:
                return sanitize_login(v)
            except ValueError:
                return None
        return v
    
    @field_validator("first_name", "last_name", "middle_name", mode="before")
    @classmethod
    def sanitize_names(cls, v):
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


class UserPasswordChange(BaseModel):
    old_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=8, max_length=MAX_PASSWORD_LENGTH)
    
    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v):
        pwd = v.lower()
        weak_passwords = {'password', '123456', 'qwerty', 'admin', 
                         '123456789', '111111', '123123', 'qwerty123'}
        if pwd in weak_passwords:
            raise ValueError("Слишком простой пароль")
        if len(set(pwd)) < 4:
            raise ValueError("Пароль слишком простой")
        return v
    
    @model_validator(mode='after')
    def check_passwords_different(self):
        if self.old_password == self.new_password:
            raise ValueError("Новый пароль должен отличаться от старого")
        return self


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
            try:
                return sanitize_login(v)
            except ValueError:
                return None
        return v
    
    @field_validator("first_name", "last_name", "middle_name", mode="before")
    @classmethod
    def sanitize_names(cls, v):
        if isinstance(v, str):
            return sanitize_name(v, max_length=100) or None
        return v
    
    @field_validator("class_letter", mode="before")
    @classmethod
    def validate_class_letter(cls, v):
        if isinstance(v, str):
            return sanitize_class_letter(v) or None
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


class BanRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)
    
    @field_validator("reason", mode="before")
    @classmethod
    def sanitize_reason(cls, v):
        if isinstance(v, str):
            return re.sub(r'<[^>]+>', '', v)
        return v
