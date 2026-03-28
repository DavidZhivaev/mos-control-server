import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from utils.sanitizers import sanitize_class_letter


class ClassTransferBody(BaseModel):
    class_number: int = Field(ge=1, le=12)
    class_letter: str = Field(min_length=1, max_length=1)
    building: int | None = Field(default=None, ge=1)
    
    @field_validator("class_letter", mode="before")
    @classmethod
    def validate_class_letter(cls, v):
        if isinstance(v, str):
            result = sanitize_class_letter(v)
            if not result:
                raise ValueError("Буква класса должна быть от А до Я")
            return result
        return v


class GlobalBlockCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    note: str | None = Field(default=None, max_length=500)
    
    @field_validator("hostname", mode="before")
    @classmethod
    def validate_hostname(cls, v):
        if isinstance(v, str):
            v = v.strip().lower()
            if len(v) > 253:
                raise ValueError("Hostname слишком длинный")
            if not re.match(r'^[a-z0-9.-]+$', v):
                raise ValueError("Hostname содержит недопустимые символы")
            if v.startswith(('.','-')) or v.endswith(('.','-')):
                raise ValueError("Hostname не должен начинаться или заканчиваться на . или -")
            return v
        return v
    
    @field_validator("note", mode="before")
    @classmethod
    def sanitize_note(cls, v):
        if isinstance(v, str):
            return re.sub(r'<[^>]+>', '', v)[:500]
        return v


class GlobalBlockPatch(BaseModel):
    is_active: bool | None = None
    note: str | None = Field(default=None, max_length=500)
    
    @field_validator("note", mode="before")
    @classmethod
    def sanitize_note(cls, v):
        if isinstance(v, str):
            return re.sub(r'<[^>]+>', '', v)[:500]
        return v


class UserHostOverrideBody(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    effect: Literal["allow", "deny"]
    
    @field_validator("hostname", mode="before")
    @classmethod
    def validate_hostname(cls, v):
        if isinstance(v, str):
            v = v.strip().lower()
            if len(v) > 253:
                raise ValueError("Hostname слишком длинный")
            if not re.match(r'^[a-z0-9.-]+$', v):
                raise ValueError("Hostname содержит недопустимые символы")
            if v.startswith(('.','-')) or v.endswith(('.','-')):
                raise ValueError("Hostname не должен начинаться или заканчиваться на . или -")
            return v
        return v
