from typing import Literal

from pydantic import BaseModel, Field


class ClassTransferBody(BaseModel):
    class_number: int = Field(ge=1, le=12)
    class_letter: str = Field(min_length=1, max_length=1)
    building: int | None = Field(default=None, ge=1)


class GlobalBlockCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    note: str | None = Field(default=None, max_length=500)


class GlobalBlockPatch(BaseModel):
    is_active: bool | None = None
    note: str | None = Field(default=None, max_length=500)


class UserHostOverrideBody(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    effect: Literal["allow", "deny"]
