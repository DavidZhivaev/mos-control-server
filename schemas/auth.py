from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    login: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("login", mode="before")
    @classmethod
    def normalize_login(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20)
