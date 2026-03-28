from pydantic import BaseSettings

class Settings(BaseSettings):
    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str

    ACCESS_TOKEN_TTL: int = 2 * 24 * 3600
    REFRESH_TOKEN_TTL: int = 5 * 24 * 3600
    MAX_TOKEN_LIFETIME: int = 14 * 24 * 3600

settings = Settings()