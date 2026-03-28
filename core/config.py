import os
import stat
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


def _check_key_file_permissions(file_path: Path) -> None:
    if not file_path.exists():
        raise FileNotFoundError(f"JWT ключ не найден: {file_path}")

    if os.name == 'nt':
        file_str = str(file_path).lower()
        if 'public' in file_str or 'shared' in file_str:
            print(f"WARNING: JWT ключ в потенциально общедоступной папке: {file_path}")
        return


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    JWT_PRIVATE_KEY: str = ""
    JWT_PUBLIC_KEY: str = ""
    JWT_KEY_ID: str = "current"
    JWT_ISSUER: str = "mos-control"
    JWT_AUDIENCE: str = "mos-control-api"

    ACCESS_TOKEN_TTL: int = 2 * 24 * 3600
    REFRESH_TOKEN_TTL: int = 5 * 24 * 3600
    MAX_TOKEN_LIFETIME: int = 14 * 24 * 3600

    TRUST_PROXY: bool = True
    TRUSTED_PROXY_IPS: str = "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    FORCE_HTTPS: bool = True

    SUPPORT_EMAIL: str = "zhivaevda@1580.ru"

    SCHOOL_NETWORKS_JSON: str = (
        '[{"cidr":"94.29.124.0/24","building":1},'
        '{"cidr":"94.29.126.0/24","building":2}]'
    )

    ALLOW_VERIFICATION_OUTSIDE_SCHOOL: bool = False
    DEFAULT_BUILDING_WHEN_OUTSIDE_NETWORK: int = 1

    MAX_REQUEST_BODY_BYTES: int = 1_048_576

    RATE_GLOBAL_PER_MIN_SCHOOL: int = 400
    RATE_GLOBAL_PER_MIN_EXTERNAL: int = 120

    AUTH_FAIL_WINDOW_SEC: int = 900
    AUTH_FAIL_BLOCK_EXTERNAL: int = 7
    AUTH_FAIL_BLOCK_SCHOOL: int = 25
    AUTH_FAIL_COOLDOWN_START_SEC: int = 60
    AUTH_FAIL_COOLDOWN_HEAVY_SEC: int = 900

    VERIFICATION_REQUEST_PER_HOUR_SCHOOL: int = 5
    VERIFICATION_REQUEST_PER_HOUR_EXTERNAL: int = 2

    DATABASE_URL: str = ""

    DB_ENGINE: str = "postgresql"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "mos_control"
    DB_USER: str = "mos_control"
    DB_PASSWORD: str = ""

    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 5432
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None
    USE_REDIS: bool = False

    LOG_LEVEL: str = "INFO"
    LOG_FILE: str | None = "logs/app.log"
    LOG_AUDIT_FILE: str | None = "logs/audit.log"

    MASTER_SECRET: str = ""
    DATA_ENCRYPTION_KEY: str | None = None


settings = Settings()

if not settings.DATABASE_URL:
    if settings.DB_ENGINE == "postgresql":
        port = settings.DB_PORT or 5432
        settings.DATABASE_URL = (
            f"postgres://{settings.DB_USER}:{settings.DB_PASSWORD}@"
            f"{settings.DB_HOST}:{port}/{settings.DB_NAME}"
        )
    else:
        settings.DATABASE_URL = "sqlite://db.sqlite3"
