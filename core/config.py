from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str
    JWT_ISSUER: str = "mos-control"
    JWT_AUDIENCE: str = "mos-control-api"

    ACCESS_TOKEN_TTL: int = 2 * 24 * 3600
    REFRESH_TOKEN_TTL: int = 5 * 24 * 3600
    MAX_TOKEN_LIFETIME: int = 14 * 24 * 3600

    TRUST_PROXY: bool = False

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


settings = Settings()
