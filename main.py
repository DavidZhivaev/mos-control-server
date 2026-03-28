import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from tortoise.contrib.fastapi import register_tortoise

from api.routes.admin import internet as admin_internet
from api.routes.admin import users as admin_users
from api.routes.admin import verification_requests as admin_verification
from api.routes.audit import router as audit_router
from api.routes.auth import router as auth_router
from api.routes.meta import router as meta_router
from api.routes.public import directory as public_directory
from api.routes.stats import router as stats_router
from api.routes import system as system_routes
from api.routes.users import router as users_router
from api.routes.sessions import router as sessions_router
from api.routes.admin_sessions import router as admin_sessions_router
from api.routes.notifications import router as notifications_router
from api.routes.admin_notifications import router as admin_notifications_router
from api.routes.storage import router as storage_router
from api.routes.admin_stats import router as admin_stats_router
from api.routes.admin_personal_data import router as admin_personal_data_router
from core.config import settings
from core.csrf import csrf_check_middleware
from core.exception_handlers import setup_exception_handlers
from core.geo_middleware import GeoRestrictionMiddleware
from core.jwt_key_manager import get_jwt_key_manager
from core.logging_config import setup_logging
from core.middleware_hardening import request_hardening_middleware
from core.redis_rate_limiter import init_redis, close_redis
from core.request_logging import RequestLoggingMiddleware, SecurityHeadersMiddleware


setup_logging()

app = FastAPI(title="MOS Control Server")

app.add_middleware(GeoRestrictionMiddleware)

app.add_middleware(RequestLoggingMiddleware)

app.add_middleware(SecurityHeadersMiddleware)

ALLOWED_ORIGINS = [
    "https://mos-control.local",
    "https://mos-control.1580.ru",
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"],
    expose_headers=["X-CSRF-Token", "X-Request-Id"],
    max_age=600,
)


setup_exception_handlers(app)


@app.middleware("http")
async def https_redirect(request, call_next):
    if settings.FORCE_HTTPS:
        is_https = request.headers.get("x-forwarded-proto", "http") == "https"

        if not is_https and request.method in ("POST", "PUT", "DELETE", "PATCH"):
            return JSONResponse(
                status_code=400,
                content={"detail": "HTTPS required"},
                headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
            )

    return await call_next(request)


@app.middleware("http")
async def hardening(request, call_next):
    return await request_hardening_middleware(request, call_next)


@app.middleware("http")
async def csrf_check(request, call_next):
    return await csrf_check_middleware(request, call_next)


@app.on_event("startup")
async def startup_event():
    jwt_manager = get_jwt_key_manager()
    if not jwt_manager.load_keys():
        private_key, public_key = jwt_manager.generate_key_pair()
        jwt_manager.save_keys(private_key, public_key, settings.JWT_KEY_ID)
        jwt_manager.load_keys()

    await init_redis()


@app.on_event("shutdown")
async def shutdown_event():
    await close_redis()


app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(users_router, prefix="/users")
app.include_router(admin_users.router, prefix="/admin")
app.include_router(admin_verification.router, prefix="/admin")
app.include_router(admin_internet.router, prefix="/admin")
app.include_router(audit_router)
app.include_router(stats_router)
app.include_router(meta_router)
app.include_router(public_directory.router)
app.include_router(system_routes.router)
app.include_router(sessions_router, prefix="/users")
app.include_router(admin_sessions_router)
app.include_router(notifications_router)
app.include_router(admin_notifications_router)
app.include_router(storage_router)
app.include_router(admin_stats_router)
app.include_router(admin_personal_data_router)

register_tortoise(
    app,
    db_url=settings.DATABASE_URL,
    modules={
        "models": [
            "models.user",
            "models.session",
            "models.audit_log",
            "models.verification_request",
            "models.global_blocked_host",
            "models.user_credentials",
            "models.notification",
        ]
    },
    generate_schemas=True,
    add_exception_handlers=True,
)
