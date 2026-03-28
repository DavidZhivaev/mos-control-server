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
from core.config import settings
from core.csrf import csrf_check_middleware
from core.exception_handlers import setup_exception_handlers
from core.logging_config import setup_logging
from core.middleware_hardening import request_hardening_middleware
from core.redis_rate_limiter import init_redis, close_redis


setup_logging()

app = FastAPI(title="MOS Control Server")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


setup_exception_handlers(app)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    
    is_https = request.headers.get("x-forwarded-proto", "http") == "https"
    force_https = settings.FORCE_HTTPS or is_https
    
    if force_https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    return response


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

# Регистрация БД
# Используем DATABASE_URL из конфига (поддерживает SQLite и PostgreSQL)
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
        ]
    },
    generate_schemas=True,
    add_exception_handlers=True,
)
