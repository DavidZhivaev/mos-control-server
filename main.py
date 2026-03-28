from fastapi import FastAPI
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
from core.middleware_hardening import request_hardening_middleware

app = FastAPI(title="MOS Control Server")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.middleware("http")
async def hardening(request, call_next):
    return await request_hardening_middleware(request, call_next)


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

# ПОКА ЧТО СКУЛАЙТ, ПТТОМ КОГДА НА СЕРВАК ЗАКИНЕМ ПОМЕНЯЮ НА ПСКЛЬ!!!
register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={
        "models": [
            "models.user",
            "models.session",
            "models.audit_log",
            "models.verification_request",
            "models.global_blocked_host",
        ]
    },
    generate_schemas=True,
    add_exception_handlers=True,
)
