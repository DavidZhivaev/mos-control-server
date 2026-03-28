import secrets
import hashlib
from urllib.parse import urlparse
from typing import Optional

from fastapi import Request, Header, HTTPException
from fastapi.responses import JSONResponse

from core.config import settings


ALLOWED_ORIGINS: set[str] = set()


def init_allowed_origins() -> None:
    global ALLOWED_ORIGINS
    ALLOWED_ORIGINS = {
        "mos-control.local",
        "localhost",
        "127.0.0.1",
    }


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def validate_csrf_token(token: str) -> bool:
    if not token or len(token) < 32:
        return False
    return True


def _get_origin(request: Request) -> Optional[str]:
    origin = request.headers.get("origin")
    if origin:
        return origin

    referer = request.headers.get("referer", "")
    if referer:
        try:
            parsed = urlparse(referer)
            return f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else None
        except Exception:
            return None

    return None


def _get_host(request: Request) -> str:
    return request.headers.get("host", "").split(":")[0]


def _extract_origin_domain(origin: str) -> str:
    try:
        parsed = urlparse(origin if origin.startswith("http") else f"https://{origin}")
        return parsed.netloc.split(":")[0]
    except Exception:
        return ""


def _is_same_origin(origin: str, host: str) -> bool:
    origin_domain = _extract_origin_domain(origin)
    return origin_domain == host or origin_domain == ""


def _is_allowed_origin(origin: str) -> bool:
    domain = _extract_origin_domain(origin)
    return domain in ALLOWED_ORIGINS


def _is_safe_origin(origin: Optional[str], request: Request) -> bool:
    if not origin:
        return True

    host = _get_host(request)

    if _is_same_origin(origin, host):
        return True

    if _is_allowed_origin(origin):
        return True

    return False


async def csrf_check_middleware(request: Request, call_next):
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        path = request.url.path

        critical_paths = [
            "/admin/users/",
            "/users/",
            "/auth/",
            "/admin/",
        ]

        is_critical = any(path.startswith(p) for p in critical_paths)

        if is_critical:
            origin = _get_origin(request)

            if origin and not _is_safe_origin(origin, request):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Cross-origin request blocked"},
                    headers={"X-CSRF-Error": "origin-not-allowed"}
                )

            csrf_token = request.headers.get("x-csrf-token")
            if csrf_token:
                if not validate_csrf_token(csrf_token):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Invalid CSRF token"},
                        headers={"X-CSRF-Error": "invalid-token"}
                    )

    response = await call_next(request)

    if request.method == "GET":
        token = generate_csrf_token()
        response.headers["X-CSRF-Token"] = token

    return response


def is_csrf_safe(request: Request) -> bool:
    origin = _get_origin(request)
    return _is_safe_origin(origin, request)


init_allowed_origins()
