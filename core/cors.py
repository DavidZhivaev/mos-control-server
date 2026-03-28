from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse

from core.config import settings


ALLOWED_ORIGINS: set[str] = set()


def _get_origin(request: Request) -> str | None:
    return request.headers.get("origin") or request.headers.get("referer", "").split("/")[2] if request.headers.get("referer") else None


def _is_same_origin(origin: str | None, request: Request) -> bool:
    if not origin:
        return True

    host = request.headers.get("host", "")

    try:
        origin_parsed = urlparse(origin if origin.startswith("http") else f"https://{origin}")
        origin_host = origin_parsed.netloc.split(":")[0]
    except Exception:
        return False

    host_parsed = host.split(":")[0]

    if origin_host == host_parsed:
        return True

    return False


async def cors_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        response = JSONResponse(content="")
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-CSRF-Token, X-Request-ID"
        response.headers["Access-Control-Max-Age"] = "86400"
        return response

    response = await call_next(request)
    
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-CSRF-Token, X-Request-ID"
    response.headers["Access-Control-Expose-Headers"] = "X-Request-ID"
    
    return response


def is_csrf_safe(request: Request) -> bool:
    origin = _get_origin(request)
    return _is_same_origin(origin, request)
