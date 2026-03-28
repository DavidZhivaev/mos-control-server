from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse

from core.config import settings


ALLOWED_ORIGINS: set[str] = set()


def _get_origin(request: Request) -> str | None:
    return request.headers.get("origin") or request.headers.get("referer", "").split("/")[2] if request.headers.get("referer") else None


def _is_safe_origin(origin: str | None, request: Request) -> bool:
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
    
    if origin in ALLOWED_ORIGINS:
        return True
    
    return False


async def csrf_check_middleware(request: Request, call_next):
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        path = request.url.path
        
        critical_paths = [
            "/admin/users/",
            "/users/",
            "/auth/",
        ]
        
        is_critical = any(path.startswith(p) for p in critical_paths)
        
        if is_critical:
            origin = _get_origin(request)
            if not _is_safe_origin(origin, request):
                if origin:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Cross-origin request blocked"},
                    )
    
    return await call_next(request)


def is_csrf_safe(request: Request) -> bool:
    origin = _get_origin(request)
    return _is_safe_origin(origin, request)
