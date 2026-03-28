from fastapi import Request
from fastapi.responses import JSONResponse

from core.client_ip import client_ip
from core.config import settings
from core.rate_limit import check_global_rate


async def request_hardening_middleware(request: Request, call_next):
    cl = request.headers.get("content-length")
    
    if cl is not None:
        try:
            cl_int = int(cl)
            if cl_int < 0:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Некорректный Content-Length"},
                )
            if cl_int > settings.MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Слишком большой запрос"},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Некорректный Content-Length"},
            )
    
    transfer_encoding = request.headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        return JSONResponse(
            status_code=400,
            content={"detail": "Chunked transfer encoding not allowed"},
        )
    
    ip = client_ip(request)

    endpoint = request.url.path
    if not check_global_rate(ip, endpoint):
        return JSONResponse(
            status_code=429,
            content={"detail": "Слишком много запросов. Попробуйте позже."},
        )

    return await call_next(request)
