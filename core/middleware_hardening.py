from fastapi.responses import JSONResponse
from starlette.requests import Request

from core.config import settings
from core.ip import client_ip
from core.rate_limit import check_global_rate


async def request_hardening_middleware(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > settings.MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Слишком большой запрос"},
                )
        except ValueError:
            pass

    if not check_global_rate(client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"detail": "Слишком много запросов с этого адреса"},
        )

    return await call_next(request)
