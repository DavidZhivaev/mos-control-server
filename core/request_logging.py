import time
import uuid
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from core.logging_config import (
    set_request_context,
    clear_request_context,
    generate_request_id,
    get_performance_logger,
    get_security_audit_logger,
)
from core.data_protection import data_masker


class RequestLoggingMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        request_id = generate_request_id()

        set_request_context(request_id=request_id)

        client_ip = request.client.host if request.client else "unknown"

        start_time = time.time()

        try:
            response: Response = await call_next(request)

            duration_ms = (time.time() - start_time) * 1000

            perf_logger = get_performance_logger()
            perf_logger.log_request_time(
                method=request.method,
                path=request.url.path,
                duration_ms=duration_ms,
                status_code=response.status_code,
            )

            response.headers["X-Request-ID"] = request_id

            if response.status_code >= 400:
                security_logger = get_security_audit_logger()
                security_logger.log_access(
                    user_id=0,
                    user_login="anonymous",
                    resource=request.url.path,
                    action=f"{request.method} {response.status_code}",
                    ip=client_ip,
                    success=False,
                )

            return response

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000

            perf_logger = get_performance_logger()
            perf_logger.log_request_time(
                method=request.method,
                path=request.url.path,
                duration_ms=duration_ms,
                status_code=500,
            )

            security_logger = get_security_audit_logger()
            security_logger.log_suspicious_activity(
                activity_type="request_error",
                ip=client_ip,
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                },
                severity="high" if request.method in ("POST", "PUT", "DELETE") else "medium"
            )

            raise

        finally:
            clear_request_context()


class SlowRequestMiddleware(BaseHTTPMiddleware):

    SLOW_THRESHOLD_MS = 1000

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        response = await call_next(request)

        duration_ms = (time.time() - start_time) * 1000

        if duration_ms > self.SLOW_THRESHOLD_MS:
            perf_logger = get_performance_logger()
            perf_logger.log_request_time(
                method=request.method,
                path=request.url.path,
                duration_ms=duration_ms,
                status_code=response.status_code,
            )

        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer-strict"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        is_https = request.headers.get("x-forwarded-proto", "http") == "https"
        if is_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        content_type = response.headers.get("content-type", "")
        if "text/html" in content_type:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "frame-ancestors 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        return response
