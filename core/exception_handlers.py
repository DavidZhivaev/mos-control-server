import logging
import traceback
from typing import Union

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from tortoise.exceptions import IntegrityError, DoesNotExist
from jose.exceptions import JWTError

from services.audit_service import write_audit


logger = logging.getLogger(__name__)


def setup_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, 
        exc: HTTPException
    ) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error(
                f"Server error: {exc.status_code} | {request.method} {request.url} | {exc.detail}",
                exc_info=True
            )
        
        if exc.status_code in (401, 403):
            await write_audit(
                f"http.error.{exc.status_code}",
                actor=None,
                target_type="http",
                target_id=str(exc.status_code),
                ip=request.client.host if request.client else "",
                user_agent=request.headers.get("user-agent", ""),
                success=False,
                meta={"path": request.url.path, "method": request.method},
            )
        
        detail = exc.detail
        
        if exc.status_code in (401, 403):
            if isinstance(detail, dict):
                pass
            else:
                detail = {
                    "code": "ACCESS_DENIED" if exc.status_code == 403 else "UNAUTHORIZED",
                    "message": "Доступ запрещён" if exc.status_code == 403 else "Необходима авторизация",
                }
        
        if exc.status_code == 404:
            detail = {"code": "NOT_FOUND", "message": "Ресурс не найден"}
        
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": detail} if isinstance(detail, str) else detail,
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError
    ) -> JSONResponse:
        logger.debug(f"Validation error: {exc.errors()}")
        
        errors = exc.errors()
        for error in errors:
            loc = error.get("loc", [])
            msg = error.get("msg", "")
            
            if any(kw in msg.lower() for kw in ["sql", "injection", "drop", "delete"]):
                logger.warning(
                    f"Suspicious validation input: {loc} | {msg} | {request.client.host}"
                )
        
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "VALIDATION_ERROR",
                    "message": "Ошибка валидации данных",
                    "errors": [
                        {"field": ".".join(str(x) for x in e["loc"]), "message": e["msg"]}
                        for e in errors
                    ]
                }
            },
        )
    
    @app.exception_handler(ValidationError)
    async def pydantic_validation_exception_handler(
        request: Request,
        exc: ValidationError
    ) -> JSONResponse:
        logger.debug(f"Pydantic validation error: {exc.errors()}")
        
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "VALIDATION_ERROR",
                    "message": "Ошибка валидации данных",
                }
            },
        )
    
    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(
        request: Request,
        exc: IntegrityError
    ) -> JSONResponse:
        logger.error(f"Integrity error: {exc}", exc_info=True)
        
        return JSONResponse(
            status_code=400,
            content={
                "detail": {
                    "code": "DATABASE_ERROR",
                    "message": "Ошибка базы данных",
                }
            },
        )
    
    @app.exception_handler(DoesNotExist)
    async def does_not_exist_handler(
        request: Request,
        exc: DoesNotExist
    ) -> JSONResponse:
        logger.debug(f"Object does not exist: {exc}")
        
        return JSONResponse(
            status_code=404,
            content={
                "detail": {
                    "code": "NOT_FOUND",
                    "message": "Ресурс не найден",
                }
            },
        )
    
    @app.exception_handler(JWTError)
    async def jwt_error_handler(
        request: Request,
        exc: JWTError
    ) -> JSONResponse:
        await write_audit(
            "auth.jwt_error",
            actor=None,
            target_type="jwt",
            target_id=None,
            ip=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", ""),
            success=False,
            meta={"error_type": type(exc).__name__},
        )
        
        logger.debug(f"JWT error: {exc}")
        
        return JSONResponse(
            status_code=401,
            content={
                "detail": {
                    "code": "INVALID_TOKEN",
                    "message": "Неверный токен",
                }
            },
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(
        request: Request,
        exc: Exception
    ) -> JSONResponse:
        logger.error(
            f"Unhandled exception: {type(exc).__name__}: {exc}\n"
            f"Traceback:\n{traceback.format_exc()}",
            exc_info=True
        )
        
        await write_audit(
            "system.error",
            actor=None,
            target_type="system",
            target_id=None,
            ip=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", ""),
            success=False,
            meta={
                "error_type": type(exc).__name__,
                "path": str(request.url),
                "method": request.method,
            },
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "detail": {
                    "code": "INTERNAL_ERROR",
                    "message": "Внутренняя ошибка сервера",
                }
            },
        )
