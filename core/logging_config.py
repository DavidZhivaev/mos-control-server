import json
import logging
import os
import re
import sys
import traceback
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Optional, Dict
from contextvars import ContextVar

from core.config import settings


request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
user_id_ctx: ContextVar[Optional[int]] = ContextVar("user_id", default=None)
user_login_ctx: ContextVar[Optional[str]] = ContextVar("user_login", default=None)


SENSITIVE_PATTERNS = [
    (re.compile(r'\b\d{10,14}\b'), '***CARD***'),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '***EMAIL***'),
    (re.compile(r'\b[\d\s()+-]{10,}\b'), '***PHONE***'),
    (re.compile(r'password["\']?\s*[:=]\s*["\']?[^"\',\s]+', re.IGNORECASE), 'password=***REDACTED***'),
    (re.compile(r'token["\']?\s*[:=]\s*["\']?[A-Za-z0-9._-]+', re.IGNORECASE), 'token=***REDACTED***'),
    (re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9._-]+', re.IGNORECASE), 'api_key=***REDACTED***'),
    (re.compile(r'secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9._-]+', re.IGNORECASE), 'secret=***REDACTED***'),
    (re.compile(r'Bearer\s+[A-Za-z0-9._-]+', re.IGNORECASE), 'Bearer ***REDACTED***'),
]


def mask_sensitive_data(data: str) -> str:
    for pattern, replacement in SENSITIVE_PATTERNS:
        data = pattern.sub(replacement, data)
    return data


def mask_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    masked = {}
    sensitive_keys = {'password', 'token', 'secret', 'api_key', 'apikey', 'auth', 'authorization', 'cookie'}

    for key, value in data.items():
        key_lower = key.lower()

        if any(s in key_lower for s in sensitive_keys):
            masked[key] = '***REDACTED***'
        elif isinstance(value, str):
            masked[key] = mask_sensitive_data(value)
        elif isinstance(value, dict):
            masked[key] = mask_dict(value)
        elif isinstance(value, list):
            masked[key] = [
                mask_sensitive_data(item) if isinstance(item, str) else item
                for item in value
            ]
        else:
            masked[key] = value

    return masked


class JSONFormatter(logging.Formatter):

    def __init__(self, include_context: bool = True):
        super().__init__()
        self.include_context = include_context

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": mask_sensitive_data(record.getMessage()),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if self.include_context:
            request_id = request_id_ctx.get()
            user_id = user_id_ctx.get()
            user_login = user_login_ctx.get()

            if request_id:
                log_data["request_id"] = request_id
            if user_id:
                log_data["user_id"] = user_id
            if user_login:
                log_data["user_login"] = user_login

        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info),
            }

        for key, value in record.__dict__.items():
            if key not in {
                'name', 'msg', 'args', 'created', 'filename', 'funcName',
                'levelname', 'levelno', 'lineno', 'module', 'msecs',
                'pathname', 'process', 'processName', 'relativeCreated',
                'stack_info', 'exc_info', 'exc_text', 'thread', 'threadName',
                'message', 'asctime'
            }:
                if isinstance(value, dict):
                    log_data[key] = mask_dict(value)
                elif isinstance(value, str):
                    log_data[key] = mask_sensitive_data(value)
                else:
                    log_data[key] = value

        return json.dumps(log_data, ensure_ascii=False, default=str)


class ColoredConsoleFormatter(logging.Formatter):

    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        request_id = request_id_ctx.get()
        user_id = user_id_ctx.get()

        context = ""
        if request_id:
            context += f" [req:{request_id[:8]}]"
        if user_id:
            context += f" [user:{user_id}]"

        return (
            f"{color}{record.levelname:8s}{self.RESET} | "
            f"{recordasctime} | "
            f"{recordname}{context} | "
            f"{mask_sensitive_data(record.getMessage())}"
        )


def _ensure_log_dir() -> None:
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    if os.name != 'nt':
        try:
            os.chmod(log_dir, 0o750)
        except OSError:
            pass


def setup_logging() -> None:
    _ensure_log_dir()

    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = ColoredConsoleFormatter(
        '%(asctime)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    if settings.LOG_FILE:
        log_path = Path(settings.LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=50 * 1024 * 1024,
            backupCount=10,
            encoding='utf-8',
            delay=True
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(JSONFormatter(include_context=True))
        root_logger.addHandler(file_handler)

        error_path = log_path.parent / f"error_{log_path.stem}.log"
        error_handler = TimedRotatingFileHandler(
            error_path,
            when='D',
            interval=1,
            backupCount=30,
            encoding='utf-8',
            delay=True
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(JSONFormatter(include_context=True))
        root_logger.addHandler(error_handler)

    logging.getLogger('uvicorn.access').setLevel(logging.WARNING)
    logging.getLogger('tortoise').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    logger = logging.getLogger(__name__)
    logger.info("Система логирования инициализирована", extra={
        "log_level": settings.LOG_LEVEL,
        "log_file": settings.LOG_FILE,
    })


class SecurityAuditLogger:

    def __init__(self):
        self.logger = logging.getLogger('security_audit')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        if settings.LOG_AUDIT_FILE:
            audit_path = Path(settings.LOG_AUDIT_FILE)
            audit_path.parent.mkdir(parents=True, exist_ok=True)

            handler = RotatingFileHandler(
                audit_path,
                maxBytes=100 * 1024 * 1024,
                backupCount=30,
                encoding='utf-8',
                delay=True
            )
            handler.setFormatter(JSONFormatter(include_context=True))
            self.logger.addHandler(handler)

    def log_auth_attempt(
        self,
        login: str,
        success: bool,
        ip: str,
        user_agent: str,
        reason: Optional[str] = None,
    ) -> None:
        self.logger.info(
            f"Auth attempt: {'success' if success else 'failed'} for {login}",
            extra={
                "event": "auth_attempt",
                "login": mask_sensitive_data(login),
                "success": success,
                "ip": ip,
                "user_agent": user_agent,
                "reason": reason,
            }
        )

    def log_access(
        self,
        user_id: int,
        user_login: str,
        resource: str,
        action: str,
        ip: str,
        success: bool = True,
    ) -> None:
        self.logger.info(
            f"Access: {user_login} -> {action} {resource}",
            extra={
                "event": "access",
                "user_id": user_id,
                "user_login": user_login,
                "resource": resource,
                "action": action,
                "ip": ip,
                "success": success,
            }
        )

    def log_sensitive_operation(
        self,
        user_id: int,
        user_login: str,
        operation: str,
        target: str,
        ip: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.logger.warning(
            f"Sensitive operation: {operation} by {user_login}",
            extra={
                "event": "sensitive_operation",
                "user_id": user_id,
                "user_login": user_login,
                "operation": operation,
                "target": target,
                "ip": ip,
                "details": mask_dict(details) if details else None,
            }
        )

    def log_suspicious_activity(
        self,
        activity_type: str,
        ip: str,
        details: Dict[str, Any],
        severity: str = "medium",
    ) -> None:
        self.logger.warning(
            f"Suspicious activity: {activity_type} from {ip}",
            extra={
                "event": "suspicious_activity",
                "activity_type": activity_type,
                "ip": ip,
                "severity": severity,
                "details": mask_dict(details),
            }
        )


class PerformanceLogger:

    def __init__(self):
        self.logger = logging.getLogger('performance')
        self.logger.setLevel(logging.INFO)

        if settings.LOG_FILE:
            log_path = Path(settings.LOG_FILE)
            perf_path = log_path.parent / f"performance_{log_path.stem}.log"

            handler = RotatingFileHandler(
                perf_path,
                maxBytes=50 * 1024 * 1024,
                backupCount=7,
                encoding='utf-8',
                delay=True
            )
            handler.setFormatter(JSONFormatter(include_context=False))
            self.logger.addHandler(handler)

    def log_request_time(
        self,
        method: str,
        path: str,
        duration_ms: float,
        status_code: int,
        user_id: Optional[int] = None,
    ) -> None:
        level = logging.WARNING if duration_ms > 1000 else logging.INFO

        self.logger.log(
            level,
            f"{method} {path} completed in {duration_ms:.2f}ms ({status_code})",
            extra={
                "event": "request_timing",
                "method": method,
                "path": path,
                "duration_ms": duration_ms,
                "status_code": status_code,
                "user_id": user_id,
            }
        )

    def log_db_query(
        self,
        query_type: str,
        table: str,
        duration_ms: float,
        rows_affected: int = 0,
    ) -> None:
        if duration_ms > 100:
            self.logger.warning(
                f"Slow query: {query_type} on {table} took {duration_ms:.2f}ms",
                extra={
                    "event": "slow_query",
                    "query_type": query_type,
                    "table": table,
                    "duration_ms": duration_ms,
                    "rows_affected": rows_affected,
                }
            )


security_audit_logger = SecurityAuditLogger()
performance_logger = PerformanceLogger()


def get_security_audit_logger() -> SecurityAuditLogger:
    return security_audit_logger


def get_performance_logger() -> PerformanceLogger:
    return performance_logger


def set_request_context(
    request_id: str,
    user_id: Optional[int] = None,
    user_login: Optional[str] = None,
) -> None:
    request_id_ctx.set(request_id)
    user_id_ctx.set(user_id)
    user_login_ctx.set(user_login)


def clear_request_context() -> None:
    request_id_ctx.set(None)
    user_id_ctx.set(None)
    user_login_ctx.set(None)


def generate_request_id() -> str:
    import uuid
    return str(uuid.uuid4())
