import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from core.config import settings


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
    
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    if settings.LOG_FILE:
        log_path = Path(settings.LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    logging.getLogger('uvicorn.access').setLevel(logging.WARNING)
    logging.getLogger('tortoise').setLevel(logging.WARNING)


class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
        
        self.logger.propagate = False
        
        if settings.LOG_AUDIT_FILE:
            audit_path = Path(settings.LOG_AUDIT_FILE)
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            
            handler = RotatingFileHandler(
                audit_path,
                maxBytes=50 * 1024 * 1024,
                backupCount=10,
                encoding='utf-8'
            )
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)
        
        if settings.LOG_LEVEL == "DEBUG":
            console = logging.StreamHandler()
            console.setFormatter(logging.Formatter('[AUDIT] %(message)s'))
            self.logger.addHandler(console)
    
    def log(
        self,
        event: str,
        actor_id: Optional[int],
        actor_login: Optional[str],
        target_type: str,
        target_id: Optional[str],
        action: str,
        ip: str,
        user_agent: str,
        building: Optional[int] = None,
        success: bool = True,
        meta: Optional[dict[str, Any]] = None,
    ) -> None:
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": event,
            "actor": {
                "id": actor_id,
                "login": actor_login,
            },
            "target": {
                "type": target_type,
                "id": target_id,
            },
            "action": action,
            "context": {
                "ip": ip,
                "user_agent": user_agent,
                "building": building,
            },
            "success": success,
            "meta": meta or {},
        }
        
        try:
            self.logger.info(json.dumps(entry, ensure_ascii=False))
        except Exception:
            pass


audit_logger = AuditLogger()


def get_audit_logger() -> AuditLogger:
    return audit_logger
