import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from core.config import settings
from core.logging_config import get_security_audit_logger


class JWTKeyManager:

    def __init__(self):
        self._current_private_key: Optional[str] = None
        self._current_public_key: Optional[str] = None
        self._previous_public_key: Optional[str] = None
        self._key_id: str = settings.JWT_KEY_ID
        self._key_loaded_at: Optional[datetime] = None
        self._audit_logger = get_security_audit_logger()

    def generate_key_pair(self) -> Tuple[str, str]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return private_pem, public_pem

    def save_keys(self, private_key: str, public_key: str, key_id: str) -> None:
        base_dir = Path(__file__).resolve().parent.parent
        private_path = base_dir / f"jwt_private_{key_id}.pem"
        public_path = base_dir / f"jwt_public_{key_id}.pem"

        if os.name != 'nt':
            with open(private_path, 'w', opener=lambda path, flags: os.open(path, flags, 0o600)) as f:
                f.write(private_key)
            with open(public_path, 'w', opener=lambda path, flags: os.open(path, flags, 0o644)) as f:
                f.write(public_key)
        else:
            private_path.write_text(private_key)
            public_path.write_text(public_key)

        self._audit_logger.log_sensitive_operation(
            user_id=0,
            user_login="system",
            operation="jwt_keys_save",
            target="jwt_keys",
            ip="localhost",
            details={"private_path": str(private_path), "public_path": str(public_path)},
        )

    def load_keys(self) -> bool:
        base_dir = Path(__file__).resolve().parent.parent

        private_path = base_dir / f"jwt_private_{self._key_id}.pem"
        public_path = base_dir / f"jwt_public_{self._key_id}.pem"

        if not private_path.exists():
            private_path = base_dir / "jwt_private.pem"
        if not public_path.exists():
            public_path = base_dir / "jwt_public.pem"

        if not private_path.exists() or not public_path.exists():
            return False

        try:
            self._current_private_key = private_path.read_text()
            self._current_public_key = public_path.read_text()
            self._key_loaded_at = datetime.now(timezone.utc)

            prev_public_path = base_dir / "jwt_public_previous.pem"
            if prev_public_path.exists():
                self._previous_public_key = prev_public_path.read_text()

            return True
        except Exception as e:
            self._audit_logger.log_suspicious_activity(
                activity_type="jwt_keys_load_error",
                ip="localhost",
                details={"error": str(e), "key_id": self._key_id},
                severity="high",
            )
            return False

    def rotate_keys(self, new_key_id: Optional[str] = None) -> bool:
        if not self._current_private_key or not self._current_public_key:
            return False

        base_dir = Path(__file__).resolve().parent.parent

        prev_public_path = base_dir / "jwt_public_previous.pem"
        prev_public_path.write_text(self._current_public_key)

        new_private, new_public = self.generate_key_pair()

        if new_key_id is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            new_key_id = f"key_{timestamp}"

        self.save_keys(new_private, new_public, new_key_id)

        self._current_private_key = new_private
        self._current_public_key = new_public
        self._previous_public_key = self._current_public_key
        self._key_id = new_key_id
        self._key_loaded_at = datetime.now(timezone.utc)

        self._audit_logger.log_sensitive_operation(
            user_id=0,
            user_login="system",
            operation="jwt_keys_rotated",
            target="jwt_keys",
            ip="localhost",
            details={"new_key_id": new_key_id},
        )

        return True

    @property
    def current_private_key(self) -> str:
        if not self._current_private_key:
            raise RuntimeError("JWT private key not loaded")
        return self._current_private_key

    @property
    def current_public_key(self) -> str:
        if not self._current_public_key:
            raise RuntimeError("JWT public key not loaded")
        return self._current_public_key

    @property
    def previous_public_key(self) -> Optional[str]:
        return self._previous_public_key

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def key_loaded_at(self) -> Optional[datetime]:
        return self._key_loaded_at

    def get_key_fingerprint(self, key_pem: str) -> str:
        key_bytes = key_pem.encode('utf-8')
        return hashlib.sha256(key_bytes).hexdigest()[:16]

    def get_key_info(self) -> dict:
        info = {
            "key_id": self._key_id,
            "loaded_at": self._key_loaded_at.isoformat() if self._key_loaded_at else None,
            "current_key_fingerprint": self.get_key_fingerprint(self._current_public_key) if self._current_public_key else None,
            "has_previous_key": self._previous_public_key is not None,
        }

        if self._previous_public_key:
            info["previous_key_fingerprint"] = self.get_key_fingerprint(self._previous_public_key)

        return info


jwt_key_manager = JWTKeyManager()


def get_jwt_key_manager() -> JWTKeyManager:
    return jwt_key_manager
