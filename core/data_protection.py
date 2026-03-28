import base64
import hashlib
import hmac
import os
import re
from typing import Optional, Dict, Any, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from core.config import settings
from core.logging_config import get_security_audit_logger


AES_KEY_SIZE = 32
NONCE_SIZE = 12
SALT_SIZE = 32
PBKDF2_ITERATIONS = 100000


def _get_encryption_key() -> bytes:
    key_b64 = os.environ.get("DATA_ENCRYPTION_KEY")

    if key_b64:
        try:
            key = base64.b64decode(key_b64)
            if len(key) == AES_KEY_SIZE:
                return key
        except Exception:
            pass

    master_secret = getattr(settings, 'MASTER_SECRET', 'default-master-secret-change-in-production')
    return _derive_key(master_secret, b"data-encryption-key-salt")


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_data(data: str, associated_data: Optional[bytes] = None) -> str:
    key = _get_encryption_key()
    aesgcm = AESGCM(key)

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), associated_data)
    encrypted = base64.b64encode(nonce + ciphertext).decode('utf-8')

    return encrypted


def decrypt_data(encrypted_data: str, associated_data: Optional[bytes] = None) -> str:
    key = _get_encryption_key()
    aesgcm = AESGCM(key)

    raw = base64.b64decode(encrypted_data)
    nonce = raw[:NONCE_SIZE]
    ciphertext = raw[NONCE_SIZE:]

    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)

    return plaintext.decode('utf-8')


def hash_sensitive_data(data: str, salt: Optional[str] = None) -> str:
    if salt is None:
        salt = base64.b64encode(os.urandom(SALT_SIZE)).decode('utf-8')

    key = _get_encryption_key()
    h = hmac.new(key, salt.encode('utf-8'), hashlib.sha256)
    h.update(data.encode('utf-8'))
    hash_value = h.hexdigest()

    return f"{salt}:{hash_value}"


def verify_hashed_data(data: str, stored_hash: str) -> bool:
    try:
        salt, expected_hash = stored_hash.split(':', 1)
        computed_hash = hash_sensitive_data(data, salt)
        _, computed = computed_hash.split(':', 1)
        return hmac.compare_digest(computed, expected_hash)
    except Exception:
        return False


class DataMasker:

    PATTERNS = {
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'phone': re.compile(r'\+?[\d\s()\-]{10,}'),
        'credit_card': re.compile(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'),
        'passport': re.compile(r'\b\d{4}\s?\d{6}\b'),
        'snils': re.compile(r'\b\d{3}-\d{3}-\d{3}\s?\d{2}\b'),
        'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    }

    @classmethod
    def mask_email(cls, email: str, show_first: int = 2, show_last: int = 5) -> str:
        if not email or '@' not in email:
            return email

        name, domain = email.rsplit('@', 1)

        if len(name) <= show_first + show_last:
            masked_name = name[0] + '***'
        else:
            masked_name = name[:show_first] + '***' + name[-show_last:]

        return f"{masked_name}@{domain}"

    @classmethod
    def mask_phone(cls, phone: str, show_last: int = 4) -> str:
        digits = re.sub(r'[^\d]', '', phone)

        if len(digits) < 10:
            return '***'

        masked = '***' + digits[-show_last:]

        if phone.startswith('+'):
            return '+' + masked
        return masked

    @classmethod
    def mask_credit_card(cls, card: str) -> str:
        digits = re.sub(r'[\s\-]', '', card)

        if len(digits) != 16:
            return '***'

        return f"{digits[:4]} **** **** {digits[-4:]}"

    @classmethod
    def mask_string(cls, data: str, show_percent: int = 20) -> str:
        if not data:
            return data

        show_percent = max(10, min(50, show_percent))
        show_count = max(1, len(data) * show_percent // 100)

        if len(data) <= 2:
            return '*' * len(data)

        show_start = show_count // 2
        show_end = show_count - show_start

        if show_start + show_end >= len(data):
            return '*' * len(data)

        return data[:show_start] + '*' * (len(data) - show_start - show_end) + data[-show_end:]

    @classmethod
    def mask_dict(cls, data: Dict[str, Any], sensitive_keys: Optional[List[str]] = None) -> Dict[str, Any]:
        if sensitive_keys is None:
            sensitive_keys = [
                'password', 'token', 'secret', 'api_key', 'apikey',
                'auth', 'authorization', 'cookie', 'session',
                'credit_card', 'card_number', 'passport', 'snils',
                'inn', 'ogrn', 'bank_account'
            ]

        masked = {}

        for key, value in data.items():
            key_lower = key.lower()

            if any(s in key_lower for s in sensitive_keys):
                if isinstance(value, str):
                    masked[key] = cls.mask_string(value, show_percent=10)
                elif isinstance(value, dict):
                    masked[key] = cls.mask_dict(value, sensitive_keys)
                elif isinstance(value, list):
                    masked[key] = [
                        cls.mask_string(item, show_percent=10) if isinstance(item, str) else item
                        for item in value
                    ]
                else:
                    masked[key] = '***REDACTED***'
            elif isinstance(value, str):
                masked_value = value

                for match in cls.PATTERNS['email'].finditer(masked_value):
                    masked_value = masked_value.replace(
                        match.group(), cls.mask_email(match.group())
                    )

                for match in cls.PATTERNS['phone'].finditer(masked_value):
                    masked_value = masked_value.replace(
                        match.group(), cls.mask_phone(match.group())
                    )

                for match in cls.PATTERNS['credit_card'].finditer(masked_value):
                    masked_value = masked_value.replace(
                        match.group(), cls.mask_credit_card(match.group())
                    )

                masked[key] = masked_value
            elif isinstance(value, dict):
                masked[key] = cls.mask_dict(value, sensitive_keys)
            elif isinstance(value, list):
                masked[key] = [
                    cls.mask_dict(item, sensitive_keys) if isinstance(item, dict)
                    else cls.mask_string(item, show_percent=10) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                masked[key] = value

        return masked

    @classmethod
    def mask_query_params(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        return cls.mask_dict(params)


data_masker = DataMasker()


def get_data_masker() -> DataMasker:
    return data_masker


def generate_encryption_key() -> str:
    return base64.b64encode(os.urandom(AES_KEY_SIZE)).decode('utf-8')


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
