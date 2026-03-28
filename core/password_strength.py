import re
from typing import Tuple, List


PASSWORD_BLACKLIST = {
    'password', 'password123', '123456', '12345678', '123456789',
    'qwerty', 'qwerty123', 'qwertyuiop', 'admin', 'admin123',
    '111111', '123123', '1234567890', 'abc123', 'monkey', 'master',
    'dragon', 'letmein', 'login', 'welcome', 'hello', 'shadow',
    'sunshine', 'princess', 'football', 'baseball', 'iloveyou',
    'passw0rd', 'pass123', 'pass1234', 'school', 'ученик', 'учитель',
    'москва', 'moscow', 'russia', '2024', '2025', '2026',
    'qwerty123456', '1234567', '12345', '12345678910',
    'zhivaevda', '1580', 'moscontrol', 'mos-control',
}

WEAK_PATTERNS = [
    r'(.)\1{2,}',
    r'(012|123|234|345|456|567|678|789|890)',
    r'(987|876|765|654|543|432|321|210)',
    r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
    r'(zyx|wvu|vut|uts|tsr|srq|rqp|qpo|pon|onm|nml|lkj|kji|jih|ihg|hgf|gfe|fed|edc|dcb|cba)',
    r'^[a-zA-Z]+$',
    r'^\d+$',
    r'^(qwerty|asdf|zxcv|йцукен|фыва|ячс)+',
]

MIN_LENGTH = 8
MAX_LENGTH = 128
MIN_UNIQUE_CHARS = 6


class PasswordStrengthResult:

    def __init__(self, is_valid: bool, errors: List[str], strength: str):
        self.is_valid = is_valid
        self.errors = errors
        self.strength = strength

    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "strength": self.strength,
        }


def check_password_strength(password: str) -> PasswordStrengthResult:
    errors = []
    strength_score = 0

    if len(password) < MIN_LENGTH:
        errors.append(f"Пароль должен содержать минимум {MIN_LENGTH} символов")
    elif len(password) >= 12:
        strength_score += 2
    elif len(password) >= 10:
        strength_score += 1

    if len(password) > MAX_LENGTH:
        errors.append(f"Пароль не должен превышать {MAX_LENGTH} символов")

    pwd_lower = password.lower().strip()
    if pwd_lower in PASSWORD_BLACKLIST:
        errors.append("Пароль слишком распространённый, выберите другой")

    unique_chars = len(set(password.lower()))
    if unique_chars < MIN_UNIQUE_CHARS:
        errors.append(f"Пароль слишком простой, используйте минимум {MIN_UNIQUE_CHARS} уникальных символов")

    if re.search(r'[A-ZА-ЯЁ]', password):
        strength_score += 1
    else:
        errors.append("Пароль должен содержать хотя бы одну заглавную букву")

    if re.search(r'[a-zа-яё]', password):
        strength_score += 1
    else:
        errors.append("Пароль должен содержать хотя бы одну строчную букву")

    if re.search(r'\d', password):
        strength_score += 1
    else:
        errors.append("Пароль должен содержать хотя бы одну цифру")

    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
        strength_score += 2
    else:
        errors.append("Пароль должен содержать хотя бы один специальный символ (!@#$%^&*...)")

    for pattern in WEAK_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            errors.append("Пароль содержит слишком простой паттерн")
            strength_score -= 1
            break

    if _has_sequential_chars(password):
        errors.append("Пароль содержит последовательные символы (например, 123 или abc)")

    if strength_score >= 6:
        strength = "strong"
    elif strength_score >= 4:
        strength = "medium"
    else:
        strength = "weak"

    is_valid = len(errors) == 0

    return PasswordStrengthResult(
        is_valid=is_valid,
        errors=errors,
        strength=strength,
    )


def _has_sequential_chars(password: str) -> bool:
    pwd = password.lower()

    for i in range(len(pwd) - 2):
        if pwd[i:i+3].isdigit():
            chars = [int(c) for c in pwd[i:i+3]]
            if chars[1] - chars[0] == 1 and chars[2] - chars[1] == 1:
                return True
            if chars[0] - chars[1] == 1 and chars[1] - chars[2] == 1:
                return True

    alpha = 'abcdefghijklmnopqrstuvwxyzабвгдеёжзийклмнопрстуфхцчшщъыьэюя'
    for i in range(len(pwd) - 2):
        idx = alpha.find(pwd[i])
        if idx >= 0 and i + 2 < len(pwd):
            if alpha.find(pwd[i+1]) == idx + 1 and alpha.find(pwd[i+2]) == idx + 2:
                return True
            if alpha.find(pwd[i+1]) == idx - 1 and alpha.find(pwd[i+2]) == idx - 2:
                return True

    return False


def validate_password(password: str) -> Tuple[bool, str]:
    result = check_password_strength(password)
    if result.is_valid:
        return True, ""
    return False, result.errors[0] if result.errors else "Недопустимый пароль"


def get_password_strength_label(strength: str) -> str:
    labels = {
        "weak": "Слабый",
        "medium": "Средний",
        "strong": "Надёжный",
    }
    return labels.get(strength, "Неизвестный")
