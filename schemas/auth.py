import re
from pydantic import BaseModel, Field, field_validator


MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_LENGTH = 8

LOGIN_PATTERN = re.compile(r'^[a-z0-9_.-]+$')

COMMON_PASSWORDS = {
    'password', '123456', 'qwerty', 'admin', '123456789', '111111', 
    '123123', 'qwerty123', '12345678', '12345', '1234567', '1234567890',
    'abc123', 'password1', 'iloveyou', 'sunshine', 'princess', 'football',
    'monkey', 'shadow', 'superman', 'michael', 'trustno1', 'dragon',
    'baseball', 'master', 'access', 'letmein', 'welcome', 'hello',
    'charlie', 'donald', 'password123', 'admin123', 'root', 'toor',
    'pass', 'test', 'guest', 'master123', 'changeme', '123qwe', '123qweasdzxc',
}

KEYBOARD_PATTERNS = [
    'qwerty', 'qwertyuiop', 'asdf', 'asdfgh', 'asdfghjkl', 'zxcv', 'zxcvbn', 'zxcvbnm',
    '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
    'qazwsx', 'wsxedc', 'rfvtgb', 'tgbyhn', 'yhnujm', 'ujmik,', '1qaz', '2wsx', '3edc',
]


class LoginRequest(BaseModel):
    login: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("login", mode="before")
    @classmethod
    def normalize_login(cls, v):
        if isinstance(v, str):
            v = v.strip().lower()
            v = re.sub(r'[^a-z0-9_.-]', '', v)
            return v
        return v

    @field_validator("login")
    @classmethod
    def validate_login(cls, v):
        if not LOGIN_PATTERN.match(v):
            raise ValueError("Логин должен содержать только буквы, цифры, _, ., -")
        if len(v) < 3:
            raise ValueError("Логин должен быть не менее 3 символов")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Пароль должен быть не менее {MIN_PASSWORD_LENGTH} символов")
        
        if len(v) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Пароль не должен превышать {MAX_PASSWORD_LENGTH} символов")
        
        if v.lower() in COMMON_PASSWORDS:
            raise ValueError("Слишком простой пароль")
        
        for pattern in KEYBOARD_PATTERNS:
            if pattern in v.lower():
                raise ValueError("Пароль содержит последовательность клавиш")
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v)
        
        strength_count = sum([has_upper, has_lower, has_digit, has_special])
        if strength_count < 3:
            raise ValueError("Пароль должен содержать заглавные буквы, строчные буквы, цифры и специальные символы")
        
        return v


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=2048)
