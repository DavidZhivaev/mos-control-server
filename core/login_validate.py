import re

LOGIN_PATTERN = re.compile(r"^[a-z0-9_]{3,32}$")


def parse_strict_login(value: str) -> str:
    s = value.strip().lower()
    if not LOGIN_PATTERN.fullmatch(s):
        raise ValueError(
            "Логин: 3–32 символа, только a–z, цифры и подчёркивание, без пробелов"
        )
    return s
