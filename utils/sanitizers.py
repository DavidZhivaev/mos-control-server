import re
import html


LOGIN_PATTERN = re.compile(r'^[a-z0-9_.-]+$')
NAME_PATTERN = re.compile(r'^[A-Za-zА-Яа-яЁё\s\'-]+$')
CLASS_LETTER_PATTERN = re.compile(r'^[A-Za-zА-Яа-яЁё]$')

HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
SCRIPT_PATTERN = re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
EVENT_HANDLER_PATTERN = re.compile(r'on\w+\s*=', re.IGNORECASE)


def sanitize_string(value: str, max_length: int = 500) -> str:
    if not isinstance(value, str):
        return ""
    
    value = value.strip()
    
    value = value[:max_length]
    
    value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
    
    return value


def sanitize_html_free(value: str, max_length: int = 500) -> str:
    value = sanitize_string(value, max_length)
    value = HTML_TAG_PATTERN.sub('', value)
    value = EVENT_HANDLER_PATTERN.sub('', value)
    
    return value


def sanitize_name(value: str, max_length: int = 100) -> str:
    value = sanitize_string(value, max_length)
    
    if not NAME_PATTERN.match(value):
        value = re.sub(r'[^A-Za-zА-Яа-яЁё\s\'-]', '', value)
    
    value = re.sub(r'\s+', ' ', value)
    
    return value.strip()


def sanitize_login(value: str, max_length: int = 32) -> str:
    value = value.strip().lower()[:max_length]
    
    value = re.sub(r'[^a-z0-9_.-]', '', value)
    
    if not LOGIN_PATTERN.match(value):
        raise ValueError("Логин должен содержать только буквы, цифры, _, ., -")
    
    return value


def sanitize_class_letter(value: str) -> str:
    if not value:
        return ""
    value = value.strip().upper()[:1]
    
    if not CLASS_LETTER_PATTERN.match(value):
        return ""
    
    ru_to_en = {'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 
                'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 
                'У': 'Y', 'Х': 'X'}
    return ru_to_en.get(value, value)


def sanitize_contact_method(value: str | None, max_length: int = 500) -> str | None:
    if not value:
        return None
    
    value = sanitize_html_free(value, max_length)
    
    value = re.sub(r'[\x00-\x1F\x7F]', '', value)
    
    return value if value else None


def validate_email(value: str) -> bool:
    if not value or len(value) > 254:
        return False
    
    if '@' not in value:
        return False
    
    parts = value.rsplit('@', 1)
    if len(parts) != 2:
        return False
    
    local, domain = parts
    
    if not local or len(local) > 64:
        return False
    
    if not domain or '.' not in domain:
        return False
    
    domain_parts = domain.split('.')
    if any(len(p) == 0 for p in domain_parts):
        return False
    
    if len(domain_parts[-1]) < 2:
        return False
    
    return True


def validate_phone(value: str) -> bool:
    if not value:
        return False
    
    digits_only = re.sub(r'[^\d]', '', value)
    
    if len(digits_only) < 10 or len(digits_only) > 15:
        return False
    
    if not re.match(r'^[\d\s()+-]+$', value):
        return False
    
    return True


def truncate_words(text: str, max_words: int) -> str:
    words = text.split()
    if len(words) <= max_words:
        return text
    return ' '.join(words[:max_words])
