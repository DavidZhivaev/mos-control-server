# mos-control-server
Бекенд проекта по управлению инфраструктурой компьютеров школы на базе операционной системы чМОС. 

## Требования

- Python 3.10+
- PostgreSQL 14+
- Redis 6+

## Установка

```bash
pip install -r requirements.txt
```

## Настройка

### 1. База данных (PostgreSQL)

Создайте базу данных и пользователя:

```sql
CREATE DATABASE mos_control;
CREATE USER mos_control WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE mos_control TO mos_control;
```

### 2. JWT ключи

Сгенерируйте пару ключей RSA:

```bash
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
```

### 3. Переменные окружения

Скопируйте `.env.example` в `.env` и настройте параметры:

```bash
cp .env.example .env
```

Основные параметры:

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `DB_ENGINE` | Тип БД (`postgresql` или `sqlite`) | `postgresql` |
| `DB_HOST` | Хост PostgreSQL | `localhost` |
| `DB_PORT` | Порт PostgreSQL | `5432` |
| `DB_NAME` | Имя базы данных | `mos_control` |
| `DB_USER` | Пользователь БД | `mos_control` |
| `DB_PASSWORD` | Пароль БД | (требуется) |
| `USE_REDIS` | Использовать Redis для rate limiting | `false` |
| `REDIS_HOST` | Хост Redis | `localhost` |
| `REDIS_PORT` | Порт Redis | `6379` |
| `TRUST_PROXY` | Доверять заголовкам прокси | `false` |
| `TRUSTED_PROXY_IPS` | Список доверенных proxy IP/CIDR | `127.0.0.1,10.0.0.0/8,...` |
| `FORCE_HTTPS` | Требовать HTTPS для write операций | `false` |

## Запуск

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Безопасность

### Валидация пароля

Требования к паролю:
- Минимум 8 символов
- Хотя бы 3 из 4 категорий: заглавные буквы, строчные буквы, цифры, специальные символы
- Не должен содержаться в списке распространённых паролей
- Не должен содержать последовательности клавиш (qwerty, asdf, 1234 и т.д.)

### Rate Limiting

- Для школьных IP: 400 запросов/минуту
- Для внешних IP: 120 запросов/минуту
- Блокировка при неудачных попытках входа: 7 для внешних, 25 для школьных IP

### HTTPS

Для включения принудительного HTTPS установите `FORCE_HTTPS=true` в `.env`.

### Proxy

Для работы за reverse proxy (nginx, traefik):
1. Установите `TRUST_PROXY=true`
2. Настройте `TRUSTED_PROXY_IPS` с IP вашего прокси

## API Documentation

После запуска документация доступна по адресам:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
