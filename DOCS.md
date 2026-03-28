# API Endpoints

## Auth
- `POST /auth/verification-request` — Заявка на регистрацию
- `POST /auth/login` — Вход в систему
- `POST /auth/refresh` — Обновление токенов
- `POST /auth/logout` — Выход из системы

## Users
- `GET /users/me` — Данные текущего пользователя
- `GET /users/me/internet/blocked` — Заблокированные хосты
- `PATCH /users/me` — Обновление профиля
- `POST /users/me/password` — Смена пароля
- `POST /users/search` — Поиск пользователей
- `GET /users/{user_id}` — Данные пользователя

## Admin Users
- `GET /admin/users/banned` — Список забаненных
- `POST /admin/users/{user_id}/ban` — Бан пользователя
- `POST /admin/users/{user_id}/unban` — Разбан пользователя
- `PATCH /admin/users/{user_id}` — Редактирование пользователя
- `POST /admin/users/{user_id}/class` — Перевод между классами
- `DELETE /admin/users/{user_id}` — Удаление пользователя

## Admin Verification
- `GET /admin/verification-requests/` — Список заявок
- `GET /admin/verification-requests/{request_id}` — Данные заявки
- `POST /admin/verification-requests/{request_id}/approve` — Одобрить заявку
- `POST /admin/verification-requests/{request_id}/reject` — Отклонить заявку

## Admin Internet
- `GET /admin/internet/global-blocks` — Глобальные блокировки
- `POST /admin/internet/global-blocks` — Создать блокировку
- `PATCH /admin/internet/global-blocks/{block_id}` — Изменить блокировку
- `DELETE /admin/internet/global-blocks/{block_id}` — Удалить блокировку
- `GET /admin/internet/users/{user_id}/overrides` — Персональные правила
- `POST /admin/internet/users/{user_id}/overrides` — Создать правило
- `DELETE /admin/internet/users/{user_id}/overrides/{override_id}` — Удалить правило

## Audit
- `GET /audit/logs` — Журнал аудита
- `GET /audit/export.ndjson` — Экспорт логов

## Stats
- `GET /stats/dashboard` — Статистика дашборда
- `GET /stats/summary` — Краткая статистика
- `GET /stats/audit/by-action` — Аудит по действиям
- `GET /stats/registrations/series` — Динамика регистраций

## Meta
- `GET /meta/roles` — Список ролей

## System
- `GET /system/api-paths` — Все API пути

## Public
- `GET /public/admins` — Список администраторов