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
- `DELETE /users/{user_id}` — Удаление аккаунта **(оператор+, нельзя удалить свой)**

## Users Sessions
- `GET /users/sessions/me` — Список активных сессий пользователя
- `DELETE /users/sessions/me/{session_id}` — Завершить сессию
- `POST /users/sessions/me/revoke-all` — Завершить все сессии

## Notifications
- `GET /notifications` — Список уведомлений
- `GET /notifications/unread-count` — Количество непрочитанных уведомлений
- `PATCH /notifications/{id}/read` — Отметить уведомление прочитанным
- `DELETE /notifications/{id}` — Удалить уведомление

## Storage
- `GET /storage/quota` — Информация о квоте хранилища
- `GET /storage/usage` — Детальное использование хранилища

## Admin Users
- `GET /admin/users/banned` — Список забаненных
- `POST /admin/users/{user_id}/ban` — Бан пользователя
- `POST /admin/users/{user_id}/unban` — Разбан пользователя
- `PATCH /admin/users/{user_id}` — Редактирование пользователя
- `POST /admin/users/{user_id}/class` — Перевод между классами
- `DELETE /admin/users/{user_id}` — Удаление пользователя
- `POST /admin/users/{user_id}/reset-password` — Сброс пароля пользователя
- `POST /admin/users/{user_id}/password` — Установка пароля пользователя **(админ школы+)**
- `GET /admin/users/{user_id}/sessions` — Сессии пользователя **(оператор+)**
- `POST /admin/users/{user_id}/sessions/revoke-all` — Завершить все сессии пользователя **(оператор+)**
- `GET /admin/users/{user_id}/personal-data-access` — Статус доступа к персональным данным **(только разработчик/админ школы)**
- `POST /admin/users/{user_id}/personal-data-access` — Выдать доступ к персональным данным **(только разработчик/админ школы)**
- `DELETE /admin/users/{user_id}/personal-data-access` — Отозвать доступ к персональным данным **(только разработчик/админ школы)**

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

## Admin Sessions
- `GET /admin/sessions` — Все активные сессии
- `DELETE /admin/sessions/{session_id}` — Принудительно завершить сессию

## Admin Notifications
- `POST /admin/notifications/broadcast` — Массовая рассылка уведомлений

## Admin Stats
- `GET /admin/stats/buildings` — Статистика по зданиям
- `GET /admin/stats/active-users` — Топ активных пользователей
- `GET /admin/stats/audit/actions` — Список audit-действий

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