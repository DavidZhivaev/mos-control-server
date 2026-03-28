"""
Rate limiting с учётом школьной специфики.

Проблема: в школе много пользователей за одним NAT/IP (компьютерный класс).
Решение:
- Для auth endpoint - rate limiting по логину (не по IP)
- Для общих запросов - значительно увеличенные лимиты для школьных IP
- Для верификации - лимит по логину
"""
import time
import hashlib
from collections import defaultdict
from typing import Optional

from core.config import settings
from core.school_networks import is_school_ip
from core.redis_rate_limiter import (
    redis_global_limiter,
    redis_auth_limiter,
    redis_verification_limiter,
    redis_refresh_limiter,
    get_redis_client,
)


class GlobalMinuteLimiter:
    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._last_prune = time.time()

    def allow(self, key: str, max_per_minute: int) -> bool:
        now = time.time()
        arr = self._hits[key]
        arr[:] = [t for t in arr if now - t < 60.0]
        
        if len(arr) >= max_per_minute:
            return False
        
        arr.append(now)
        
        if now - self._last_prune > 300:
            self._prune_stale(now)
            self._last_prune = now
        
        return True

    def _prune_stale(self, now: float) -> None:
        dead = [k for k, v in self._hits.items() if not v or now - max(v) > 120]
        for k in dead[:20_000]:  # batches
            del self._hits[k]
    
    def get_hits(self, key: str) -> int:
        now = time.time()
        arr = self._hits.get(key, [])
        return len([t for t in arr if now - t < 60.0])


class AuthBruteforceLimiter:
    def __init__(self):
        self.failures: dict[str, list[float]] = defaultdict(list)
        self.blocked_until: dict[str, float] = {}

    def _key(self, ip: str, login: str, from_school: bool) -> str:
        ln = login.strip().lower()
        if from_school:
            return f"sch:login:{ln}"
        return f"ext:ip:{ip}:login:{ln}"

    def is_blocked(self, ip: str, login: str, from_school: bool) -> bool:
        key = self._key(ip, login, from_school)
        until = self.blocked_until.get(key)
        if until and time.time() < until:
            return True
        if until:
            del self.blocked_until[key]
        return False

    def register_attempt(
        self, ip: str, login: str, success: bool, from_school: bool
    ) -> None:
        key = self._key(ip, login, from_school)
        now = time.time()
        win = float(settings.AUTH_FAIL_WINDOW_SEC)

        if success:
            self.failures[key] = []
            self.blocked_until.pop(key, None)
            return

        self.failures[key].append(now)
        self.failures[key] = [t for t in self.failures[key] if now - t < win]
        fails = len(self.failures[key])

        cap = (
            settings.AUTH_FAIL_BLOCK_SCHOOL
            if from_school
            else settings.AUTH_FAIL_BLOCK_EXTERNAL
        )

        if fails >= cap:
            self.blocked_until[key] = now + float(settings.AUTH_FAIL_COOLDOWN_START_SEC)
        if fails >= cap * 2:
            self.blocked_until[key] = now + float(settings.AUTH_FAIL_COOLDOWN_HEAVY_SEC)
    
    def get_failures(self, ip: str, login: str, from_school: bool) -> int:
        key = self._key(ip, login, from_school)
        now = time.time()
        win = float(settings.AUTH_FAIL_WINDOW_SEC)
        arr = self.failures.get(key, [])
        return len([t for t in arr if now - t < win])


class HourlyKeyedLimiter:
    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str, max_per_hour: int) -> bool:
        now = time.time()
        arr = self._hits[key]
        arr[:] = [t for t in arr if now - t < 3600.0]
        if len(arr) >= max_per_hour:
            return False
        arr.append(now)
        return True

    def key_verification(self, ip: str, login: str, from_school: bool) -> str:
        ln = login.strip().lower()
        if from_school:
            return f"vr:sch:login:{ln}"
        return f"vr:ext:ip:{ip}:login:{ln}"


class RefreshTokenLimiter:
    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)
    
    def allow(self, ip: str, from_school: bool) -> bool:
        now = time.time()
        key = f"refresh:{ip}"
        arr = self._hits[key]
        arr[:] = [t for t in arr if now - t < 60.0]
        
        max_per_min = 60 if from_school else 20
        
        if len(arr) >= max_per_min:
            return False
        arr.append(now)
        return True


global_minute_limiter = GlobalMinuteLimiter()
auth_limiter = AuthBruteforceLimiter()
verification_hourly_limiter = HourlyKeyedLimiter()
refresh_limiter = RefreshTokenLimiter()


def check_global_rate(ip: str, endpoint: str = "") -> bool:
    from_school = is_school_ip(ip)
    lim = (
        settings.RATE_GLOBAL_PER_MIN_SCHOOL
        if from_school
        else settings.RATE_GLOBAL_PER_MIN_EXTERNAL
    )

    key = f"{ip}:{endpoint}" if from_school else ip
    
    if get_redis_client() is not None and redis_global_limiter is not None:
        return redis_global_limiter.allow(key, lim)
    
    return global_minute_limiter.allow(key, lim)


async def verification_request_allowed_async(ip: str, login: str, from_school: bool) -> bool:
    cap = (
        settings.VERIFICATION_REQUEST_PER_HOUR_SCHOOL
        if from_school
        else settings.VERIFICATION_REQUEST_PER_HOUR_EXTERNAL
    )
    key = verification_hourly_limiter.key_verification(ip, login, from_school)
    
    if get_redis_client() is not None and redis_verification_limiter is not None:
        return await redis_verification_limiter.allow(key, cap)
    
    return verification_hourly_limiter.allow(key, cap)


def verification_request_allowed(ip: str, login: str, from_school: bool) -> bool:
    cap = (
        settings.VERIFICATION_REQUEST_PER_HOUR_SCHOOL
        if from_school
        else settings.VERIFICATION_REQUEST_PER_HOUR_EXTERNAL
    )
    key = verification_hourly_limiter.key_verification(ip, login, from_school)
    return verification_hourly_limiter.allow(key, cap)


async def check_refresh_rate_async(ip: str, from_school: bool) -> bool:
    if get_redis_client() is not None and redis_refresh_limiter is not None:
        return await redis_refresh_limiter.allow(ip, from_school)
    return refresh_limiter.allow(ip, from_school)


def check_refresh_rate(ip: str, from_school: bool) -> bool:
    return refresh_limiter.allow(ip, from_school)


async def is_auth_blocked_async(ip: str, login: str, from_school: bool) -> bool:
    if get_redis_client() is not None and redis_auth_limiter is not None:
        return await redis_auth_limiter.is_blocked(ip, login, from_school)
    return auth_limiter.is_blocked(ip, login, from_school)


async def register_auth_attempt_async(
    ip: str, login: str, success: bool, from_school: bool
) -> None:
    if get_redis_client() is not None and redis_auth_limiter is not None:
        await redis_auth_limiter.register_attempt(ip, login, success, from_school)
    else:
        auth_limiter.register_attempt(ip, login, success, from_school)
