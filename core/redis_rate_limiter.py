import time
import hashlib
from typing import Optional

import redis.asyncio as redis

from core.config import settings
from core.school_networks import is_school_ip


class RedisGlobalMinuteLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def allow(self, key: str, max_per_minute: int) -> bool:
        now = int(time.time())
        window_key = f"rate:global:{key}:{now}"
        prev_window_key = f"rate:global:{key}:{now - 1}"
        
        pipe = self.redis.pipeline()
        pipe.incr(window_key)
        pipe.expire(window_key, 120)
        pipe.incr(prev_window_key)
        pipe.expire(prev_window_key, 120)
        results = await pipe.execute()
        
        current_count = results[0] + results[2]
        
        return current_count <= max_per_minute

    async def get_hits(self, key: str) -> int:
        now = int(time.time())
        window_key = f"rate:global:{key}:{now}"
        prev_window_key = f"rate:global:{key}:{now - 1}"
        
        pipe = self.redis.pipeline()
        pipe.get(window_key)
        pipe.get(prev_window_key)
        results = await pipe.execute()
        
        return int(results[0] or 0) + int(results[1] or 0)


class RedisAuthBruteforceLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def _key(self, ip: str, login: str, from_school: bool) -> str:
        ln = login.strip().lower()
        if from_school:
            return f"auth:sch:login:{ln}"
        return f"auth:ext:ip:{ip}:login:{ln}"

    async def is_blocked(self, ip: str, login: str, from_school: bool) -> bool:
        key = f"auth:blocked:{self._key(ip, login, from_school)}"
        ttl = await self.redis.ttl(key)
        return ttl > 0

    async def register_attempt(
        self, ip: str, login: str, success: bool, from_school: bool
    ) -> None:
        key = self._key(ip, login, from_school)
        failures_key = f"auth:failures:{key}"
        now = time.time()
        win = float(settings.AUTH_FAIL_WINDOW_SEC)

        if success:
            await self.redis.delete(failures_key, f"auth:blocked:{key}")
            return

        pipe = self.redis.pipeline()
        pipe.zadd(failures_key, {str(now): now})
        pipe.zremrangebyscore(failures_key, "-inf", now - win)
        pipe.expire(failures_key, int(win) + 60)
        await pipe.execute()

        failures = await self.redis.zcard(failures_key)

        cap = (
            settings.AUTH_FAIL_BLOCK_SCHOOL
            if from_school
            else settings.AUTH_FAIL_BLOCK_EXTERNAL
        )

        if failures >= cap:
            block_time = float(settings.AUTH_FAIL_COOLDOWN_START_SEC)
            await self.redis.setex(f"auth:blocked:{key}", int(block_time), "1")
        
        if failures >= cap * 2:
            block_time = float(settings.AUTH_FAIL_COOLDOWN_HEAVY_SEC)
            await self.redis.setex(f"auth:blocked:{key}", int(block_time), "1")

    async def get_failures(self, ip: str, login: str, from_school: bool) -> int:
        key = f"auth:failures:{self._key(ip, login, from_school)}"
        now = time.time()
        win = float(settings.AUTH_FAIL_WINDOW_SEC)
        return await self.redis.zcount(key, now - win, now)


class RedisHourlyKeyedLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def allow(self, key: str, max_per_hour: int) -> bool:
        now = int(time.time())
        hour_key = f"rate:hourly:{key}:{now // 3600}"
        
        count = await self.redis.incr(hour_key)
        await self.redis.expire(hour_key, 7200)
        
        return count <= max_per_hour

    def key_verification(self, ip: str, login: str, from_school: bool) -> str:
        ln = login.strip().lower()
        if from_school:
            return f"vr:sch:login:{ln}"
        return f"vr:ext:ip:{ip}:login:{ln}"


class RedisRefreshTokenLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def allow(self, ip: str, from_school: bool) -> bool:
        now = int(time.time())
        key = f"refresh:{ip}:{now // 60}"
        
        max_per_min = 60 if from_school else 20
        
        count = await self.redis.incr(key)
        await self.redis.expire(key, 120)
        
        return count <= max_per_min


redis_client: Optional[redis.Redis] = None
redis_global_limiter: Optional[RedisGlobalMinuteLimiter] = None
redis_auth_limiter: Optional[RedisAuthBruteforceLimiter] = None
redis_verification_limiter: Optional[RedisHourlyKeyedLimiter] = None
redis_refresh_limiter: Optional[RedisRefreshTokenLimiter] = None


async def init_redis():
    global redis_client, redis_global_limiter, redis_auth_limiter
    global redis_verification_limiter, redis_refresh_limiter
    
    if not settings.USE_REDIS:
        return
    
    redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD,
        decode_responses=True,
    )
    
    redis_global_limiter = RedisGlobalMinuteLimiter(redis_client)
    redis_auth_limiter = RedisAuthBruteforceLimiter(redis_client)
    redis_verification_limiter = RedisHourlyKeyedLimiter(redis_client)
    redis_refresh_limiter = RedisRefreshTokenLimiter(redis_client)


async def close_redis():
    global redis_client
    if redis_client:
        await redis_client.close()


def get_redis_client() -> Optional[redis.Redis]:
    return redis_client
