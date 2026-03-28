import time
from collections import defaultdict

from core.config import settings
from core.school_networks import is_school_ip


class GlobalMinuteLimiter:
    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str, max_per_minute: int) -> bool:
        now = time.time()
        arr = self._hits[key]
        arr[:] = [t for t in arr if now - t < 60.0]
        if len(arr) >= max_per_minute:
            return False
        arr.append(now)
        if len(self._hits) > 50_000:
            self._prune_stale(now)
        return True

    def _prune_stale(self, now: float) -> None:
        dead = [k for k, v in self._hits.items() if not v or now - max(v) > 120]
        for k in dead[: 20_000]:
            del self._hits[k]


class AuthBruteforceLimiter:
    def __init__(self):
        self.failures: dict[str, list[float]] = defaultdict(list)
        self.blocked_until: dict[str, float] = {}

    def _key(self, ip: str, login: str, from_school: bool) -> str:
        ln = login.strip().lower()
        if from_school:
            return f"sch:{ln}"
        return f"ext:{ip}:{ln}"

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
            return f"vr:sch:{ln}"
        return f"vr:ext:{ip}:{ln}"


global_minute_limiter = GlobalMinuteLimiter()
auth_limiter = AuthBruteforceLimiter()
verification_hourly_limiter = HourlyKeyedLimiter()


def check_global_rate(ip: str) -> bool:
    lim = (
        settings.RATE_GLOBAL_PER_MIN_SCHOOL
        if is_school_ip(ip)
        else settings.RATE_GLOBAL_PER_MIN_EXTERNAL
    )
    return global_minute_limiter.allow(ip or "unknown", lim)


def verification_request_allowed(ip: str, login: str, from_school: bool) -> bool:
    cap = (
        settings.VERIFICATION_REQUEST_PER_HOUR_SCHOOL
        if from_school
        else settings.VERIFICATION_REQUEST_PER_HOUR_EXTERNAL
    )
    key = verification_hourly_limiter.key_verification(ip, login, from_school)
    return verification_hourly_limiter.allow(key, cap)
