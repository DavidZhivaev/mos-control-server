import time
from collections import defaultdict

class SmartRateLimiter:
    def __init__(self):
        self.attempts = defaultdict(list)
        self.blocked_until = {}

    def _key(self, ip, email):
        return f"{ip}:{email}"

    def is_blocked(self, ip, email):
        key = self._key(ip, email)
        if key in self.blocked_until:
            if time.time() < self.blocked_until[key]:
                return True
            else:
                del self.blocked_until[key]
        return False

    def register_attempt(self, ip, email, success: bool):
        key = self._key(ip, email)
        now = time.time()

        self.attempts[key].append(now)

        self.attempts[key] = [
            t for t in self.attempts[key]
            if now - t < 600
        ]

        fails = len(self.attempts[key])

        if not success:
            if fails > 5:
                self.blocked_until[key] = now + 60
            if fails > 10:
                self.blocked_until[key] = now + 300
            if fails > 20:
                self.blocked_until[key] = now + 1800

rate_limiter = SmartRateLimiter()