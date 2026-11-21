"""In-process token-bucket rate limiter (OWASP LLM10: unbounded consumption).

Per-identity buckets. For multi-replica deployments, swap the dict for Redis
with an atomic Lua script; the interface stays the same.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucketLimiter:
    def __init__(self, per_minute: int, clock=time.monotonic) -> None:
        self.capacity = float(per_minute)
        self.refill_per_sec = per_minute / 60.0
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[key] = b
            b.tokens = min(self.capacity, b.tokens + (now - b.updated) * self.refill_per_sec)
            b.updated = now
            if b.tokens >= cost:
                b.tokens -= cost
                return True, 0.0
            return False, round((cost - b.tokens) / self.refill_per_sec, 2)
