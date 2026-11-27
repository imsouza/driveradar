"""Bounded-memory thread-safe Sliding-Window Rate Limiter."""

from __future__ import annotations

import threading
import time
from collections import deque

from radar_core.domain.models import RateLimitDecision


class SlidingWindowRateLimiter:
    """In-memory sliding-window rate limiter with bounded key cardinality to prevent OOM."""

    def __init__(self, max_buckets: int = 4096) -> None:
        self._max_buckets = max_buckets
        self._buckets: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, bucket_key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        now = time.monotonic()
        cutoff = now - float(window_seconds)
        with self._lock:
            if bucket_key not in self._buckets and len(self._buckets) >= self._max_buckets:
                self._evict_stale(now, float(window_seconds))
            q = self._buckets.setdefault(bucket_key, deque())
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:
                retry_after = max(1, int(round(window_seconds - (now - q[0]))))
                return RateLimitDecision(allowed=False, retry_after_seconds=retry_after, remaining=0)
            q.append(now)
            return RateLimitDecision(allowed=True, retry_after_seconds=0, remaining=max(0, limit - len(q)))

    def _evict_stale(self, now: float, default_window: float) -> None:
        stale_keys = [k for k, q in self._buckets.items() if not q or (now - q[-1]) > default_window]
        for k in stale_keys:
            self._buckets.pop(k, None)
        if len(self._buckets) >= self._max_buckets:
            # Drop oldest 10% if still full under heavy attack.
            for k in list(self._buckets.keys())[: max(1, self._max_buckets // 10)]:
                self._buckets.pop(k, None)
