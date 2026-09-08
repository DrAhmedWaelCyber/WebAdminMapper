"""
WebAdminMapper - Rate Limiting & Concurrency Control Module
============================================================
Thread-safe Token Bucket rate limiter providing deterministic request
frequency throttling, per-request delays, and randomized timing jitter
independently of thread worker concurrency.

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import random
import threading
import time

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


class RateLimiter:
    """
    Thread-safe Token Bucket Rate Limiter with Delay and Jitter.
    Authored and designed by Ahmed Wael.

    Enables fine-grained traffic pacing to prevent target server exhaustion,
    evade basic frequency-based rate alarms, and decouple concurrency from RPS.
    """

    def __init__(
        self,
        rate_limit: float = 0.0,
        delay: float = 0.0,
        jitter: float = 0.0,
    ) -> None:
        """
        Initialize rate limiter.

        :param rate_limit: Maximum allowed requests per second (0.0 = unlimited).
        :param delay: Fixed pause in seconds before every outbound request.
        :param jitter: Random timing variance in seconds [0.0, jitter] added to delay.
        """
        self.rate_limit: float = max(0.0, float(rate_limit)) if rate_limit else 0.0
        self.delay: float = max(0.0, float(delay)) if delay else 0.0
        self.jitter: float = max(0.0, float(jitter)) if jitter else 0.0
        self._lock = threading.Lock()
        self.max_tokens: float = 1.0
        self._tokens: float = 1.0
        self._last_time: float = time.perf_counter()

    def wait(self) -> None:
        """
        Block calling thread until rate limit token is acquired and delay/jitter expires.
        """
        # 1. Apply per-request fixed delay + random jitter
        sleep_duration = self.delay
        if self.jitter > 0.0:
            sleep_duration += random.uniform(0.0, self.jitter)

        if sleep_duration > 0.0:
            time.sleep(sleep_duration)

        # 2. Enforce Token Bucket request frequency
        if self.rate_limit > 0.0:
            while True:
                with self._lock:
                    now = time.perf_counter()
                    elapsed = now - self._last_time
                    self._last_time = now

                    # Replenish available tokens based on elapsed wall time up to max capacity
                    self._tokens = min(self.max_tokens, self._tokens + (elapsed * self.rate_limit))

                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return

                    # Compute wait time for next available token
                    deficit = 1.0 - self._tokens
                    wait_sec = max(0.001, deficit / self.rate_limit)

                time.sleep(wait_sec)
