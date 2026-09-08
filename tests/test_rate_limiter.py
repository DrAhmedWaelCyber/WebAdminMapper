"""
WebAdminMapper - Unit Tests for Rate Limiter & Concurrency Control
==================================================================
Tests thread-safe token bucket rate limiting, per-request delays,
and randomized jitter timing independently of thread worker concurrency.

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import time
from concurrent.futures import ThreadPoolExecutor
import unittest
from web_mapper.rate_limiter import RateLimiter

__author__ = "Ahmed Wael"


class TestRateLimiter(unittest.TestCase):

    def test_default_unlimited_no_delay(self):
        """Verify unconstrained limiter permits instantaneous calls."""
        limiter = RateLimiter(rate_limit=0.0, delay=0.0, jitter=0.0)
        start = time.perf_counter()
        for _ in range(50):
            limiter.wait()
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 0.05, "Zero rate limit and zero delay should execute without delay")

    def test_fixed_delay_enforcement(self):
        """Verify fixed delay is enforced per call."""
        delay = 0.03
        limiter = RateLimiter(delay=delay)
        start = time.perf_counter()
        limiter.wait()
        limiter.wait()
        elapsed = time.perf_counter() - start
        self.assertGreaterEqual(elapsed, delay * 2 * 0.85)

    def test_jitter_variation(self):
        """Verify randomized jitter adds timing delta within [0, jitter]."""
        jitter = 0.04
        limiter = RateLimiter(delay=0.01, jitter=jitter)
        times = []
        for _ in range(5):
            s = time.perf_counter()
            limiter.wait()
            times.append(time.perf_counter() - s)

        # All delays should be >= base delay
        for t in times:
            self.assertGreaterEqual(t, 0.008)
            self.assertLessEqual(t, 0.01 + jitter + 0.05)

        # Timing should vary due to randomness
        self.assertGreater(len(set(round(t, 3) for t in times)), 1)

    def test_token_bucket_multithreaded_throttling(self):
        """Verify token bucket controls total requests per second across concurrent threads."""
        rps = 20.0  # 20 requests per second -> 10 requests should take at least ~0.4 - 0.5s
        limiter = RateLimiter(rate_limit=rps)

        start = time.perf_counter()
        num_requests = 10

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(limiter.wait) for _ in range(num_requests)]
            for f in futures:
                f.result()

        elapsed = time.perf_counter() - start
        # With 20 RPS, first token or burst is available, and subsequent tokens require 1/20 = 0.05s each
        expected_min = (num_requests - 1) / rps * 0.70
        self.assertGreaterEqual(elapsed, expected_min)


if __name__ == "__main__":
    unittest.main()
