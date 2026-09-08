"""
WebAdminMapper - Unit Tests for Benchmarking Suite
==================================================
Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from benchmarks.benchmark_suite import (
    get_system_specifications,
    run_benchmark_suite,
)

__author__ = "Ahmed Wael"


class TestBenchmarkSuite(unittest.TestCase):

    def test_system_specifications_capture(self):
        specs = get_system_specifications()
        self.assertIn("os", specs)
        self.assertIn("cpu_cores", specs)
        self.assertIn("python_version", specs)
        self.assertGreaterEqual(specs["cpu_cores"], 1)

    def test_quick_benchmark_execution(self):
        # Run small benchmark with 20 requests at 2 threads
        report = run_benchmark_suite(thread_levels=[2], requests_per_level=20)
        self.assertEqual(report["author"], "Ahmed Wael")
        self.assertEqual(len(report["trials"]), 1)
        trial = report["trials"][0]
        self.assertEqual(trial["threads"], 2)
        self.assertEqual(trial["total_requests"], 20)
        self.assertGreater(trial["throughput_req_sec"], 0.0)


if __name__ == "__main__":
    unittest.main()
