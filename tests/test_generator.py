"""
WebAdminMapper - Unit Tests for Generator Module
================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.config import ScanConfig
from web_mapper.generator import PathGenerator

__author__ = "Ahmed Wael"


class TestPathGenerator(unittest.TestCase):

    def test_extension_permutations(self):
        cfg = ScanConfig(target_url="https://example.com", wordlist_type="admin", extensions=["php", "json"])
        gen = PathGenerator(cfg)
        paths = gen.get_all_paths()
        self.assertTrue(any(p.endswith(".php") for p in paths))
        self.assertTrue(any(p.endswith(".json") for p in paths))

    def test_prefix_suffix(self):
        cfg = ScanConfig(target_url="https://example.com", wordlist_type="admin", prefix="api_", suffix="_v1")
        gen = PathGenerator(cfg)
        paths = gen.get_all_paths()
        self.assertTrue(any("/api_" in p for p in paths))
        self.assertTrue(any("_v1" in p for p in paths))


if __name__ == "__main__":
    unittest.main()
