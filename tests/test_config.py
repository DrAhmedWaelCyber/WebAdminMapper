"""
WebAdminMapper - Unit Tests for Configuration Module
====================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.config import ScanConfig

__author__ = "Ahmed Wael"


class TestScanConfig(unittest.TestCase):

    def test_url_normalization(self):
        cfg = ScanConfig(target_url="example.com")
        self.assertEqual(cfg.target_url, "https://example.com")

        cfg2 = ScanConfig(target_url="http://example.com:8080/path/")
        self.assertEqual(cfg2.target_url, "http://example.com:8080/path")

    def test_invalid_threads(self):
        with self.assertRaises(ValueError):
            ScanConfig(target_url="https://example.com", threads=0)

    def test_profile_serialization(self):
        cfg = ScanConfig(target_url="https://example.com", threads=30, extensions=["php", "html"])
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            path = tf.name

        cfg.save_profile(path)
        loaded = ScanConfig.load_profile(path)
        self.assertEqual(loaded.target_url, cfg.target_url)
        self.assertEqual(loaded.threads, 30)
        self.assertEqual(loaded.extensions, ["php", "html"])


if __name__ == "__main__":
    unittest.main()
