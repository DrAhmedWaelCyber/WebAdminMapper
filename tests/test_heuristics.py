"""
WebAdminMapper - Unit Tests for Heuristics & Soft-404 Module
===========================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.heuristics import Soft404Detector, WAFDetector

__author__ = "Ahmed Wael"


class TestHeuristics(unittest.TestCase):

    def test_soft_404_detection(self):
        detector = Soft404Detector()
        baseline_body = b"<html><title>Not Found</title><body>Custom error 404 message template</body></html>"
        detector.add_baseline(status_code=200, body=baseline_body, title="Not Found")

        # Test identical response
        self.assertTrue(detector.is_soft_404(200, len(baseline_body), baseline_body, "Not Found"))

        # Test completely different response
        diff_body = b"<html><title>Dashboard</title><body>Welcome user dashboard panel</body></html>"
        self.assertFalse(detector.is_soft_404(200, len(diff_body), diff_body, "Dashboard"))

    def test_waf_detection(self):
        waf = WAFDetector()
        headers = {"cf-ray": "123456789", "server": "cloudflare"}
        detected = waf.check_headers(headers, 403)
        self.assertIn("Cloudflare", detected)


if __name__ == "__main__":
    unittest.main()
