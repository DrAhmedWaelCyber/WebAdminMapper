"""
WebAdminMapper - Unit Tests for Heuristics & Soft-404 Module
===========================================================
Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.heuristics import (
    Soft404Detector,
    WAFDetector,
    compute_token_set,
    compute_words_and_lines,
    jaccard_similarity,
)

__author__ = "Ahmed Wael"


class TestHeuristics(unittest.TestCase):

    def test_compute_words_and_lines(self):
        """Test word and line counting edge cases."""
        w, l = compute_words_and_lines("")
        self.assertEqual(w, 0)
        self.assertEqual(l, 0)

        sample = "Line 1 with five words\nLine 2\nLine 3"
        w, l = compute_words_and_lines(sample)
        self.assertEqual(w, 9)
        self.assertEqual(l, 3)

    def test_jaccard_similarity(self):
        """Test Jaccard similarity mathematical properties."""
        set_a = {"apple", "banana", "cherry"}
        set_b = {"apple", "banana", "cherry"}
        set_c = {"dog", "elephant"}

        # Identical
        self.assertAlmostEqual(jaccard_similarity(set_a, set_b), 1.0)
        # Completely disjoint
        self.assertAlmostEqual(jaccard_similarity(set_a, set_c), 0.0)
        # Empty sets
        self.assertAlmostEqual(jaccard_similarity(set(), set()), 1.0)
        self.assertAlmostEqual(jaccard_similarity(set_a, set()), 0.0)

        # Partial overlap (2 in common out of 4 union -> 0.5)
        set_d = {"apple", "banana", "date"}
        self.assertAlmostEqual(jaccard_similarity(set_a, set_d), 0.5)

    def test_soft_404_detection_exact_and_dynamic(self):
        """Test soft-404 detection across exact, word/line, and dynamic templates."""
        detector = Soft404Detector()
        baseline_body = b"<html><title>Error 404</title><body>Document Not Found on Server Ref: 981273</body></html>"
        detector.add_baseline(status_code=200, body=baseline_body, title="Error 404")

        # 1. Exact match
        self.assertTrue(detector.is_soft_404(200, len(baseline_body), baseline_body, "Error 404"))

        # 2. Dynamic token variation (e.g. different Ref ID, small length difference)
        dynamic_body = b"<html><title>Error 404</title><body>Document Not Found on Server Ref: 981299</body></html>"
        self.assertTrue(detector.is_soft_404(200, len(dynamic_body), dynamic_body, "Error 404"))

        # 3. Status code mismatch (404 status shouldn't trigger soft-404 suppression if baseline was 200)
        self.assertFalse(detector.is_soft_404(404, len(baseline_body), baseline_body, "Error 404"))

        # 4. Legitimate content page (dissimilar)
        legit_body = b"<html><title>Dashboard</title><body>User Profile Analytics Settings Orders</body></html>"
        self.assertFalse(detector.is_soft_404(200, len(legit_body), legit_body, "Dashboard"))

    def test_waf_detection_signatures(self):
        """Test signature detection for major WAF providers."""
        waf = WAFDetector()

        # Cloudflare passive
        cf_detected = waf.check_headers({"cf-ray": "123456789"}, 200)
        self.assertEqual(cf_detected, "Cloudflare")

        # Cloudflare active block
        cf_blocked = waf.check_headers({"cf-ray": "123456789"}, 403)
        self.assertIn("Active Block", cf_blocked)

        # AWS WAF
        aws_detected = waf.check_headers({"x-amzn-requestid": "abc-123"}, 200)
        self.assertEqual(aws_detected, "AWS WAF")

        # Akamai active block
        akamai_blocked = waf.check_headers({"x-akamai-transformed": "9 1000"}, 429)
        self.assertIn("Active Block", akamai_blocked)

        # Unknown / clean headers
        none_detected = waf.check_headers({"server": "Apache/2.4"}, 200)
        self.assertIsNone(none_detected)


if __name__ == "__main__":
    unittest.main()
