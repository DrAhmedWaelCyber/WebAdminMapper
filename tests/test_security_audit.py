"""
WebAdminMapper - Unit Tests for Security Posture Auditor Module
===============================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.security_audit import SecurityAuditor

__author__ = "Ahmed Wael"


class TestSecurityAuditor(unittest.TestCase):

    def test_missing_headers_lowers_score(self):
        auditor = SecurityAuditor()
        # Minimal insecure headers
        headers = {"server": "Apache/2.4.41"}
        result = auditor.audit("https://example.com", headers)
        self.assertIn(result.grade, ["D", "F"])
        self.assertTrue(len(result.missing_headers) >= 4)

    def test_strong_headers_high_score(self):
        auditor = SecurityAuditor()
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        }
        result = auditor.audit("https://example.com", headers)
        self.assertIn(result.grade, ["A", "A+"])
        self.assertEqual(len(result.missing_headers), 0)


if __name__ == "__main__":
    unittest.main()
