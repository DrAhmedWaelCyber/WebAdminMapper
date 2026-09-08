"""
WebAdminMapper - Unit Tests for Automated Security Assertion & Vulnerability Validation Module
=============================================================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.requester import ScanResult
from web_mapper.security_assertions import SecurityAssertion, SecurityAssertionValidator

__author__ = "Ahmed Wael"


class TestSecurityAssertionValidator(unittest.TestCase):

    def setUp(self):
        self.validator = SecurityAssertionValidator()

    def test_improper_access_control_admin_path(self):
        res = ScanResult(
            path="/admin/dashboard",
            url="https://example.com/admin/dashboard",
            status_code=200,
            content_length=1500,
            response_time_ms=35.0,
            title="SuperAdmin Portal",
        )
        assertions = self.validator.validate_endpoint(res)
        cats = [a.category for a in assertions]
        self.assertIn("Improper Access Control", cats)
        finding = next(a for a in assertions if a.category == "Improper Access Control")
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("Ahmed Wael", finding.to_dict()["author"])

    def test_sensitive_backup_exposure(self):
        res = ScanResult(
            path="/backup/database.sql",
            url="https://example.com/backup/database.sql",
            status_code=200,
            content_length=54000,
            response_time_ms=40.0,
        )
        assertions = self.validator.validate_endpoint(res)
        titles = [a.title for a in assertions]
        self.assertIn("Publicly Accessible Configuration or Backup Asset", titles)

    def test_dangerous_http_methods(self):
        res = ScanResult(
            path="/api/resource",
            url="https://example.com/api/resource",
            status_code=200,
            content_length=100,
            response_time_ms=20.0,
            allowed_methods="GET, POST, TRACE, PUT",
        )
        assertions = self.validator.validate_endpoint(res)
        titles = [a.title for a in assertions]
        self.assertIn("HTTP TRACE/TRACK Method Enabled", titles)
        self.assertIn("Potentially Unrestricted HTTP Modification Verbs", titles)

    def test_parameter_injection_surface_mapping(self):
        res = ScanResult(
            path="/search?q=test&page=1",
            url="https://example.com/search?q=test&page=1",
            status_code=200,
            content_length=1200,
            response_time_ms=22.0,
        )
        assertions = self.validator.validate_endpoint(res)
        cats = [a.category for a in assertions]
        self.assertIn("Injection Surface Analysis", cats)

    def test_validate_all_deduplication(self):
        res1 = ScanResult(
            path="/admin",
            url="https://example.com/admin",
            status_code=200,
            content_length=500,
            response_time_ms=10.0,
        )
        res2 = ScanResult(
            path="/admin",
            url="https://example.com/admin",
            status_code=200,
            content_length=500,
            response_time_ms=10.0,
        )
        assertions = self.validator.validate_all([res1, res2])
        admin_findings = [a for a in assertions if a.category == "Improper Access Control"]
        self.assertEqual(len(admin_findings), 1)


if __name__ == "__main__":
    unittest.main()
