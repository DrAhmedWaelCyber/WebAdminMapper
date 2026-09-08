"""
WebAdminMapper - Unit Tests for Automated Security Assertion & Vulnerability Validation Module
=============================================================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.requester import ScanResult
from web_mapper.security_assertions import (
    AssertionClassification,
    SecurityAssertion,
    SecurityAssertionValidator,
)

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
        self.assertEqual(finding.classification, AssertionClassification.POTENTIAL)
        self.assertTrue(finding.manual_verification_required)
        self.assertIn("Ahmed Wael", finding.to_dict()["author"])

    def test_admin_login_gateway_informational(self):
        res = ScanResult(
            path="/admin/login",
            url="https://example.com/admin/login",
            status_code=200,
            content_length=1200,
            response_time_ms=25.0,
            title="Admin Sign In Portal",
        )
        assertions = self.validator.validate_endpoint(res)
        finding = next(a for a in assertions if "Authentication Gateway" in a.title)
        self.assertEqual(finding.classification, AssertionClassification.INFORMATIONAL)
        self.assertEqual(finding.confidence, "HIGH")

    def test_sensitive_backup_exposure(self):
        res = ScanResult(
            path="/backup/database.sql",
            url="https://example.com/backup/database.sql",
            status_code=200,
            content_length=54000,
            response_time_ms=40.0,
        )
        assertions = self.validator.validate_endpoint(res)
        finding = next(a for a in assertions if a.category == "Sensitive Data Exposure")
        self.assertIn("Publicly Accessible Configuration", finding.title)
        self.assertEqual(finding.classification, AssertionClassification.CONFIRMED)
        self.assertEqual(finding.confidence, "HIGH")
        self.assertFalse(finding.manual_verification_required)

    def test_server_error_requires_manual_verification(self):
        res = ScanResult(
            path="/api/admin/query",
            url="https://example.com/api/admin/query",
            status_code=500,
            content_length=420,
            response_time_ms=120.0,
        )
        assertions = self.validator.validate_endpoint(res)
        finding = next(a for a in assertions if a.category == "Information Disclosure")
        self.assertIn("Server Error", finding.title)
        self.assertEqual(finding.classification, AssertionClassification.MANUAL_VERIFY)
        self.assertTrue(finding.manual_verification_required)

    def test_api_endpoint_attack_surface(self):
        res = ScanResult(
            path="/api/v1/users",
            url="https://example.com/api/v1/users",
            status_code=200,
            content_length=80,
            response_time_ms=15.0,
        )
        assertions = self.validator.validate_endpoint(res)
        finding = next(a for a in assertions if a.category == "Attack Surface Mapping")
        self.assertEqual(finding.classification, AssertionClassification.INFORMATIONAL)
        self.assertTrue(finding.manual_verification_required)

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
        trace_finding = next(a for a in assertions if "TRACE" in a.title)
        self.assertEqual(trace_finding.classification, AssertionClassification.CONFIRMED)

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
