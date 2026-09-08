"""
WebAdminMapper - Unit Tests for Defensive Security Assessment & Compliance Engine
=================================================================================
Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.compliance import (
    ComplianceBenchmark,
    ComplianceEngine,
    ComplianceFinding,
    ComplianceReport,
    ComplianceRule,
    ComplianceSeverity,
    ComplianceStatus,
)
from web_mapper.config import ScanConfig
from web_mapper.reporter import ScanReporter
from web_mapper.requester import ScanResult

__author__ = "Ahmed Wael"


class TestComplianceEngine(unittest.TestCase):
    """Unit tests for the Defensive Security Assessment & Compliance Validation Engine."""

    def setUp(self):
        self.engine_all = ComplianceEngine(benchmark="all")
        self.engine_owasp = ComplianceEngine(benchmark="owasp")
        self.engine_cis = ComplianceEngine(benchmark="cis")
        self.engine_nist = ComplianceEngine(benchmark="nist")

    def test_engine_initialization(self):
        """Verify engine initialization and benchmark filtering."""
        self.assertEqual(self.engine_all.benchmark, "all")
        self.assertEqual(self.engine_owasp.benchmark, "owasp")
        self.assertEqual(self.engine_cis.benchmark, "cis")
        self.assertEqual(self.engine_nist.benchmark, "nist")
        # Fallback on invalid benchmark
        fallback = ComplianceEngine(benchmark="invalid_baseline")
        self.assertEqual(fallback.benchmark, "all")

    def test_unauthenticated_admin_surface_evaluation(self):
        """Test rule evaluation for exposed administrative surfaces."""
        results = [
            ScanResult(
                path="/admin/dashboard",
                url="https://example.com/admin/dashboard",
                status_code=200,
                content_length=1200,
                response_time_ms=30.0,
                title="Admin Console",
            )
        ]
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        }
        report = self.engine_all.evaluate(results=results, base_headers=headers, target_url="https://example.com")
        rule_ids = {f.rule_id for f in report.findings}

        self.assertIn("OWASP-ASVS-V4.1", rule_ids)
        self.assertIn("NIST-AC-3", rule_ids)
        self.assertIn("CIS-WEB-1.1", rule_ids)
        self.assertGreater(report.failed_rules, 0)
        self.assertLess(report.compliance_score, 100.0)
        self.assertEqual(report.author, "Ahmed Wael")

    def test_sensitive_backup_and_scm_exposure(self):
        """Test rule evaluation for exposed sensitive credentials and repos."""
        results = [
            ScanResult(
                path="/.env",
                url="https://example.com/.env",
                status_code=200,
                content_length=450,
                response_time_ms=25.0,
            ),
            ScanResult(
                path="/.git/config",
                url="https://example.com/.git/config",
                status_code=200,
                content_length=280,
                response_time_ms=20.0,
            ),
        ]
        report = self.engine_all.evaluate(results=results, base_headers={}, target_url="https://example.com")
        rule_ids = {f.rule_id for f in report.findings}

        self.assertIn("OWASP-ASVS-V8.1", rule_ids)
        self.assertIn("NIST-SC-28", rule_ids)
        self.assertIn("CIS-WEB-2.3", rule_ids)
        self.assertIn("OWASP-ASVS-V14.3", rule_ids)
        self.assertIn("CIS-WEB-2.4", rule_ids)

    def test_transport_security_http_plaintext(self):
        """Test transport layer evaluation when running over plain HTTP."""
        results = [
            ScanResult(
                path="/home",
                url="http://example.com/home",
                status_code=200,
                content_length=500,
                response_time_ms=20.0,
            )
        ]
        report = self.engine_all.evaluate(results=results, base_headers={}, target_url="http://example.com")
        rule_ids = {f.rule_id for f in report.findings}

        self.assertIn("OWASP-ASVS-V14.1", rule_ids)
        self.assertIn("NIST-SC-8", rule_ids)
        self.assertIn("CIS-WEB-3.1", rule_ids)

    def test_missing_client_security_headers(self):
        """Test detection of missing CSP, XFO, nosniff, and wildcard CORS."""
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Server": "Apache/2.4.52 (Ubuntu)",
        }
        report = self.engine_all.evaluate(results=[], base_headers=headers, target_url="https://example.com")
        rule_ids = {f.rule_id for f in report.findings}

        self.assertIn("OWASP-ASVS-V14.2-CSP", rule_ids)
        self.assertIn("OWASP-ASVS-V14.2-XFO", rule_ids)
        self.assertIn("CIS-WEB-3.2", rule_ids)
        self.assertIn("OWASP-ASVS-V14.2-NOSNIFF", rule_ids)
        self.assertIn("CIS-WEB-3.3", rule_ids)
        self.assertIn("OWASP-ASVS-V14.5", rule_ids)
        self.assertIn("OWASP-ASVS-V14.3-B", rule_ids)
        self.assertIn("CIS-WEB-1.3", rule_ids)
        self.assertIn("NIST-SI-11-A", rule_ids)

    def test_benchmark_filter_owasp(self):
        """Verify that engine with benchmark='owasp' only produces OWASP findings."""
        results = [
            ScanResult(
                path="/admin",
                url="https://example.com/admin",
                status_code=200,
                content_length=500,
                response_time_ms=20.0,
            )
        ]
        report = self.engine_owasp.evaluate(results=results, base_headers={}, target_url="https://example.com")
        for f in report.findings:
            self.assertEqual(f.benchmark, "OWASP ASVS v4.0")

    def test_benchmark_filter_cis(self):
        """Verify that engine with benchmark='cis' only produces CIS findings."""
        results = [
            ScanResult(
                path="/admin",
                url="https://example.com/admin",
                status_code=200,
                content_length=500,
                response_time_ms=20.0,
            )
        ]
        report = self.engine_cis.evaluate(results=results, base_headers={}, target_url="https://example.com")
        for f in report.findings:
            self.assertEqual(f.benchmark, "CIS Web Benchmark")

    def test_benchmark_filter_nist(self):
        """Verify that engine with benchmark='nist' only produces NIST findings."""
        results = [
            ScanResult(
                path="/admin",
                url="https://example.com/admin",
                status_code=200,
                content_length=500,
                response_time_ms=20.0,
            )
        ]
        report = self.engine_nist.evaluate(results=results, base_headers={}, target_url="https://example.com")
        for f in report.findings:
            self.assertEqual(f.benchmark, "NIST SP 800-53 Rev 5")

    def test_fully_compliant_environment(self):
        """Verify 100% compliance score on fully hardened target."""
        results = [
            ScanResult(
                path="/about",
                url="https://example.com/about",
                status_code=200,
                content_length=500,
                response_time_ms=20.0,
            )
        ]
        hardened_headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        }
        report = self.engine_all.evaluate(results=results, base_headers=hardened_headers, target_url="https://example.com")
        self.assertEqual(report.failed_rules, 0)
        self.assertEqual(report.compliance_score, 100.0)
        self.assertIn("A+", report.compliance_grade)

    def test_scanconfig_compliance_settings(self):
        """Test ScanConfig compliance flags and validation."""
        cfg = ScanConfig(target_url="https://example.com", compliance_check=True, compliance_benchmark="owasp")
        self.assertTrue(cfg.compliance_check)
        self.assertEqual(cfg.compliance_benchmark, "owasp")

        # Invalid benchmark raises ValueError
        with self.assertRaises(ValueError):
            ScanConfig(target_url="https://example.com", compliance_benchmark="invalid")

        # Serialization roundtrip
        cfg_dict = cfg.to_dict()
        self.assertIn("compliance_check", cfg_dict)
        self.assertIn("compliance_benchmark", cfg_dict)

    def test_compliance_report_serialization(self):
        """Verify ComplianceReport to_dict serialization including disclaimer and limitations."""
        results = [
            ScanResult(
                path="/admin",
                url="https://example.com/admin",
                status_code=200,
                content_length=500,
                response_time_ms=20.0,
            )
        ]
        report = self.engine_all.evaluate(results=results, base_headers={}, target_url="https://example.com")
        data = report.to_dict()
        self.assertEqual(data["author"], "Ahmed Wael")
        self.assertIn("compliance_score", data)
        self.assertIn("compliance_grade", data)
        self.assertIn("findings", data)
        self.assertIn("summary", data)
        self.assertIn("disclaimer", data)
        self.assertIn("OWASP ASVS v4.0", data["disclaimer"])
        self.assertTrue(len(report.findings) > 0)
        for finding in report.findings:
            self.assertTrue(hasattr(finding, "limitations"))
            self.assertIsInstance(finding.limitations, str)
            self.assertGreater(len(finding.limitations), 0)

    def test_all_rules_have_limitations(self):
        """Verify that every catalogued compliance rule specifies documented limitations."""
        for rule_id, rule in self.engine_all.rules.items():
            self.assertTrue(hasattr(rule, "limitations"), f"Rule {rule_id} missing limitations attr")
            self.assertGreater(len(rule.limitations), 10, f"Rule {rule_id} limitations string is too short or empty")


if __name__ == "__main__":
    unittest.main()
