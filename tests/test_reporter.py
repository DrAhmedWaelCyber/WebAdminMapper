"""
WebAdminMapper - Unit Tests for ScanReporter Module
===================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import json
import tempfile
import unittest
from pathlib import Path

from web_mapper.config import ScanConfig
from web_mapper.network_diag import NetworkDiagResult
from web_mapper.reporter import ScanReporter
from web_mapper.requester import ScanResult
from web_mapper.security_audit import SecurityAuditResult

__author__ = "Ahmed Wael"


class TestScanReporter(unittest.TestCase):

    def setUp(self):
        self.sample_results = [
            ScanResult(
                path="/admin",
                url="https://example.com/admin",
                status_code=200,
                content_length=1200,
                response_time_ms=50.0,
                title="Admin Control Panel",
            ),
            ScanResult(
                path="/login",
                url="https://example.com/login",
                status_code=302,
                content_length=0,
                response_time_ms=25.0,
                redirect_location="/auth/login",
            ),
        ]
        self.sample_diag = NetworkDiagResult(
            hostname="example.com",
            port=443,
            ip_addresses=["93.184.216.34"],
            primary_ip="93.184.216.34",
            tcp_latency_ms=15.4,
        )
        self.sample_audit = SecurityAuditResult(
            target_url="https://example.com",
            grade="B",
            score=82,
            missing_headers=["Permissions-Policy"],
        )

    def test_export_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.json"
            config = ScanConfig(target_url="https://example.com", output_file=str(out_file), output_format="json")
            reporter = ScanReporter(config)

            saved = reporter.export_results(
                results=self.sample_results,
                duration_sec=2.5,
                security_audit=self.sample_audit,
                network_diag=self.sample_diag,
            )

            self.assertIsNotNone(saved)
            self.assertTrue(out_file.exists())
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertEqual(data["metadata"]["total_found"], 2)
            self.assertEqual(data["metadata"]["network_diagnostics"]["primary_ip"], "93.184.216.34")
            self.assertEqual(data["metadata"]["security_audit"]["grade"], "B")

    def test_export_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.html"
            config = ScanConfig(target_url="https://example.com", output_file=str(out_file), output_format="html")
            reporter = ScanReporter(config)

            saved = reporter.export_results(
                results=self.sample_results,
                duration_sec=1.5,
                security_audit=self.sample_audit,
                network_diag=self.sample_diag,
            )

            self.assertIsNotNone(saved)
            self.assertTrue(out_file.exists())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("Ahmed Wael", content)
            self.assertIn("/admin", content)
            self.assertIn("Network Diagnostics", content)
            self.assertIn("93.184.216.34", content)

    def test_export_compliance_report(self):
        from web_mapper.compliance import ComplianceEngine
        comp_engine = ComplianceEngine(benchmark="all")
        comp_report = comp_engine.evaluate(results=self.sample_results, base_headers={}, target_url="https://example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Test JSON export with compliance
            json_file = Path(tmpdir) / "comp_report.json"
            cfg_json = ScanConfig(target_url="https://example.com", output_file=str(json_file), output_format="json")
            rep_json = ScanReporter(cfg_json)
            rep_json.export_results(results=self.sample_results, duration_sec=1.0, compliance_report=comp_report)
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIsNotNone(data["metadata"]["compliance_report"])
            self.assertEqual(data["metadata"]["compliance_report"]["author"], "Ahmed Wael")

            # Test HTML export with compliance
            html_file = Path(tmpdir) / "comp_report.html"
            cfg_html = ScanConfig(target_url="https://example.com", output_file=str(html_file), output_format="html")
            rep_html = ScanReporter(cfg_html)
            rep_html.export_results(results=self.sample_results, duration_sec=1.0, compliance_report=comp_report)
            html_text = html_file.read_text(encoding="utf-8")
            self.assertIn("Compliance Baseline", html_text)
            self.assertIn("OWASP ASVS v4.0", html_text)

            # Test Markdown export with compliance
            md_file = Path(tmpdir) / "comp_report.md"
            cfg_md = ScanConfig(target_url="https://example.com", output_file=str(md_file), output_format="markdown")
            rep_md = ScanReporter(cfg_md)
            rep_md.export_results(results=self.sample_results, duration_sec=1.0, compliance_report=comp_report)
            md_text = md_file.read_text(encoding="utf-8")
            self.assertIn("Defensive Security Assessment & Compliance Baseline Audit", md_text)
            self.assertIn("OWASP-ASVS", md_text)
            self.assertIn("Detection Logic", md_text)

    def test_export_security_assertions_and_csv(self):
        from web_mapper.security_assertions import SecurityAssertionValidator

        assertion_engine = SecurityAssertionValidator()
        assertions = assertion_engine.validate_all(self.sample_results)
        self.assertGreater(len(assertions), 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. JSON Export verification
            json_file = Path(tmpdir) / "report.json"
            cfg_json = ScanConfig(target_url="https://example.com", output_file=str(json_file), output_format="json")
            rep_json = ScanReporter(cfg_json)
            rep_json.export_results(results=self.sample_results, duration_sec=1.0, security_assertions=assertions)
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["metadata"]["version"], "1.1.0")
            self.assertGreater(len(data["metadata"]["security_assertions"]), 0)
            first_assertion = data["metadata"]["security_assertions"][0]
            self.assertIn("classification", first_assertion)
            self.assertIn("confidence", first_assertion)
            self.assertIn("impact", first_assertion)
            self.assertIn("manual_verification_required", first_assertion)

            # 2. HTML Export verification
            html_file = Path(tmpdir) / "report.html"
            cfg_html = ScanConfig(target_url="https://example.com", output_file=str(html_file), output_format="html")
            rep_html = ScanReporter(cfg_html)
            rep_html.export_results(results=self.sample_results, duration_sec=1.0, security_assertions=assertions)
            html_text = html_file.read_text(encoding="utf-8")
            self.assertIn("Automated Security Assertions", html_text)
            self.assertIn("Classification", html_text)
            self.assertIn("Confidence", html_text)
            self.assertIn("Impact", html_text)
            self.assertIn("Manual Verif.", html_text)

            # 3. Markdown Export verification
            md_file = Path(tmpdir) / "report.md"
            cfg_md = ScanConfig(target_url="https://example.com", output_file=str(md_file), output_format="markdown")
            rep_md = ScanReporter(cfg_md)
            rep_md.export_results(results=self.sample_results, duration_sec=1.0, security_assertions=assertions)
            md_text = md_file.read_text(encoding="utf-8")
            self.assertIn("Automated Security Assertions & Vulnerability Validations", md_text)
            self.assertIn("Classification", md_text)
            self.assertIn("Impact", md_text)

            # 4. CSV Export verification
            csv_file = Path(tmpdir) / "report.csv"
            cfg_csv = ScanConfig(target_url="https://example.com", output_file=str(csv_file), output_format="csv")
            rep_csv = ScanReporter(cfg_csv)
            rep_csv.export_results(results=self.sample_results, duration_sec=1.0, security_assertions=assertions)
            self.assertTrue(csv_file.exists())
            assertions_csv = Path(tmpdir) / "report_assertions.csv"
            self.assertTrue(assertions_csv.exists())
            csv_text = assertions_csv.read_text(encoding="utf-8")
            self.assertIn("classification", csv_text)
            self.assertIn("confidence", csv_text)
            self.assertIn("impact", csv_text)
            self.assertIn("manual_verification_required", csv_text)


if __name__ == "__main__":
    unittest.main()
