"""
WebAdminMapper - Comprehensive End-to-End Integration Test Suite
================================================================
Executes complete scanner pipeline tests against the dedicated local test
web server: Target -> Requester -> Engine -> Heuristics -> Security Assertions -> Reporter.

Verifies:
  - Successful endpoints (/test-200, /admin)
  - Redirects (/test-301, /test-302, /redirect)
  - Forbidden resources (/test-403)
  - Not-found responses (/test-404)
  - Server errors (/test-500)
  - Soft-404 responses (/soft-404)
  - Wildcard behavior (/wildcard)
  - Slow responses (/slow)
  - Sensitive-looking paths (/.env, /.git/config)
  - Recursive discoveries (/dir -> /dir/secret)
  - Complete reporting export pipeline (HTML, JSON, Markdown)

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from tests.local_test_server import (
    IntegrationTestHandler,
    create_test_opener,
    start_local_test_server,
    stop_local_test_server,
)
from web_mapper.config import ScanConfig
from web_mapper.engine import ExecutionEngine
from web_mapper.reporter import ScanReporter
from web_mapper.requester import HTTPRequester
from web_mapper.security_assertions import SecurityAssertionValidator

__author__ = "Ahmed Wael"


class TestLocalServerIntegration(unittest.TestCase):
    """Full pipeline integration tests against the dedicated test server."""

    @classmethod
    def setUpClass(cls):
        # 1. Start multi-threaded server on ephemeral loopback port
        cls.server, cls.server_thread, cls.base_url = start_local_test_server(port=0)

        # 2. Check if direct socket connect is permitted in this OS environment
        cls.use_socket_opener = False
        try:
            import urllib.request
            req = urllib.request.Request(f"{cls.base_url}/test-200")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    cls.use_socket_opener = True
        except (OSError, Exception):
            cls.use_socket_opener = False

    @classmethod
    def tearDownClass(cls):
        stop_local_test_server(cls.server, cls.server_thread)

    def _get_requester(self, config: ScanConfig) -> HTTPRequester:
        """Create HTTPRequester with loopback socket or in-memory transport opener."""
        if self.use_socket_opener:
            return HTTPRequester(config)
        opener = create_test_opener(IntegrationTestHandler, follow_redirects=config.follow_redirects)
        return HTTPRequester(config, opener=opener)

    def test_successful_endpoints(self):
        """Verify discovery of 200 OK endpoints and HTML page title extraction."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = self._get_requester(cfg)

        res_200 = requester.probe_path("/test-200")
        self.assertIsNotNone(res_200)
        self.assertEqual(res_200.status_code, 200)
        self.assertEqual(res_200.title, "Test Success Page")
        self.assertGreater(res_200.content_length, 0)
        self.assertIn("WebAdminMapper", res_200.server)

        res_admin = requester.probe_path("/admin")
        self.assertIsNotNone(res_admin)
        self.assertEqual(res_admin.status_code, 200)
        self.assertEqual(res_admin.title, "Administrative Control Panel")

    def test_redirects_detection(self):
        """Verify accurate capture of 301 and 302 redirects with Location headers."""
        cfg = ScanConfig(target_url=self.base_url, follow_redirects=False, wildcard_detection=False)
        requester = self._get_requester(cfg)

        res_301 = requester.probe_path("/test-301")
        self.assertIsNotNone(res_301)
        self.assertEqual(res_301.status_code, 301)
        self.assertEqual(res_301.redirect_location, "/test-200")

        res_302 = requester.probe_path("/test-302")
        self.assertIsNotNone(res_302)
        self.assertEqual(res_302.status_code, 302)
        self.assertEqual(res_302.redirect_location, "/admin")

        res_redir = requester.probe_path("/redirect")
        self.assertIsNotNone(res_redir)
        self.assertEqual(res_redir.status_code, 302)
        self.assertEqual(res_redir.redirect_location, "/admin")

    def test_forbidden_resources(self):
        """Verify 403 Forbidden resource detection and status matching."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = self._get_requester(cfg)

        res_403 = requester.probe_path("/test-403")
        self.assertIsNotNone(res_403)
        self.assertEqual(res_403.status_code, 403)
        self.assertGreater(res_403.content_length, 0)

    def test_not_found_responses(self):
        """Verify that default filter codes correctly suppress standard 404 responses."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = self._get_requester(cfg)

        res_404 = requester.probe_path("/test-404")
        self.assertIsNone(res_404, "Default filter_codes={404} must suppress 404 responses")

        # When 404 is explicitly matched
        cfg_match_404 = ScanConfig(target_url=self.base_url, filter_codes=set(), match_codes={404}, wildcard_detection=False)
        req_match_404 = self._get_requester(cfg_match_404)
        res_matched = req_match_404.probe_path("/test-404")
        self.assertIsNotNone(res_matched)
        self.assertEqual(res_matched.status_code, 404)

    def test_server_errors_handling(self):
        """Verify 500 Internal Server Error detection and response body retention."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = self._get_requester(cfg)

        res_500 = requester.probe_path("/test-500")
        self.assertIsNotNone(res_500)
        self.assertEqual(res_500.status_code, 500)
        self.assertGreater(res_500.content_length, 0)

    def test_soft_404_responses_suppression(self):
        """Verify heuristic calibration dynamically suppresses disguised 200 OK soft-404s."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=True)
        requester = self._get_requester(cfg)

        # Baseline calibration seeds _wm_probe_* responses
        calib = requester.calibrate_heuristics()
        self.assertTrue(calib["soft404_active"])

        # /soft-404 returns same template and must be suppressed
        res_soft = requester.probe_path("/soft-404")
        self.assertIsNone(res_soft, "Expected soft-404 response to be suppressed by heuristic engine")

    def test_wildcard_behavior_detection(self):
        """Verify catch-all wildcard application pages are detected and suppressed."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=True)
        requester = self._get_requester(cfg)

        # Manually seed wildcard baseline
        probe = requester._raw_probe("/wildcard_seed_probe")
        if probe:
            status, body, title = probe
            requester.soft404.add_baseline(status, body, title)

        # Probing arbitrary non-existent subpath should be identified as soft-404/wildcard
        res_wc = requester.probe_path("/wildcard/arbitrary/subpath")
        self.assertIsNone(res_wc)

    def test_slow_responses_timeout(self):
        """Verify timeout handling and error counter increments on slow endpoints."""
        cfg = ScanConfig(target_url=self.base_url, timeout=0.1, retries=0, wildcard_detection=False)
        requester = self._get_requester(cfg)

        res_slow = requester.probe_path("/slow")
        self.assertIsNone(res_slow)
        self.assertGreaterEqual(requester.error_counts["timeouts"], 1)

    def test_sensitive_looking_paths(self):
        """Verify discovery of sensitive configuration assets like .env and .git/config."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = self._get_requester(cfg)

        res_env = requester.probe_path("/.env")
        self.assertIsNotNone(res_env)
        self.assertEqual(res_env.status_code, 200)

        res_git = requester.probe_path("/.git/config")
        self.assertIsNotNone(res_git)
        self.assertEqual(res_git.status_code, 200)

    def test_recursive_discoveries(self):
        """Verify recursive queue exploration discovers nested directory items."""
        cfg = ScanConfig(
            target_url=self.base_url,
            threads=2,
            recursive=True,
            max_depth=2,
            wildcard_detection=False,
        )
        requester = self._get_requester(cfg)
        engine = ExecutionEngine(cfg, requester)

        # Patch generator to supply /dir at root and /dir/secret for /dir prefix
        def custom_get_paths(base_prefix=""):
            if base_prefix == "/dir":
                return ["/dir/secret"]
            return ["/dir"]

        engine.generator.get_all_paths = custom_get_paths
        results = engine.run()

        found_paths = {r.path for r in results}
        self.assertIn("/dir", found_paths)
        self.assertIn("/dir/secret", found_paths)

    def test_complete_scanner_pipeline(self):
        """
        Verify the complete end-to-end scanner pipeline:
        Target -> Requester -> Engine -> Heuristics -> Security Assertions -> Reporter.
        """
        cfg = ScanConfig(
            target_url=self.base_url,
            threads=4,
            wildcard_detection=False,
            security_audit=True,
            validate_vulns=True,
        )
        requester = self._get_requester(cfg)
        engine = ExecutionEngine(cfg, requester)

        # Seed realistic target paths
        test_paths = [
            "/test-200",
            "/test-301",
            "/test-403",
            "/test-404",
            "/test-500",
            "/admin",
            "/.env",
            "/.git/config",
        ]
        engine.generator.get_all_paths = lambda base_prefix="": test_paths

        # 1. Engine runs Requester & Heuristics
        results = engine.run()
        self.assertTrue(len(results) >= 6)

        found_paths = {r.path for r in results}
        self.assertIn("/test-200", found_paths)
        self.assertIn("/admin", found_paths)
        self.assertIn("/.env", found_paths)
        self.assertIn("/.git/config", found_paths)
        self.assertIn("/test-500", found_paths)
        self.assertNotIn("/test-404", found_paths)

        # 2. Security Assertions Validation
        validator = SecurityAssertionValidator()
        assertions = validator.validate_all(results)
        self.assertTrue(len(assertions) > 0)

        # Confirm specific security assertions
        assertion_titles = {a.title for a in assertions}
        assertion_endpoints = {a.endpoint for a in assertions}
        self.assertIn("/admin", assertion_endpoints)
        self.assertIn("/.env", assertion_endpoints)

        # 3. Reporter export validation
        reporter = ScanReporter(cfg)
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test JSON Export
            json_file = Path(tmpdir) / "scan_report.json"
            cfg.output_file = str(json_file)
            cfg.output_format = "json"
            reporter.export_results(
                results=results,
                duration_sec=1.5,
                sitemap=engine.sitemap,
                security_assertions=assertions,
            )
            self.assertTrue(json_file.exists())
            with open(json_file, "r", encoding="utf-8") as jf:
                report_data = json.load(jf)
                self.assertIn("results", report_data)
                self.assertIn("metadata", report_data)

            # Test HTML Export
            html_file = Path(tmpdir) / "scan_report.html"
            cfg.output_file = str(html_file)
            cfg.output_format = "html"
            reporter.export_results(
                results=results,
                duration_sec=1.5,
                sitemap=engine.sitemap,
                security_assertions=assertions,
            )
            self.assertTrue(html_file.exists())
            html_content = html_file.read_text(encoding="utf-8")
            self.assertIn("WebAdminMapper", html_content)
            self.assertIn("Test Success Page", html_content)

            # Test Markdown Export
            md_file = Path(tmpdir) / "scan_report.md"
            cfg.output_file = str(md_file)
            cfg.output_format = "markdown"
            reporter.export_results(
                results=results,
                duration_sec=1.5,
                sitemap=engine.sitemap,
                security_assertions=assertions,
            )
            self.assertTrue(md_file.exists())
            md_content = md_file.read_text(encoding="utf-8")
            self.assertIn("# WebAdminMapper Audit Report", md_content)


if __name__ == "__main__":
    unittest.main()
