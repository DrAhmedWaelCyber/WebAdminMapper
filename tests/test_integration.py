"""
WebAdminMapper - End-to-End Integration Tests with Local Test Server
====================================================================
Tests real network interactions across HTTP status codes, redirects,
soft-404 suppression, wildcard routes, timeouts, connection failures,
and recursive directory discovery.

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import http.server
import socket
import threading
import time
import unittest
from typing import Optional

from web_mapper.config import ScanConfig
from web_mapper.engine import ExecutionEngine
from web_mapper.requester import HTTPRequester, ScanResult

__author__ = "Ahmed Wael"


class IntegrationTestHandler(http.server.BaseHTTPRequestHandler):
    """Custom HTTP handler serving controlled test scenarios."""

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP logs during test execution
        pass

    def do_GET(self):
        url_path = self.path.split("?")[0]

        # 1. Standard 200 OK with title
        if url_path in ("/page200", "/status-200"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            body = b"<html><head><title>Test Success Page</title></head><body>Welcome Home</body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 2. Redirect 301 (Permanent)
        elif url_path == "/redirect-301":
            self.send_response(301)
            self.send_header("Location", "/page200")
            self.send_header("Content-Length", "0")
            self.end_headers()

        # 3. Redirect 302 (Temporary)
        elif url_path == "/redirect-302":
            self.send_response(302)
            self.send_header("Location", "/auth/login")
            self.send_header("Content-Length", "0")
            self.end_headers()

        # 4. Forbidden 403
        elif url_path == "/forbidden-403":
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            body = b"Access Denied by Security Policy"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 5. Not Found 404
        elif url_path == "/notfound-404":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            body = b"Endpoint Not Found"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 6. Server Error 500
        elif url_path == "/error-500":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            body = b"Internal Server Error: Database Connection Failed Traceback"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 7. Soft-404 Custom Error Page (returns 200 with error text)
        elif url_path.startswith("/_wm_probe_") or url_path == "/soft404-page":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            body = b"<html><title>Page Not Found</title><body>Sorry, the requested document does not exist.</body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 8. Slow endpoint for timeout testing
        elif url_path == "/slow-endpoint":
            time.sleep(0.4)
            self.send_response(200)
            body = b"Slow Response Delivered"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 9. Recursive directory hierarchy
        elif url_path == "/dir":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            body = b"<html><head><title>Directory Listing</title></head><body>Directory Root</body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif url_path == "/dir/secret":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            body = b"Secret nested content discovered"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Default 404 for any other path
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


class TestLocalServerIntegration(unittest.TestCase):
    """Integration test suite executing against a live local HTTP server."""

    @classmethod
    def setUpClass(cls):
        # Start server on an ephemeral loopback port
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), IntegrationTestHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_status_200_and_title_extraction(self):
        """Test standard 200 discovery and page title extraction."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = HTTPRequester(cfg)
        res = requester.probe_path("/page200")

        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.title, "Test Success Page")
        self.assertTrue(len(res.body_hash_md5) > 0)

    def test_redirect_301_and_302_detection(self):
        """Test logging of 301 and 302 redirects with location headers."""
        cfg = ScanConfig(target_url=self.base_url, follow_redirects=False, wildcard_detection=False)
        requester = HTTPRequester(cfg)

        res_301 = requester.probe_path("/redirect-301")
        self.assertIsNotNone(res_301)
        self.assertEqual(res_301.status_code, 301)
        self.assertEqual(res_301.redirect_location, "/page200")

        res_302 = requester.probe_path("/redirect-302")
        self.assertIsNotNone(res_302)
        self.assertEqual(res_302.status_code, 302)
        self.assertEqual(res_302.redirect_location, "/auth/login")

    def test_forbidden_403_matching(self):
        """Test 403 Forbidden matching."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = HTTPRequester(cfg)
        res = requester.probe_path("/forbidden-403")

        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.content_length, len(b"Access Denied by Security Policy"))

    def test_not_found_404_filtering(self):
        """Test default 404 filtering suppresses not-found responses."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = HTTPRequester(cfg)
        res = requester.probe_path("/notfound-404")
        self.assertIsNone(res)

    def test_server_error_500_reporting(self):
        """Test 500 error reporting and matching."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=False)
        requester = HTTPRequester(cfg)
        res = requester.probe_path("/error-500")

        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 500)
        self.assertGreater(res.content_length, 0)

    def test_soft_404_automatic_suppression(self):
        """Test heuristic calibration automatically suppresses soft-404 error pages."""
        cfg = ScanConfig(target_url=self.base_url, wildcard_detection=True)
        requester = HTTPRequester(cfg)

        # Calibrate heuristics against the local server (seeds _wm_probe_* responses)
        calib = requester.calibrate_heuristics()
        self.assertTrue(calib["soft404_active"])

        # Probing another path with identical soft-404 body should be suppressed
        res = requester.probe_path("/soft404-page")
        self.assertIsNone(res, "Expected soft-404 page to be filtered out by heuristics")

    def test_slow_endpoint_timeout_handling(self):
        """Test timeout detection and classification on slow endpoints."""
        cfg = ScanConfig(target_url=self.base_url, timeout=0.1, retries=0, wildcard_detection=False)
        requester = HTTPRequester(cfg)
        res = requester.probe_path("/slow-endpoint")

        self.assertIsNone(res)
        self.assertGreaterEqual(requester.error_counts["timeouts"], 1)

    def test_connection_failure_handling(self):
        """Test unreachable port error classification and safe recovery."""
        # Port 59998 should not be listening
        cfg = ScanConfig(target_url="http://127.0.0.1:59998", timeout=0.5, retries=0, wildcard_detection=False)
        requester = HTTPRequester(cfg)
        res = requester.probe_path("/test")

        self.assertIsNone(res)
        self.assertGreaterEqual(requester.error_counts["connection_errors"], 1)

    def test_recursive_directory_discovery_integration(self):
        """Test recursive queue exploration against real local HTTP hierarchy."""
        cfg = ScanConfig(
            target_url=self.base_url,
            threads=2,
            recursive=True,
            max_depth=2,
            wildcard_detection=False,
        )
        requester = HTTPRequester(cfg)
        engine = ExecutionEngine(cfg, requester)

        # Seed discovery with /dir
        all_gen = set(engine.generator.get_all_paths())
        initial_completed = all_gen - {"/dir"}

        # Patch generator for /dir prefix to produce /dir/secret
        original_get_paths = engine.generator.get_all_paths
        def custom_get_paths(base_prefix=""):
            if base_prefix == "/dir":
                return ["/dir/secret"]
            return original_get_paths(base_prefix)
        engine.generator.get_all_paths = custom_get_paths

        results = engine.run(
            initial_completed_paths=initial_completed,
            extra_seed_paths={"/dir"},
        )

        found_paths = {r.path for r in results}
        self.assertIn("/dir", found_paths)
        self.assertIn("/dir/secret", found_paths)
        self.assertGreaterEqual(engine.total_enqueued, 2)


if __name__ == "__main__":
    unittest.main()
