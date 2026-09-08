"""
WebAdminMapper - Unit Tests for HTTP Requester & Result Processing
==================================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.config import ScanConfig
from web_mapper.requester import HTTPRequester, ScanResult

__author__ = "Ahmed Wael"


class TestHTTPRequester(unittest.TestCase):

    def setUp(self):
        self.config = ScanConfig(target_url="https://example.com")
        self.requester = HTTPRequester(self.config)

    def test_process_response_basic(self):
        body = b"<html><head><title>Admin Portal</title></head><body>Welcome Admin</body></html>"
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "nginx/1.18.0",
            "Allow": "GET, POST, OPTIONS",
        }
        res = self.requester._process_response(
            path="/admin",
            full_url="https://example.com/admin",
            status_code=200,
            headers=headers,
            body=body,
            elapsed_ms=45.2,
        )

        self.assertIsNotNone(res)
        self.assertEqual(res.path, "/admin")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.title, "Admin Portal")
        self.assertEqual(res.content_length, len(body))
        self.assertEqual(len(res.body_hash_md5), 32)
        self.assertEqual(len(res.body_hash_sha256), 64)
        self.assertEqual(res.allowed_methods, "GET, POST, OPTIONS")

    def test_process_response_filtered_status_code(self):
        body = b"Not Found"
        headers = {"Content-Type": "text/plain"}
        # Default filter codes include 404
        res = self.requester._process_response(
            path="/not-found",
            full_url="https://example.com/not-found",
            status_code=404,
            headers=headers,
            body=body,
            elapsed_ms=20.0,
        )
        self.assertIsNone(res)

    def test_process_response_html_link_harvesting(self):
        html_body = b"""
        <html>
            <body>
                <a href="/dashboard">Dashboard</a>
                <a href="/api/v1/users">Users API</a>
            </body>
        </html>
        """
        headers = {"Content-Type": "text/html"}
        res = self.requester._process_response(
            path="/home",
            full_url="https://example.com/home",
            status_code=200,
            headers=headers,
            body=html_body,
            elapsed_ms=30.0,
        )
        self.assertIsNotNone(res)
        self.assertIn("/dashboard", res.discovered_links)
        self.assertIn("/api/v1/users", res.discovered_links)

    def test_process_response_filter_text(self):
        config = ScanConfig(target_url="https://example.com", filter_text="Maintenance Mode")
        requester = HTTPRequester(config)
        body = b"Sorry, we are currently under Maintenance Mode. Please check back later."
        res = requester._process_response(
            path="/test",
            full_url="https://example.com/test",
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=body,
            elapsed_ms=15.0,
        )
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
