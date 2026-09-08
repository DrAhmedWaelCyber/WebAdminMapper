"""
WebAdminMapper - Unit Tests for Network Diagnostics Module
==========================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.network_diag import NetworkDiagnostics

__author__ = "Ahmed Wael"


class TestNetworkDiagnostics(unittest.TestCase):

    def test_localhost_inspection(self):
        diag = NetworkDiagnostics.inspect("http://127.0.0.1:80")
        self.assertIsNotNone(diag)
        self.assertEqual(diag.hostname, "127.0.0.1")
        self.assertEqual(diag.port, 80)
        self.assertIn("127.0.0.1", diag.ip_addresses)

    def test_invalid_url(self):
        diag = NetworkDiagnostics.inspect("invalid_url_without_scheme")
        self.assertIsNone(diag)


if __name__ == "__main__":
    unittest.main()
