"""
WebAdminMapper - Unit Tests for Site Map Module
===============================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.requester import ScanResult
from web_mapper.sitemap import SiteMapTree

__author__ = "Ahmed Wael"


class TestSiteMapTree(unittest.TestCase):

    def test_tree_construction(self):
        tree = SiteMapTree("https://example.com")
        res1 = ScanResult(path="/admin", url="https://example.com/admin", status_code=301, content_length=0, response_time_ms=5.0)
        res2 = ScanResult(path="/admin/dashboard", url="https://example.com/admin/dashboard", status_code=200, content_length=150, response_time_ms=10.0)

        tree.add_result(res1)
        tree.add_result(res2)

        ascii_out = tree.render_ascii()
        self.assertIn("admin", ascii_out)
        self.assertIn("dashboard", ascii_out)
        self.assertEqual(tree.count_nodes(), 2)


if __name__ == "__main__":
    unittest.main()
