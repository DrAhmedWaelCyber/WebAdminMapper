"""
WebAdminMapper - Unit Tests for Crawler & Harvester Module
==========================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from web_mapper.crawler import RouteHarvester

__author__ = "Ahmed Wael"


class TestRouteHarvester(unittest.TestCase):

    def test_extract_html_links(self):
        harvester = RouteHarvester("https://example.com")
        html_doc = """
        <html>
          <body>
            <a href="/admin/login">Admin Login</a>
            <a href="/api/v1/users">Users API</a>
            <a href="https://external.com/logout">External</a>
            <script src="/static/js/app.js"></script>
          </body>
        </html>
        """
        routes = harvester.extract_html_links(html_doc)
        self.assertIn("/admin/login", routes)
        self.assertIn("/api/v1/users", routes)
        self.assertNotIn("/logout", routes)


if __name__ == "__main__":
    unittest.main()
