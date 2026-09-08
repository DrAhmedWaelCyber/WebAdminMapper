"""
WebAdminMapper - Administrative Crawler & Route Harvester Module
================================================================
Parses robots.txt, sitemap.xml, and harvests in-scope endpoints from
discovered HTML responses, forms, and client-side links.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import re
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

from .requester import HTTPRequester

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"

LINK_REGEX = re.compile(r"""(?:href|action|src)=["']([^"'#>]+)["']""", re.IGNORECASE)
SITEMAP_LOC_REGEX = re.compile(r"<loc>(.*?)</loc>", re.IGNORECASE)


class RouteHarvester:
    """
    Discovers endpoints from robots.txt, sitemaps, and HTML response parsing.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed_target = urlparse(target_url)
        self.discovered_routes: Set[str] = set()

    def harvest_robots_txt(self, requester: HTTPRequester) -> Set[str]:
        """Fetch and extract all Disallow and Allow directives from /robots.txt."""
        res = requester._raw_probe("/robots.txt")
        if not res or res[0] != 200:
            return set()

        body_text = res[1].decode("utf-8", errors="ignore")
        found = set()

        for line in body_text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    raw_path = parts[1].strip()
                    # Clean wildcards and query symbols for route mapping
                    clean = raw_path.split("$")[0].split("*")[0].strip()
                    if clean and clean.startswith("/"):
                        found.add(clean)

        self.discovered_routes.update(found)
        return found

    def harvest_sitemap_xml(self, requester: HTTPRequester) -> Set[str]:
        """Fetch and extract URLs from /sitemap.xml."""
        res = requester._raw_probe("/sitemap.xml")
        if not res or res[0] != 200:
            return set()

        body_text = res[1].decode("utf-8", errors="ignore")
        found = set()

        for match in SITEMAP_LOC_REGEX.finditer(body_text):
            loc_url = match.group(1).strip()
            parsed_loc = urlparse(loc_url)
            # Ensure in-scope host
            if parsed_loc.netloc == self.parsed_target.netloc or not parsed_loc.netloc:
                clean_path = parsed_loc.path or "/"
                if clean_path != "/":
                    found.add(clean_path)

        self.discovered_routes.update(found)
        return found

    def extract_html_links(self, html_content: str) -> Set[str]:
        """Extract internal in-scope routes from HTML content."""
        if not html_content:
            return set()

        found = set()
        for match in LINK_REGEX.finditer(html_content):
            raw_url = match.group(1).strip()
            if raw_url.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue

            parsed = urlparse(raw_url)
            if not parsed.netloc or parsed.netloc == self.parsed_target.netloc:
                path = parsed.path
                if path and path.startswith("/") and path != "/":
                    # Skip common media assets
                    if not path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico")):
                        found.add(path)

        self.discovered_routes.update(found)
        return found
