"""
WebAdminMapper - Technology & CMS Fingerprinting Module
======================================================
Automated detection and fingerprinting of web servers, web application
frameworks, Content Management Systems (CMS), API gateways, and CDNs.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import re
from typing import Dict, List, Set

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


HEADER_SIGNATURES: Dict[str, List[tuple]] = {
    "server": [
        (re.compile(r"nginx/([\d.]+)?", re.I), "Nginx"),
        (re.compile(r"apache/([\d.]+)?", re.I), "Apache HTTP Server"),
        (re.compile(r"microsoft-iis/([\d.]+)?", re.I), "Microsoft IIS"),
        (re.compile(r"cloudflare", re.I), "Cloudflare CDN"),
        (re.compile(r"caddy", re.I), "Caddy Server"),
        (re.compile(r"gunicorn/([\d.]+)?", re.I), "Gunicorn (Python)"),
        (re.compile(r"werkzeug/([\d.]+)?", re.I), "Werkzeug/Flask (Python)"),
        (re.compile(r"litespeed", re.I), "LiteSpeed Web Server"),
        (re.compile(r"openresty/([\d.]+)?", re.I), "OpenResty (Nginx+Lua)"),
        (re.compile(r"envoy", re.I), "Envoy Proxy"),
        (re.compile(r"traefik", re.I), "Traefik Proxy"),
        (re.compile(r"kestrel", re.I), "Kestrel (.NET)"),
    ],
    "x-powered-by": [
        (re.compile(r"php/([\d.]+)?", re.I), "PHP"),
        (re.compile(r"asp\.net", re.I), "ASP.NET"),
        (re.compile(r"express", re.I), "Express.js (Node.js)"),
        (re.compile(r"next\.js", re.I), "Next.js (React)"),
        (re.compile(r"nuxt", re.I), "Nuxt.js (Vue)"),
        (re.compile(r"plesk", re.I), "Plesk Panel"),
        (re.compile(r"wp engine", re.I), "WP Engine"),
    ],
    "x-generator": [
        (re.compile(r"wordpress\s*([\d.]+)?", re.I), "WordPress"),
        (re.compile(r"drupal\s*([\d.]+)?", re.I), "Drupal"),
        (re.compile(r"joomla", re.I), "Joomla"),
        (re.compile(r"ghost", re.I), "Ghost CMS"),
    ],
}

COOKIE_SIGNATURES = [
    ("PHPSESSID", "PHP"),
    ("JSESSIONID", "Java (Servlet / Spring)"),
    ("ASPSESSIONID", "Classic ASP"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("connect.sid", "Node.js (Express Session)"),
    ("laravel_session", "Laravel (PHP)"),
    ("csrftoken", "Django (Python)"),
    ("rack.session", "Ruby on Rails"),
    ("wp-settings-", "WordPress"),
    ("XSRF-TOKEN", "Angular / SPA Framework"),
]

BODY_SIGNATURES = [
    (re.compile(r"/wp-content/|/wp-includes/", re.I), "WordPress CMS"),
    (re.compile(r"whitelabel\s+error\s+page", re.I), "Spring Boot (Java)"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django (Python)"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js (React)"),
    (re.compile(r"__NUXT__", re.I), "Nuxt.js (Vue)"),
    (re.compile(r"swagger-ui|swagger\.json", re.I), "Swagger / OpenAPI Documentation"),
    (re.compile(r"graphiql|graphql", re.I), "GraphQL API"),
    (re.compile(r"laravel", re.I), "Laravel Framework"),
    (re.compile(r"drupal\.js|drupalsettings", re.I), "Drupal CMS"),
    (re.compile(r"jira|atlassian", re.I), "Atlassian Suite"),
]


class TechProfiler:
    """
    Automated Web Application & Infrastructure Profiler.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self):
        self.detected: Set[str] = set()

    def analyze(self, headers: Dict[str, str], body_sample: bytes = b"") -> List[str]:
        """
        Analyze HTTP response headers and body content to identify running tech stacks.
        Authored by Ahmed Wael.
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # 1. Header Analysis
        for header_key, rules in HEADER_SIGNATURES.items():
            if header_key in headers_lower:
                val = headers_lower[header_key]
                for pattern, name in rules:
                    match = pattern.search(val)
                    if match:
                        ver = match.group(1) if match.groups() and match.group(1) else ""
                        tag = f"{name} {ver}".strip() if ver else name
                        self.detected.add(tag)

        # 2. Cookie Signatures
        set_cookie = headers_lower.get("set-cookie", "")
        for cookie_name, tech in COOKIE_SIGNATURES:
            if cookie_name.lower() in set_cookie.lower():
                self.detected.add(tech)

        # 3. CDN & Infrastructure Headers
        if "cf-ray" in headers_lower:
            self.detected.add("Cloudflare CDN")
        if "x-amz-cf-id" in headers_lower:
            self.detected.add("Amazon CloudFront")
        if "x-sucuri-id" in headers_lower:
            self.detected.add("Sucuri WAF")
        if "x-varnish" in headers_lower:
            self.detected.add("Varnish Cache")

        # 4. Body Content Inspection (first 16KB)
        if body_sample:
            try:
                decoded = body_sample[:16384].decode("utf-8", errors="ignore")
                for pattern, tech in BODY_SIGNATURES:
                    if pattern.search(decoded):
                        self.detected.add(tech)
            except Exception:
                pass

        return sorted(list(self.detected))

    def get_recommended_extensions(self) -> List[str]:
        """
        Recommend tailored file extensions to fuzz based on detected technologies.
        Authored by Ahmed Wael.
        """
        recs: Set[str] = set()
        detected_str = " ".join(self.detected).lower()

        if "php" in detected_str or "wordpress" in detected_str or "laravel" in detected_str:
            recs.update(["php", "php.bak", "phtml"])
        if "asp" in detected_str or "iis" in detected_str:
            recs.update(["aspx", "asp", "axd", "ashx", "config"])
        if "java" in detected_str or "spring" in detected_str:
            recs.update(["jsp", "action", "do", "json"])
        if "python" in detected_str or "django" in detected_str or "flask" in detected_str:
            recs.update(["py", "json", "env", "ini"])
        if "node" in detected_str or "express" in detected_str:
            recs.update(["js", "json", "ts"])

        # Universal backups & configs
        recs.update(["bak", "old", "zip", "json", "txt"])
        return sorted(list(recs))
