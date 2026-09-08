"""
WebAdminMapper - Automated Security Assertion & Vulnerability Validation Module
================================================================================
Programmatically inspects target endpoints for common web application security flaws,
improper access controls, dangerous HTTP methods, sensitive file disclosures, and
information leakage patterns using safe, non-destructive validation techniques.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from .requester import ScanResult

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


@dataclass
class SecurityAssertion:
    """Represents a validated security posture finding or policy assertion."""
    endpoint: str
    category: str
    severity: str  # "HIGH", "MEDIUM", "LOW", "INFO"
    title: str
    description: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, any]:
        return {
            "endpoint": self.endpoint,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "author": __author__,
        }


class SecurityAssertionValidator:
    """
    Automated security assertion and non-destructive vulnerability validator.
    Authored and designed by Ahmed Wael.
    """

    ADMIN_PATH_PATTERN = re.compile(
        r"/(admin|administrator|dashboard|cpanel|actuator|kibana|grafana|phpmyadmin|env|config)(\b|/)",
        re.IGNORECASE,
    )

    SENSITIVE_FILE_PATTERN = re.compile(
        r"(\.env|\.git|\.sql|\.bak|\.backup|\.tar\.gz|\.zip|\.cfg|\.ini|\.log|\.conf|\.key|\.pem)$"
        r"|/(docker-compose\.ya?ml|web\.config|database\.yml|id_rsa)$",
        re.IGNORECASE,
    )

    STACK_TRACE_PATTERNS = [
        re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
        re.compile(r"Fatal error:", re.IGNORECASE),
        re.compile(r"org\.springframework\.", re.IGNORECASE),
        re.compile(r"java\.lang\.[A-Za-z]+Exception", re.IGNORECASE),
        re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
        re.compile(r"SQLSTATE\[[0-9A-Z]+\]", re.IGNORECASE),
        re.compile(r"Unhandled rejection", re.IGNORECASE),
    ]

    def validate_endpoint(self, result: ScanResult, raw_headers: Optional[Dict[str, str]] = None) -> List[SecurityAssertion]:
        """
        Evaluate a single scan result for security policy violations and vulnerabilities.
        Authored by Ahmed Wael.
        """
        assertions: List[SecurityAssertion] = []
        path = result.path
        clean_path = "/" + path.lstrip("/")

        # 1. Improper Access Control - Unprotected Administrative Endpoints
        if result.status_code == 200 and self.ADMIN_PATH_PATTERN.search(clean_path):
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Improper Access Control",
                severity="HIGH",
                title="Unrestricted Administrative Endpoint Access",
                description="Administrative control surface returned HTTP 200 without enforcing authentication or access gates.",
                evidence=f"HTTP Status: {result.status_code}, Length: {result.content_length}B, Title: '{result.title or 'N/A'}'",
                remediation="Enforce strict authentication middleware, session verification, and IP-level allowlists on administrative routes.",
            ))

        # 2. Sensitive Data Exposure - Direct Access to Backup & Configuration Assets
        if result.status_code == 200 and self.SENSITIVE_FILE_PATTERN.search(clean_path):
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Sensitive Data Exposure",
                severity="HIGH",
                title="Publicly Accessible Configuration or Backup Asset",
                description="A sensitive source archive, environment file, or database backup is directly accessible over HTTP.",
                evidence=f"Accessible path: {clean_path}, Status: {result.status_code}, Size: {result.content_length} bytes",
                remediation="Remove sensitive archives from document roots and configure web server access rules to block sensitive file extensions.",
            ))

        # 3. Dangerous HTTP Verbs & Verb Tampering
        if result.allowed_methods:
            methods = [m.strip().upper() for m in result.allowed_methods.split(",")]
            if "TRACE" in methods or "TRACK" in methods:
                assertions.append(SecurityAssertion(
                    endpoint=clean_path,
                    category="Insecure Configuration",
                    severity="MEDIUM",
                    title="HTTP TRACE/TRACK Method Enabled",
                    description="The server supports the HTTP TRACE/TRACK method, which can be leveraged in Cross-Site Tracing (XST) attacks.",
                    evidence=f"Allow Header: {result.allowed_methods}",
                    remediation="Disable HTTP TRACE and TRACK methods in web server configuration (e.g., TraceEnable Off).",
                ))
            if "PUT" in methods or "DELETE" in methods:
                assertions.append(SecurityAssertion(
                    endpoint=clean_path,
                    category="Insecure Configuration",
                    severity="LOW",
                    title="Potentially Unrestricted HTTP Modification Verbs",
                    description=f"Endpoint advertises modification methods ({', '.join(m for m in methods if m in ('PUT', 'DELETE'))}) without granular method gating.",
                    evidence=f"Allow Header: {result.allowed_methods}",
                    remediation="Audit endpoints accepting PUT/DELETE verbs to ensure strict authorization controls are enforced.",
                ))

        # 4. Verbose Technology Version Disclosure
        if result.server and any(char.isdigit() for char in result.server):
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Information Disclosure",
                severity="LOW",
                title="Verbose Server Software Version Disclosure",
                description="Web server reveals exact software version strings in HTTP headers, facilitating attacker reconnaissance.",
                evidence=f"Server Header: {result.server}",
                remediation="Configure server banners to suppress detailed version tokens (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
            ))

        # 5. Missing Cache Controls on Sensitive Content
        if result.status_code == 200 and (self.ADMIN_PATH_PATTERN.search(clean_path) or "api" in clean_path.lower()):
            if raw_headers:
                cache_ctrl = raw_headers.get("Cache-Control", raw_headers.get("cache-control", "")).lower()
                if "no-store" not in cache_ctrl:
                    assertions.append(SecurityAssertion(
                        endpoint=clean_path,
                        category="Sensitive Data Exposure",
                        severity="LOW",
                        title="Missing Sensitive Cache-Control Directive",
                        description="Sensitive or API endpoint response does not enforce 'no-store', risking caching in shared proxy or browser caches.",
                        evidence=f"Cache-Control: '{cache_ctrl or 'Not Set'}'",
                        remediation="Set 'Cache-Control: no-store, no-cache, must-revalidate' on all authenticated and API endpoints.",
                    ))

        # 6. Unhandled Exception / Stack Trace Exposure
        if result.status_code >= 500:
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Information Disclosure",
                severity="MEDIUM",
                title="Server-Side Exception & 5xx State",
                description="The endpoint generated a server-side error, potentially leaking debug traces or architectural details.",
                evidence=f"HTTP Status: {result.status_code}, Length: {result.content_length} bytes",
                remediation="Implement global custom error handling pages to prevent unhandled exception bubbles and stack leakage.",
            ))

        # 7. Non-Destructive Input Injection Surface Mapping
        if "?" in clean_path or "=" in clean_path:
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Injection Surface Analysis",
                severity="INFO",
                title="Active Query Parameter Input Surface",
                description="Endpoint accepts dynamic query parameters that should be validated and contextualized against injection flaws.",
                evidence=f"Target parameter path: {clean_path}",
                remediation="Apply parameterized queries, strict schema validation, and context-aware output encoding across all input parameters.",
            ))

        return assertions

    def validate_all(self, results: List[ScanResult]) -> List[SecurityAssertion]:
        """
        Validate an entire batch of scan results and return deduplicated assertions.
        Authored by Ahmed Wael.
        """
        all_assertions: List[SecurityAssertion] = []
        seen: Set[str] = set()

        for res in results:
            findings = self.validate_endpoint(res)
            for f in findings:
                key = f"{f.endpoint}::{f.title}"
                if key not in seen:
                    seen.add(key)
                    all_assertions.append(f)

        return all_assertions
