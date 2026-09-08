"""
WebAdminMapper - Automated Security Assertion & Vulnerability Validation Module
================================================================================
Programmatically inspects target endpoints for common web application security flaws,
improper access controls, dangerous HTTP methods, sensitive file disclosures, and
information leakage patterns using safe, non-destructive validation techniques.

Classifies all findings with precision:
  - Confirmed Observation
  - Potential Finding
  - Informational
  - Requires Manual Verification

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from .requester import ScanResult

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


class AssertionClassification:
    """Standard classification categories to prevent false positive confusion."""
    CONFIRMED = "Confirmed Observation"
    POTENTIAL = "Potential Finding"
    INFORMATIONAL = "Informational"
    MANUAL_VERIFY = "Requires Manual Verification"


@dataclass
class SecurityAssertion:
    """Represents a classified security posture finding or policy assertion."""
    endpoint: str
    category: str
    severity: str  # "HIGH", "MEDIUM", "LOW", "INFO"
    title: str
    description: str
    evidence: str
    remediation: str
    classification: str = AssertionClassification.POTENTIAL
    confidence: str = "MEDIUM"  # "HIGH", "MEDIUM", "LOW"
    manual_verification_required: bool = True
    impact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "category": self.category,
            "severity": self.severity,
            "classification": self.classification,
            "confidence": self.confidence,
            "manual_verification_required": self.manual_verification_required,
            "impact": self.impact,
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

    API_PATH_PATTERN = re.compile(
        r"/(api|v1|v2|v3|graphql|swagger|openapi)(\b|/)",
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

    def validate_endpoint(
        self,
        result: ScanResult,
        raw_headers: Optional[Dict[str, str]] = None,
    ) -> List[SecurityAssertion]:
        """
        Evaluate a single scan result for security policy assertions.
        Accurately classifies observations into confirmed, potential, informational,
        and manual verification categories.
        Authored by Ahmed Wael.
        """
        assertions: List[SecurityAssertion] = []
        path = result.path
        clean_path = "/" + path.lstrip("/")

        # 1. Administrative Surface Access Control
        if self.ADMIN_PATH_PATTERN.search(clean_path):
            if result.status_code == 200:
                is_login = any(k in (result.title or "").lower() for k in ("login", "sign in", "auth"))
                if is_login:
                    assertions.append(SecurityAssertion(
                        endpoint=clean_path,
                        category="Access Control",
                        severity="LOW",
                        title="Administrative Authentication Gateway Observed",
                        description="Administrative route returned HTTP 200 with an authentication or login prompt.",
                        evidence=f"Status: 200 OK, Title: '{result.title or 'N/A'}'",
                        classification=AssertionClassification.INFORMATIONAL,
                        confidence="HIGH",
                        manual_verification_required=True,
                        impact="Entry point to privileged portal identified; assess credential brute-force protections and MFA.",
                        remediation="Enforce strict multi-factor authentication and IP allowlisting on administrative entry points.",
                    ))
                else:
                    assertions.append(SecurityAssertion(
                        endpoint=clean_path,
                        category="Improper Access Control",
                        severity="HIGH",
                        title="Potentially Unprotected Administrative Surface",
                        description="Administrative surface returned HTTP 200 without evident redirect to an authentication gateway.",
                        evidence=f"Status: 200 OK, Length: {result.content_length}B, Title: '{result.title or 'N/A'}'",
                        classification=AssertionClassification.POTENTIAL,
                        confidence="MEDIUM",
                        manual_verification_required=True,
                        impact="Unauthorized visitors may view sensitive administrative dashboards or configuration panels.",
                        remediation="Enforce mandatory session authentication middleware before serving administrative assets.",
                    ))
            elif result.status_code == 403:
                assertions.append(SecurityAssertion(
                    endpoint=clean_path,
                    category="Access Control",
                    severity="INFO",
                    title="Administrative Route Access Boundary Enforced (HTTP 403)",
                    description="Administrative route is actively blocked by server access controls.",
                    evidence=f"Status: 403 Forbidden, Size: {result.content_length}B",
                    classification=AssertionClassification.CONFIRMED,
                    confidence="HIGH",
                    manual_verification_required=True,
                    impact="Resource exists but public access is denied; verify against URL normalization bypasses.",
                    remediation="Maintain strict web server access control rules and verify reverse proxy path mappings.",
                ))

        # 2. Sensitive Configuration or Source Asset Exposure
        if self.SENSITIVE_FILE_PATTERN.search(clean_path):
            if result.status_code == 200:
                if result.content_length > 0:
                    assertions.append(SecurityAssertion(
                        endpoint=clean_path,
                        category="Sensitive Data Exposure",
                        severity="HIGH",
                        title="Publicly Accessible Configuration or Secret Asset",
                        description="A sensitive configuration, environment definition, or source archive is directly accessible over HTTP.",
                        evidence=f"Status: 200 OK, Size: {result.content_length} bytes, Hash: {result.body_hash_md5[:12]}...",
                        classification=AssertionClassification.CONFIRMED,
                        confidence="HIGH",
                        manual_verification_required=False,
                        impact="Severe exposure of credentials, database keys, or proprietary source code.",
                        remediation="Remove sensitive assets from the web document root and block sensitive extensions at server level.",
                    ))
                else:
                    assertions.append(SecurityAssertion(
                        endpoint=clean_path,
                        category="Sensitive Data Exposure",
                        severity="MEDIUM",
                        title="Zero-Byte Sensitive Route Response",
                        description="Endpoint returned HTTP 200 with zero bytes on a sensitive filename pattern.",
                        evidence=f"Status: 200 OK, Size: 0 bytes",
                        classification=AssertionClassification.MANUAL_VERIFY,
                        confidence="LOW",
                        manual_verification_required=True,
                        impact="Ambiguous response; verify if asset exists or is dynamically generated by application router.",
                        remediation="Ensure non-existent assets return HTTP 404 and sensitive file patterns are blocked.",
                    ))
            elif result.status_code == 403:
                assertions.append(SecurityAssertion(
                    endpoint=clean_path,
                    category="Access Control",
                    severity="INFO",
                    title="Sensitive File Pattern Blocked by Security Rule (HTTP 403)",
                    description="Sensitive path is protected by server deny rules.",
                    evidence=f"Status: 403 Forbidden on {clean_path}",
                    classification=AssertionClassification.CONFIRMED,
                    confidence="HIGH",
                    manual_verification_required=False,
                    impact="Access is successfully prohibited by origin policy.",
                    remediation="Maintain deny rules across all virtual host mappings.",
                ))

        # 3. HTTP 500 Server Errors (Requires Manual Verification)
        if result.status_code >= 500:
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Information Disclosure",
                severity="MEDIUM",
                title=f"Server Error & Unhandled Exception (HTTP {result.status_code})",
                description="Endpoint produced a server error. Requires manual review to confirm whether debug details or stack traces are leaked.",
                evidence=f"HTTP Status: {result.status_code}, Response Size: {result.content_length}B",
                classification=AssertionClassification.MANUAL_VERIFY,
                confidence="MEDIUM",
                manual_verification_required=True,
                impact="Internal errors may bubble unhandled exceptions, reveal framework versions, or leak query fragments.",
                remediation="Implement custom error handling to return generic 500 templates without debug traces.",
            ))

        # 4. API Attack Surface Mapping
        if self.API_PATH_PATTERN.search(clean_path) and result.status_code in (200, 204):
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Attack Surface Mapping",
                severity="INFO",
                title="API Endpoint Surface Identified",
                description="API route discovered on application. Requires contextual audit of authentication, rate-limiting, and authorization.",
                evidence=f"Status: {result.status_code}, Path: {clean_path}",
                classification=AssertionClassification.INFORMATIONAL,
                confidence="HIGH",
                manual_verification_required=True,
                impact="APIs often expose object references (BOLA/IDOR) and require rigorous auth auditing.",
                remediation="Enforce token-based authentication (OAuth2/JWT) and validate authorization on every API route.",
            ))

        # 5. Dangerous HTTP Methods
        if result.allowed_methods:
            methods = [m.strip().upper() for m in result.allowed_methods.split(",")]
            if "TRACE" in methods or "TRACK" in methods:
                assertions.append(SecurityAssertion(
                    endpoint=clean_path,
                    category="Insecure Configuration",
                    severity="MEDIUM",
                    title="HTTP TRACE/TRACK Method Enabled",
                    description="Server supports TRACE/TRACK method, which can be leveraged in Cross-Site Tracing (XST) attacks.",
                    evidence=f"Allow Header: {result.allowed_methods}",
                    classification=AssertionClassification.CONFIRMED,
                    confidence="HIGH",
                    manual_verification_required=False,
                    impact="Allows reflected cookie harvesting via client-side scripts.",
                    remediation="Disable TRACE and TRACK in server configuration (e.g. TraceEnable Off).",
                ))
            if "PUT" in methods or "DELETE" in methods:
                assertions.append(SecurityAssertion(
                    endpoint=clean_path,
                    category="Insecure Configuration",
                    severity="LOW",
                    title="Potentially Unrestricted HTTP Modification Verbs",
                    description=f"Endpoint advertises modification methods ({', '.join(m for m in methods if m in ('PUT', 'DELETE'))}).",
                    evidence=f"Allow Header: {result.allowed_methods}",
                    classification=AssertionClassification.MANUAL_VERIFY,
                    confidence="MEDIUM",
                    manual_verification_required=True,
                    impact="Modification verbs require manual verification to confirm authorization middleware is strictly applied.",
                    remediation="Audit endpoints accepting PUT/DELETE verbs to ensure strict authorization gates are enforced.",
                ))

        # 6. Technology Version Disclosure
        if result.server and any(char.isdigit() for char in result.server):
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Information Disclosure",
                severity="LOW",
                title="Verbose Server Software Version Disclosure",
                description="Web server reveals exact software version strings in HTTP headers.",
                evidence=f"Server Header: '{result.server}'",
                classification=AssertionClassification.CONFIRMED,
                confidence="HIGH",
                manual_verification_required=False,
                impact="Assists attackers in targeting published CVE vulnerabilities for specific version numbers.",
                remediation="Configure server banners to suppress granular version tokens (e.g. ServerTokens Prod).",
            ))

        # 7. Cache-Control on Sensitive Surfaces
        if result.status_code == 200 and (self.ADMIN_PATH_PATTERN.search(clean_path) or "api" in clean_path.lower()):
            if raw_headers:
                cache_ctrl = raw_headers.get("Cache-Control", raw_headers.get("cache-control", "")).lower()
                if "no-store" not in cache_ctrl:
                    assertions.append(SecurityAssertion(
                        endpoint=clean_path,
                        category="Sensitive Data Exposure",
                        severity="LOW",
                        title="Missing Sensitive Cache-Control Directive",
                        description="Sensitive or API endpoint response does not enforce 'no-store'.",
                        evidence=f"Cache-Control: '{cache_ctrl or 'Not Set'}'",
                        classification=AssertionClassification.CONFIRMED,
                        confidence="HIGH",
                        manual_verification_required=False,
                        impact="Sensitive information may be stored in shared intermediary proxies or local browser caches.",
                        remediation="Set 'Cache-Control: no-store, no-cache, must-revalidate' on all authenticated and API endpoints.",
                    ))

        # 8. Dynamic Input Injection Surface Mapping
        if "?" in clean_path or "=" in clean_path:
            assertions.append(SecurityAssertion(
                endpoint=clean_path,
                category="Injection Surface Analysis",
                severity="INFO",
                title="Active Query Parameter Input Surface",
                description="Endpoint accepts dynamic query parameters that should be audited for injection vulnerabilities.",
                evidence=f"Target parameter path: {clean_path}",
                classification=AssertionClassification.INFORMATIONAL,
                confidence="HIGH",
                manual_verification_required=True,
                impact="Input parameters may expose SQLi, XSS, or SSRF if input validation is missing.",
                remediation="Apply parameterized queries, strict input validation, and contextual output encoding.",
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
