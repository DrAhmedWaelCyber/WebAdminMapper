"""
WebAdminMapper - Defensive Security Assessment & Compliance Validation Engine
==============================================================================
Programmatically audits discovered application endpoints and server configurations
against industry-standard security baselines:
  - OWASP ASVS v4.0 (Application Security Verification Standard)
  - CIS Web Application & Server Configuration Benchmarks
  - NIST SP 800-53 Rev 5 (Security and Privacy Controls for Information Systems)

Evaluates endpoints using non-destructive, safe automated assertions to identify
misconfigurations, weak access controls, sensitive asset exposures, and injection
attack surfaces.

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from .requester import ScanResult

__author__ = "Ahmed Wael"
__email__ = "ahmedwael6143@gmail.com"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"
__version__ = "1.0.0"


class ComplianceBenchmark:
    """Supported compliance benchmark baselines."""
    ALL = "all"
    OWASP = "owasp"
    CIS = "cis"
    NIST = "nist"


class ComplianceSeverity:
    """Severity ratings for compliance violations."""
    CRITICAL = "HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStatus:
    """Evaluation status for compliance rules."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class ComplianceFinding:
    """
    Represents an audited compliance violation, warning, or passed assertion.
    Authored and designed by Ahmed Wael.
    """
    rule_id: str
    benchmark: str
    category: str
    severity: str
    status: str
    title: str
    endpoint: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "benchmark": self.benchmark,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "title": self.title,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "author": __author__,
        }


@dataclass
class ComplianceRule:
    """Specification of an industry-standard compliance rule."""
    rule_id: str
    benchmark: str  # OWASP, CIS, NIST
    category: str
    severity: str
    title: str
    description: str
    remediation: str
    weight: float = 10.0


@dataclass
class ComplianceReport:
    """
    Comprehensive compliance evaluation report across evaluated benchmarks.
    Authored and designed by Ahmed Wael.
    """
    target_url: str
    benchmark: str
    findings: List[ComplianceFinding] = field(default_factory=list)
    passed_rules: int = 0
    failed_rules: int = 0
    warn_rules: int = 0
    compliance_score: float = 100.0
    compliance_grade: str = "A+ (Compliant)"
    benchmark_scores: Dict[str, float] = field(default_factory=dict)
    author: str = __author__

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "benchmark": self.benchmark,
            "compliance_score": round(self.compliance_score, 1),
            "compliance_grade": self.compliance_grade,
            "summary": {
                "passed_rules": self.passed_rules,
                "failed_rules": self.failed_rules,
                "warn_rules": self.warn_rules,
                "total_findings": len(self.findings),
            },
            "benchmark_scores": {k: round(v, 1) for k, v in self.benchmark_scores.items()},
            "findings": [f.to_dict() for f in self.findings],
            "author": self.author,
        }


class ComplianceEngine:
    """
    Defensive Security Assessment and Compliance Validation Engine.
    Authored and designed by Ahmed Wael.

    Audits discovered endpoints, headers, and configurations against
    OWASP ASVS v4.0, CIS Web Benchmarks, and NIST SP 800-53 Rev 5 baselines.
    """

    ADMIN_SURFACES = re.compile(
        r"/(admin|administrator|dashboard|cpanel|actuator|kibana|grafana|phpmyadmin|env|config)(\b|/)",
        re.IGNORECASE,
    )

    SENSITIVE_FILES = re.compile(
        r"(\.env|\.sql|\.bak|\.backup|\.tar\.gz|\.zip|\.cfg|\.ini|\.log|\.conf|\.key|\.pem)$"
        r"|/(docker-compose\.ya?ml|web\.config|database\.yml|id_rsa|id_dsa)$",
        re.IGNORECASE,
    )

    REPO_PATTERNS = re.compile(
        r"(/(\.git|\.svn|\.hg)(/|$))",
        re.IGNORECASE,
    )

    SERVER_BANNER_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]

    def __init__(self, benchmark: str = "all"):
        """
        Initialize compliance engine with target benchmark standard.
        Supported: 'all', 'owasp', 'cis', 'nist'.
        """
        self.benchmark = benchmark.lower()
        if self.benchmark not in ("all", "owasp", "cis", "nist"):
            self.benchmark = "all"

        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> Dict[str, ComplianceRule]:
        """Define rule catalog across OWASP, CIS, and NIST standards."""
        return {
            # 1. Access Control & Administrative Exposure
            "OWASP-ASVS-V4.1": ComplianceRule(
                rule_id="OWASP-ASVS-V4.1",
                benchmark="OWASP ASVS v4.0",
                category="Access Control Verification",
                severity=ComplianceSeverity.HIGH,
                title="Unauthenticated Administrative Interface Access",
                description="Verify that administrative and operational interfaces enforce strict authentication and access control gates.",
                remediation="Enforce mandatory multi-factor authentication, session gating, and IP allowlists on all administrative interfaces.",
                weight=25.0,
            ),
            "NIST-AC-3": ComplianceRule(
                rule_id="NIST-AC-3",
                benchmark="NIST SP 800-53 Rev 5",
                category="Access Enforcement",
                severity=ComplianceSeverity.HIGH,
                title="Unrestricted Access Control on Sensitive Surfaces",
                description="The system must enforce approved authorizations for logical access to administrative information and functions.",
                remediation="Configure role-based access control (RBAC) and authorization checks prior to fulfilling requests to sensitive endpoints.",
                weight=25.0,
            ),
            "CIS-WEB-1.1": ComplianceRule(
                rule_id="CIS-WEB-1.1",
                benchmark="CIS Web Benchmark",
                category="Access Control",
                severity=ComplianceSeverity.HIGH,
                title="Public Exposure of Privileged Administrative Portals",
                description="Administrative tools, consoles, and dashboards should not be directly routable from untrusted public networks.",
                remediation="Restrict administrative route bindings to internal management networks, VPNs, or private subnets.",
                weight=25.0,
            ),

            # 2. Sensitive Data & Secrets Exposure
            "OWASP-ASVS-V8.1": ComplianceRule(
                rule_id="OWASP-ASVS-V8.1",
                benchmark="OWASP ASVS v4.0",
                category="Data Protection",
                severity=ComplianceSeverity.HIGH,
                title="Exposure of Sensitive Configuration and Secrets",
                description="Verify that sensitive configuration files, environment definitions, and secrets are not publicly accessible.",
                remediation="Remove sensitive assets from the web document root and block direct file requests via web server access rules.",
                weight=20.0,
            ),
            "NIST-SC-28": ComplianceRule(
                rule_id="NIST-SC-28",
                benchmark="NIST SP 800-53 Rev 5",
                category="Protection of Information at Rest",
                severity=ComplianceSeverity.HIGH,
                title="Unprotected System Configuration and Backup Assets",
                description="Protect confidential system configuration files, database backups, and credentials from unauthorized exposure.",
                remediation="Store backups and credentials in isolated, encrypted vaults outside of the public HTTP document root.",
                weight=20.0,
            ),
            "CIS-WEB-2.3": ComplianceRule(
                rule_id="CIS-WEB-2.3",
                benchmark="CIS Web Benchmark",
                category="Sensitive Exposure",
                severity=ComplianceSeverity.HIGH,
                title="Exposed Database and Server Configuration Backups",
                description="Do not store database dumps, archive backups, or configuration files within document root directories.",
                remediation="Audit web root directories and deploy web server deny rules matching .sql, .bak, .env, and .conf extensions.",
                weight=20.0,
            ),

            # 3. Repository & Version Control Disclosure
            "OWASP-ASVS-V14.3": ComplianceRule(
                rule_id="OWASP-ASVS-V14.3",
                benchmark="OWASP ASVS v4.0",
                category="Configuration Verification",
                severity=ComplianceSeverity.HIGH,
                title="Version Control Metadata Exposure (.git / .svn)",
                description="Verify that source code management repositories (.git, .svn) are not exposed via the web server.",
                remediation="Block access to .git, .svn, and .hg directories at the web server or reverse proxy level.",
                weight=20.0,
            ),
            "CIS-WEB-2.4": ComplianceRule(
                rule_id="CIS-WEB-2.4",
                benchmark="CIS Web Benchmark",
                category="Information Disclosure",
                severity=ComplianceSeverity.HIGH,
                title="Exposed SCM Repositories in Document Root",
                description="Ensure source code management metadata folders are blocked from HTTP retrieval.",
                remediation="Configure server location blocks to return HTTP 404 or 403 on requests matching /\\.(git|svn|hg).",
                weight=20.0,
            ),

            # 4. Server Version Banner & Technology Leakage
            "OWASP-ASVS-V14.3-B": ComplianceRule(
                rule_id="OWASP-ASVS-V14.3-B",
                benchmark="OWASP ASVS v4.0",
                category="Configuration Verification",
                severity=ComplianceSeverity.LOW,
                title="Detailed Server and Runtime Version Disclosure",
                description="Verify that the application server suppresses granular version tokens in HTTP response headers.",
                remediation="Disable verbose server headers (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
                weight=5.0,
            ),
            "CIS-WEB-1.3": ComplianceRule(
                rule_id="CIS-WEB-1.3",
                benchmark="CIS Web Benchmark",
                category="Configuration Baseline",
                severity=ComplianceSeverity.LOW,
                title="Verbose Web Server Banner Disclosure",
                description="Configure web server to minimize information disclosed in the Server and X-Powered-By response headers.",
                remediation="Strip Server and X-Powered-By headers using reverse proxy rules or server configuration directives.",
                weight=5.0,
            ),
            "NIST-SI-11-A": ComplianceRule(
                rule_id="NIST-SI-11-A",
                benchmark="NIST SP 800-53 Rev 5",
                category="Error Handling & Information Disclosure",
                severity=ComplianceSeverity.LOW,
                title="Architectural Technology Leakage via Headers",
                description="The system must prevent disclosure of internal architectural components and framework versions.",
                remediation="Configure framework and runtime middleware to suppress identifying response headers.",
                weight=5.0,
            ),

            # 5. Unhandled Server Exception & Stack Traces
            "OWASP-ASVS-V14.4": ComplianceRule(
                rule_id="OWASP-ASVS-V14.4",
                benchmark="OWASP ASVS v4.0",
                category="Error Handling",
                severity=ComplianceSeverity.MEDIUM,
                title="Server-Side Exception & Unhandled 5xx State",
                description="Verify that the application handles errors gracefully and returns generic error messages to clients.",
                remediation="Implement custom, standardized error pages (404, 500) and log diagnostic details internally.",
                weight=10.0,
            ),
            "NIST-SI-11-B": ComplianceRule(
                rule_id="NIST-SI-11-B",
                benchmark="NIST SP 800-53 Rev 5",
                category="Error Handling",
                severity=ComplianceSeverity.MEDIUM,
                title="Improper Error Handling and Debug Information",
                description="The information system must generate error messages that provide necessary information without revealing details exploited by adversaries.",
                remediation="Sanitize all error outputs and configure production environments to disable debug modes.",
                weight=10.0,
            ),

            # 6. Transport Security & HTTPS Enforcement
            "OWASP-ASVS-V14.1": ComplianceRule(
                rule_id="OWASP-ASVS-V14.1",
                benchmark="OWASP ASVS v4.0",
                category="Communications Security",
                severity=ComplianceSeverity.HIGH,
                title="Missing HTTP Strict Transport Security (HSTS)",
                description="Verify that all communications use TLS and enforce Strict-Transport-Security with a long max-age.",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                weight=15.0,
            ),
            "NIST-SC-8": ComplianceRule(
                rule_id="NIST-SC-8",
                benchmark="NIST SP 800-53 Rev 5",
                category="Transmission Confidentiality and Integrity",
                severity=ComplianceSeverity.HIGH,
                title="Inadequate Transport Layer Encryption Policy",
                description="The information system must protect the confidentiality and integrity of transmitted information using strict encryption standards.",
                remediation="Enforce TLS 1.2+ across all application routes and deploy HSTS headers with preload directives.",
                weight=15.0,
            ),
            "CIS-WEB-3.1": ComplianceRule(
                rule_id="CIS-WEB-3.1",
                benchmark="CIS Web Benchmark",
                category="Transport Layer Security",
                severity=ComplianceSeverity.HIGH,
                title="Missing HSTS Directive on Web Application",
                description="Ensure the web server transmits the HSTS header to prevent SSL-stripping and protocol downgrade attacks.",
                remediation="Configure web server to inject Strict-Transport-Security header on all virtual hosts.",
                weight=15.0,
            ),

            # 7. Client-Side Security Controls (CSP & Clickjacking)
            "OWASP-ASVS-V14.2-CSP": ComplianceRule(
                rule_id="OWASP-ASVS-V14.2-CSP",
                benchmark="OWASP ASVS v4.0",
                category="Configuration Verification",
                severity=ComplianceSeverity.MEDIUM,
                title="Missing Content Security Policy (CSP)",
                description="Verify that a Content Security Policy is defined to mitigate cross-site scripting (XSS) and code injection.",
                remediation="Define a restrictive Content-Security-Policy (e.g. default-src 'self'; object-src 'none'; base-uri 'self').",
                weight=10.0,
            ),
            "OWASP-ASVS-V14.2-XFO": ComplianceRule(
                rule_id="OWASP-ASVS-V14.2-XFO",
                benchmark="OWASP ASVS v4.0",
                category="Configuration Verification",
                severity=ComplianceSeverity.MEDIUM,
                title="Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
                description="Verify that frame restriction headers or CSP frame-ancestors are set to protect against UI redressing / clickjacking.",
                remediation="Send 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none'' in all responses.",
                weight=10.0,
            ),
            "CIS-WEB-3.2": ComplianceRule(
                rule_id="CIS-WEB-3.2",
                benchmark="CIS Web Benchmark",
                category="HTTP Header Security",
                severity=ComplianceSeverity.MEDIUM,
                title="Missing Clickjacking Protection Header",
                description="Configure web server to send X-Frame-Options or CSP frame-ancestors directive to prevent framing.",
                remediation="Configure global header injection: 'X-Frame-Options: SAMEORIGIN'.",
                weight=10.0,
            ),

            # 8. MIME Sniffing Defense
            "OWASP-ASVS-V14.2-NOSNIFF": ComplianceRule(
                rule_id="OWASP-ASVS-V14.2-NOSNIFF",
                benchmark="OWASP ASVS v4.0",
                category="Configuration Verification",
                severity=ComplianceSeverity.LOW,
                title="Missing X-Content-Type-Options: nosniff Header",
                description="Verify that X-Content-Type-Options is set to 'nosniff' to prevent browsers from MIME-sniffing response bodies.",
                remediation="Add 'X-Content-Type-Options: nosniff' header across all HTTP responses.",
                weight=5.0,
            ),
            "CIS-WEB-3.3": ComplianceRule(
                rule_id="CIS-WEB-3.3",
                benchmark="CIS Web Benchmark",
                category="HTTP Header Security",
                severity=ComplianceSeverity.LOW,
                title="Missing MIME Sniffing Suppression Header",
                description="Ensure the web server instructs client browsers not to override the declared Content-Type header.",
                remediation="Add 'X-Content-Type-Options: nosniff' header directive to the global web server configuration.",
                weight=5.0,
            ),

            # 9. Sensitive Data Caching Controls
            "OWASP-ASVS-V8.2": ComplianceRule(
                rule_id="OWASP-ASVS-V8.2",
                benchmark="OWASP ASVS v4.0",
                category="Data Protection",
                severity=ComplianceSeverity.LOW,
                title="Missing Cache-Control: no-store on Sensitive Endpoints",
                description="Verify that sensitive responses (authenticated, administrative, API) prevent caching in intermediate proxies and browsers.",
                remediation="Set 'Cache-Control: no-store, no-cache, must-revalidate' and 'Pragma: no-cache' on authenticated responses.",
                weight=5.0,
            ),

            # 10. Injection Surface Mapping & Input Validation
            "OWASP-ASVS-V5.1": ComplianceRule(
                rule_id="OWASP-ASVS-V5.1",
                benchmark="OWASP ASVS v4.0",
                category="Validation, Sanitization and Encoding",
                severity=ComplianceSeverity.INFO,
                title="Dynamic Parameter Injection Attack Surface",
                description="Identify query parameter interfaces requiring strict positive input validation and parameterized processing.",
                remediation="Apply parameterized queries, strong schema validation, and context-aware output encoding across all inputs.",
                weight=2.0,
            ),
            "NIST-SI-10": ComplianceRule(
                rule_id="NIST-SI-10",
                benchmark="NIST SP 800-53 Rev 5",
                category="Information Input Validation",
                severity=ComplianceSeverity.INFO,
                title="Exposed Input Handling Interface Surface",
                description="The information system must validate all user inputs to ensure they conform to expected syntax and rules.",
                remediation="Implement strict server-side validation against well-formed regex schemas and type specifications.",
                weight=2.0,
            ),

            # 11. Permissive Wildcard Cross-Origin Resource Sharing (CORS)
            "OWASP-ASVS-V14.5": ComplianceRule(
                rule_id="OWASP-ASVS-V14.5",
                benchmark="OWASP ASVS v4.0",
                category="Configuration Verification",
                severity=ComplianceSeverity.MEDIUM,
                title="Wildcard Cross-Origin Resource Sharing (CORS)",
                description="Verify that CORS headers do not use wildcard '*' with credentials or expose internal operational endpoints.",
                remediation="Explicitly specify trusted origin domains instead of utilizing wildcard '*' in Access-Control-Allow-Origin.",
                weight=10.0,
            ),
        }

    def _matches_benchmark(self, rule: ComplianceRule) -> bool:
        """Check if rule matches the configured benchmark filter."""
        if self.benchmark == "all":
            return True
        b_lower = rule.benchmark.lower()
        if self.benchmark == "owasp" and "owasp" in b_lower:
            return True
        if self.benchmark == "cis" and "cis" in b_lower:
            return True
        if self.benchmark == "nist" and "nist" in b_lower:
            return True
        return False

    def evaluate(
        self,
        results: List[ScanResult],
        base_headers: Optional[Dict[str, str]] = None,
        target_url: str = "",
    ) -> ComplianceReport:
        """
        Evaluate discovered endpoints and headers against selected baseline standards.
        Authored and designed by Ahmed Wael.
        """
        headers = base_headers or {}
        # Normalize header keys to lowercase for robust lookup
        low_headers = {k.lower(): v for k, v in headers.items()}

        findings: List[ComplianceFinding] = []
        rule_violations: Set[str] = set()

        # Helper to record a violation
        def add_violation(rule_id: str, endpoint: str, evidence: str) -> None:
            rule = self.rules.get(rule_id)
            if not rule or not self._matches_benchmark(rule):
                return
            findings.append(ComplianceFinding(
                rule_id=rule.rule_id,
                benchmark=rule.benchmark,
                category=rule.category,
                severity=rule.severity,
                status=ComplianceStatus.FAIL,
                title=rule.title,
                endpoint=endpoint,
                evidence=evidence,
                remediation=rule.remediation,
            ))
            rule_violations.add(rule_id)

        # ---------------------------------------------------------------------
        # 1. Transport Layer Security & HTTPS Evaluation
        # ---------------------------------------------------------------------
        is_https = target_url.startswith("https://") if target_url else any(r.url.startswith("https://") for r in results)
        hsts_header = low_headers.get("strict-transport-security", "")

        if not is_https:
            ev = "Target operates over unencrypted plaintext HTTP transport."
            add_violation("OWASP-ASVS-V14.1", "GLOBAL (Transport)", ev)
            add_violation("NIST-SC-8", "GLOBAL (Transport)", ev)
            add_violation("CIS-WEB-3.1", "GLOBAL (Transport)", ev)
        elif not hsts_header:
            ev = "Header 'Strict-Transport-Security' is absent from base HTTPS response."
            add_violation("OWASP-ASVS-V14.1", "GLOBAL (Transport)", ev)
            add_violation("NIST-SC-8", "GLOBAL (Transport)", ev)
            add_violation("CIS-WEB-3.1", "GLOBAL (Transport)", ev)

        # ---------------------------------------------------------------------
        # 2. Defensive Client-Side Headers (CSP, XFO, nosniff)
        # ---------------------------------------------------------------------
        csp_header = low_headers.get("content-security-policy", "")
        if not csp_header:
            add_violation("OWASP-ASVS-V14.2-CSP", "GLOBAL (HTTP Headers)", "Header 'Content-Security-Policy' is not configured.")

        xfo_header = low_headers.get("x-frame-options", "")
        has_frame_ancestors = "frame-ancestors" in csp_header.lower()
        if not xfo_header and not has_frame_ancestors:
            ev = "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' are enforced."
            add_violation("OWASP-ASVS-V14.2-XFO", "GLOBAL (HTTP Headers)", ev)
            add_violation("CIS-WEB-3.2", "GLOBAL (HTTP Headers)", ev)

        xcto_header = low_headers.get("x-content-type-options", "").lower()
        if "nosniff" not in xcto_header:
            ev = f"'X-Content-Type-Options' is '{xcto_header or 'Not Set'}' (expected: 'nosniff')."
            add_violation("OWASP-ASVS-V14.2-NOSNIFF", "GLOBAL (HTTP Headers)", ev)
            add_violation("CIS-WEB-3.3", "GLOBAL (HTTP Headers)", ev)

        cors_header = low_headers.get("access-control-allow-origin", "")
        if cors_header == "*":
            add_violation("OWASP-ASVS-V14.5", "GLOBAL (HTTP Headers)", "Access-Control-Allow-Origin: * set without origin restriction.")

        # ---------------------------------------------------------------------
        # 3. Server Banners & Technology Leakage
        # ---------------------------------------------------------------------
        for b_hdr in self.SERVER_BANNER_HEADERS:
            val = low_headers.get(b_hdr)
            if val and any(char.isdigit() for char in val):
                ev = f"Verbose version disclosed in '{b_hdr}: {val}'."
                add_violation("OWASP-ASVS-V14.3-B", "GLOBAL (HTTP Headers)", ev)
                add_violation("CIS-WEB-1.3", "GLOBAL (HTTP Headers)", ev)
                add_violation("NIST-SI-11-A", "GLOBAL (HTTP Headers)", ev)
                break

        # ---------------------------------------------------------------------
        # 4. Discovered Endpoint Auditing (Access Control, Exposures, Exceptions)
        # ---------------------------------------------------------------------
        for res in results:
            clean_path = "/" + res.path.lstrip("/")

            # Unauthenticated Administrative Portals
            if res.status_code == 200 and self.ADMIN_SURFACES.search(clean_path):
                ev = f"HTTP {res.status_code}, Length: {res.content_length}B, Title: '{res.title or 'N/A'}'"
                add_violation("OWASP-ASVS-V4.1", clean_path, ev)
                add_violation("NIST-AC-3", clean_path, ev)
                add_violation("CIS-WEB-1.1", clean_path, ev)

            # Sensitive Configuration & Backups Exposure
            if res.status_code == 200 and self.SENSITIVE_FILES.search(clean_path):
                ev = f"HTTP {res.status_code}, Length: {res.content_length}B on sensitive asset route."
                add_violation("OWASP-ASVS-V8.1", clean_path, ev)
                add_violation("NIST-SC-28", clean_path, ev)
                add_violation("CIS-WEB-2.3", clean_path, ev)

            # SCM Repository Exposure
            if res.status_code in (200, 301, 302, 403) and self.REPO_PATTERNS.search(clean_path):
                ev = f"SCM repository metadata route returned HTTP {res.status_code}."
                add_violation("OWASP-ASVS-V14.3", clean_path, ev)
                add_violation("CIS-WEB-2.4", clean_path, ev)

            # Server 5xx Unhandled Exception
            if res.status_code >= 500:
                ev = f"HTTP Status {res.status_code} indicating unhandled exception or crash."
                add_violation("OWASP-ASVS-V14.4", clean_path, ev)
                add_violation("NIST-SI-11-B", clean_path, ev)

            # Missing Cache-Control on Sensitive Endpoints
            if res.status_code == 200 and (self.ADMIN_SURFACES.search(clean_path) or "api" in clean_path.lower()):
                cc = low_headers.get("cache-control", "").lower()
                if cc and "no-store" not in cc:
                    ev = f"Cache-Control '{cc}' lacks 'no-store' on sensitive path '{clean_path}'."
                    add_violation("OWASP-ASVS-V8.2", clean_path, ev)

            # Dynamic Parameter Injection Surface
            if "?" in clean_path or "=" in clean_path:
                ev = f"Dynamic query parameters identified at '{clean_path}'."
                add_violation("OWASP-ASVS-V5.1", clean_path, ev)
                add_violation("NIST-SI-10", clean_path, ev)

        # ---------------------------------------------------------------------
        # 5. Score & Compliance Grade Computation
        # ---------------------------------------------------------------------
        active_rules = [r for r in self.rules.values() if self._matches_benchmark(rule=r)]
        total_eval_weight = sum(r.weight for r in active_rules) or 1.0
        passed_weight = 0.0

        passed_rules_count = 0
        failed_rules_count = 0
        warn_rules_count = 0

        benchmark_scores: Dict[str, Dict[str, float]] = {
            "OWASP ASVS v4.0": {"total": 0.0, "passed": 0.0},
            "CIS Web Benchmark": {"total": 0.0, "passed": 0.0},
            "NIST SP 800-53 Rev 5": {"total": 0.0, "passed": 0.0},
        }

        for r in active_rules:
            is_violated = r.rule_id in rule_violations
            bm = r.benchmark
            if bm in benchmark_scores:
                benchmark_scores[bm]["total"] += r.weight

            if is_violated:
                failed_rules_count += 1
            else:
                passed_rules_count += 1
                passed_weight += r.weight
                if bm in benchmark_scores:
                    benchmark_scores[bm]["passed"] += r.weight

        compliance_score = max(0.0, min(100.0, (passed_weight / total_eval_weight) * 100.0))

        if compliance_score >= 95.0:
            compliance_grade = "A+ (Compliant)"
        elif compliance_score >= 85.0:
            compliance_grade = "A (Compliant)"
        elif compliance_score >= 70.0:
            compliance_grade = "B (Substantially Compliant)"
        elif compliance_score >= 50.0:
            compliance_grade = "C (Partially Compliant)"
        elif compliance_score >= 35.0:
            compliance_grade = "D (Non-Compliant)"
        else:
            compliance_grade = "F (Critical Non-Compliance)"

        calc_bm_scores: Dict[str, float] = {}
        for bm, data in benchmark_scores.items():
            if data["total"] > 0:
                calc_bm_scores[bm] = round((data["passed"] / data["total"]) * 100.0, 1)

        # Deduplicate findings by rule_id and endpoint
        dedup_findings: List[ComplianceFinding] = []
        seen_keys: Set[str] = set()
        for f in findings:
            key = f"{f.rule_id}::{f.endpoint}"
            if key not in seen_keys:
                seen_keys.add(key)
                dedup_findings.append(f)

        return ComplianceReport(
            target_url=target_url,
            benchmark=self.benchmark,
            findings=dedup_findings,
            passed_rules=passed_rules_count,
            failed_rules=failed_rules_count,
            warn_rules=warn_rules_count,
            compliance_score=compliance_score,
            compliance_grade=compliance_grade,
            benchmark_scores=calc_bm_scores,
            author=__author__,
        )
