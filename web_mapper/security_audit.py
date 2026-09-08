"""
WebAdminMapper - Security Posture & Header Audit Module
=======================================================
Evaluates web server security headers, cookie attributes, information disclosure
indicators, and produces defensive configuration grades and remediation guidance.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


@dataclass
class SecurityFinding:
    """Individual security configuration issue or recommendation."""
    name: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "INFO"
    description: str
    recommendation: str


@dataclass
class SecurityAuditResult:
    """Comprehensive security evaluation results for a target host."""
    target_url: str
    grade: str  # A+, A, B, C, D, F
    score: int  # 0 - 100
    findings: List[SecurityFinding] = field(default_factory=list)
    present_headers: Dict[str, str] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)
    cookie_issues: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "grade": self.grade,
            "score": self.score,
            "findings": [
                {
                    "name": f.name,
                    "severity": f.severity,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "present_headers": self.present_headers,
            "missing_headers": self.missing_headers,
            "cookie_issues": self.cookie_issues,
            "author": __author__,
        }


class SecurityAuditor:
    """
    Evaluates defensive HTTP headers, cookie security, and configuration posture.
    Authored and designed by Ahmed Wael.
    """

    CRITICAL_HEADERS = [
        ("Strict-Transport-Security", "HSTS enforces HTTPS connections and prevents SSL stripping.", "HIGH"),
        ("Content-Security-Policy", "CSP mitigates cross-site scripting (XSS) and data injection.", "HIGH"),
        ("X-Frame-Options", "Prevents clickjacking attacks by controlling framing permissions.", "MEDIUM"),
        ("X-Content-Type-Options", "Prevents MIME-type confusion attacks by enforcing 'nosniff'.", "MEDIUM"),
        ("Referrer-Policy", "Protects sensitive URLs and parameters from leaking via HTTP Referer.", "LOW"),
        ("Permissions-Policy", "Restricts browser features like camera, microphone, and geolocation.", "LOW"),
    ]

    DISCLOSURE_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator",
        "X-Runtime",
    ]

    def audit(self, target_url: str, headers: Dict[str, str]) -> SecurityAuditResult:
        """
        Perform a thorough defensive posture check against target response headers.
        Authored by Ahmed Wael.
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        findings: List[SecurityFinding] = []
        present: Dict[str, str] = {}
        missing: List[str] = []
        cookie_issues: List[str] = []

        score = 100

        # 1. Check Defensive Security Headers
        for header_name, desc, severity in self.CRITICAL_HEADERS:
            h_key = header_name.lower()
            if h_key in headers_lower:
                val = headers_lower[h_key]
                present[header_name] = val

                # Deep inspection of specific headers
                if h_key == "strict-transport-security":
                    if "max-age" not in val.lower() or "includeSubDomains" not in val:
                        findings.append(SecurityFinding(
                            name="Weak HSTS Policy",
                            severity="LOW",
                            description="HSTS header is present but lacks 'includeSubDomains' or optimal max-age.",
                            recommendation="Set 'max-age=31536000; includeSubDomains; preload'.",
                        ))
                        score -= 5
                elif h_key == "x-content-type-options":
                    if "nosniff" not in val.lower():
                        findings.append(SecurityFinding(
                            name="Invalid X-Content-Type-Options",
                            severity="MEDIUM",
                            description="Header is present but not configured with 'nosniff'.",
                            recommendation="Set header value to 'nosniff'.",
                        ))
                        score -= 10
            else:
                missing.append(header_name)
                deduction = 18 if severity == "HIGH" else 10 if severity == "MEDIUM" else 5
                score -= deduction
                findings.append(SecurityFinding(
                    name=f"Missing {header_name}",
                    severity=severity,
                    description=desc,
                    recommendation=f"Configure web server or proxy to send the '{header_name}' header.",
                ))

        # 2. Check Information Disclosure Headers
        for disc_header in self.DISCLOSURE_HEADERS:
            d_key = disc_header.lower()
            if d_key in headers_lower:
                val = headers_lower[d_key]
                findings.append(SecurityFinding(
                    name=f"Information Disclosure ({disc_header})",
                    severity="LOW",
                    description=f"Server exposes technology details via '{disc_header}: {val}'.",
                    recommendation=f"Disable or sanitize the '{disc_header}' header in web server configuration.",
                ))
                score -= 4

        # 3. Check Cookies for Security Attributes
        set_cookie = headers_lower.get("set-cookie", "")
        if set_cookie:
            cookies = set_cookie.split(",")
            for cookie in cookies:
                cookie_clean = cookie.strip()
                cookie_name = cookie_clean.split("=")[0] if "=" in cookie_clean else "Cookie"
                if target_url.startswith("https://") and "secure" not in cookie_clean.lower():
                    cookie_issues.append(f"'{cookie_name}' missing 'Secure' flag.")
                    score -= 5
                if "httponly" not in cookie_clean.lower():
                    cookie_issues.append(f"'{cookie_name}' missing 'HttpOnly' flag.")
                    score -= 5
                if "samesite" not in cookie_clean.lower():
                    cookie_issues.append(f"'{cookie_name}' missing 'SameSite' attribute.")
                    score -= 3

        score = max(0, min(100, score))

        # Determine Letter Grade
        if score >= 90:
            grade = "A+" if score >= 95 else "A"
        elif score >= 80:
            grade = "B"
        elif score >= 65:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"

        return SecurityAuditResult(
            target_url=target_url,
            grade=grade,
            score=score,
            findings=findings,
            present_headers=present,
            missing_headers=missing,
            cookie_issues=cookie_issues,
        )
