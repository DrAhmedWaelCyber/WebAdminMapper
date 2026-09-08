"""
WebAdminMapper - SSL/TLS Certificate & Transport Auditor
========================================================
Inspects SSL/TLS certificates, validation dates, certificate authorities,
Subject Alternative Names (SANs), and cryptographic cipher suites.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


class CertificateInfo:
    """Stores parsed SSL/TLS certificate metadata."""

    def __init__(
        self,
        subject: str,
        issuer: str,
        valid_from: str,
        valid_until: str,
        days_remaining: int,
        sans: List[str],
        tls_version: str,
        cipher: str,
    ):
        self.subject = subject
        self.issuer = issuer
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.days_remaining = days_remaining
        self.sans = sans
        self.tls_version = tls_version
        self.cipher = cipher

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "days_remaining": self.days_remaining,
            "subject_alternative_names": self.sans,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "author": __author__,
        }


class CertInspector:
    """
    Native SSL/TLS certificate analysis engine.
    Authored and designed by Ahmed Wael.
    """

    @staticmethod
    def inspect(target_url: str, timeout: float = 6.0) -> Optional[CertificateInfo]:
        """
        Connect to HTTPS host and extract certificate details without third-party dependencies.
        Authored by Ahmed Wael.
        """
        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return None

        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return None

        try:
            context = ssl.create_default_context()
            # Allow fallback inspection even if certificate is untrusted/expired
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version() or "Unknown"
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else "Unknown"

            # Re-read formatted certificate with peer verification for full dictionary
            verif_context = ssl.create_default_context()
            try:
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with verif_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert_dict = ssock.getpeercert()
            except Exception:
                cert_dict = None

            if not cert_dict:
                return CertificateInfo(
                    subject=hostname,
                    issuer="Self-Signed / Untrusted CA",
                    valid_from="N/A",
                    valid_until="N/A",
                    days_remaining=0,
                    sans=[hostname],
                    tls_version=tls_version,
                    cipher=cipher_name,
                )

            # Parse Subject
            subject_parts = [v[0][1] for v in cert_dict.get("subject", []) if v and v[0]]
            subject_str = ", ".join(subject_parts) or hostname

            # Parse Issuer
            issuer_parts = [v[0][1] for v in cert_dict.get("issuer", []) if v and v[0]]
            issuer_str = ", ".join(issuer_parts) or "Unknown CA"

            # Parse Dates
            not_before = cert_dict.get("notBefore", "")
            not_after = cert_dict.get("notAfter", "")
            days_left = -1

            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry_date - now).days
                except Exception:
                    pass

            # Parse SANs (Subject Alternative Names)
            sans = [v[1] for v in cert_dict.get("subjectAltName", []) if v and v[0] == "DNS"]

            return CertificateInfo(
                subject=subject_str,
                issuer=issuer_str,
                valid_from=not_before,
                valid_until=not_after,
                days_remaining=days_left,
                sans=sans,
                tls_version=tls_version,
                cipher=cipher_name,
            )

        except Exception:
            return None
