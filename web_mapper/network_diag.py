"""
WebAdminMapper - Network & Host Diagnostics Module
==================================================
Performs IP address resolution, canonical name discovery, reverse DNS lookups,
and socket-level TCP connection latency diagnostics.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


@dataclass
class NetworkDiagResult:
    """Network connection and resolution metrics for a target host."""
    hostname: str
    port: int
    ip_addresses: List[str] = field(default_factory=list)
    primary_ip: Optional[str] = None
    canonical_name: Optional[str] = None
    reverse_dns: Optional[str] = None
    tcp_latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "ip_addresses": self.ip_addresses,
            "primary_ip": self.primary_ip,
            "canonical_name": self.canonical_name,
            "reverse_dns": self.reverse_dns,
            "tcp_latency_ms": round(self.tcp_latency_ms, 2),
            "author": __author__,
        }


class NetworkDiagnostics:
    """
    Host network diagnostic probe.
    Authored and designed by Ahmed Wael.
    """

    @staticmethod
    def inspect(target_url: str, timeout: float = 5.0) -> Optional[NetworkDiagResult]:
        """
        Diagnose network attributes, DNS mappings, and TCP latency for target URL.
        Authored by Ahmed Wael.
        """
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            return None

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ip_addresses: List[str] = []
        canonical_name = None
        reverse_dns = None
        tcp_latency_ms = 0.0

        # 1. DNS Resolution (IPv4 & CNAME)
        try:
            cname, aliases, addrs = socket.gethostbyname_ex(hostname)
            canonical_name = cname
            ip_addresses = addrs
        except (socket.gaierror, socket.herror, socket.error, OSError):
            try:
                addr_info = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
                ip_addresses = sorted(list({info[4][0] for info in addr_info if info and info[4]}))
            except (socket.gaierror, socket.herror, socket.error, OSError):
                ip_addresses = []

        primary_ip = ip_addresses[0] if ip_addresses else None

        # 2. Reverse DNS Lookup
        if primary_ip:
            try:
                rev_host, _, _ = socket.gethostbyaddr(primary_ip)
                reverse_dns = rev_host
            except (socket.herror, socket.gaierror, socket.error, OSError):
                reverse_dns = None

        # 3. TCP Connect Latency Measurement
        if primary_ip:
            try:
                start = time.perf_counter()
                with socket.create_connection((primary_ip, port), timeout=timeout):
                    tcp_latency_ms = (time.perf_counter() - start) * 1000.0
            except (socket.timeout, TimeoutError, ConnectionError, OSError):
                tcp_latency_ms = 0.0

        return NetworkDiagResult(
            hostname=hostname,
            port=port,
            ip_addresses=ip_addresses,
            primary_ip=primary_ip,
            canonical_name=canonical_name,
            reverse_dns=reverse_dns,
            tcp_latency_ms=tcp_latency_ms,
        )
