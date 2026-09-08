"""
WebAdminMapper - Advanced HTTP Requester Engine
===============================================
High-speed multithreaded network engine with advanced heuristics,
fingerprinting, soft-404 suppression, and deep response parsing.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import hashlib
import http.client
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from .config import ScanConfig
from .fingerprint import TechProfiler
from .heuristics import Soft404Detector, WAFDetector, compute_words_and_lines


__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"

TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Prevents automatic following of 3xx redirects so administrative
    and directory redirection paths are captured.
    Authored by Ahmed Wael.
    """

    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    def http_error_303(self, req, fp, code, msg, headers):
        return fp

    def http_error_307(self, req, fp, code, msg, headers):
        return fp

    def http_error_308(self, req, fp, code, msg, headers):
        return fp


@dataclass
class ScanResult:
    """
    Detailed probe result for a discovered path.
    Authored by Ahmed Wael.
    """

    path: str
    url: str
    status_code: int
    content_length: int
    response_time_ms: float
    word_count: int = 0
    line_count: int = 0
    title: Optional[str] = None
    redirect_location: Optional[str] = None
    content_type: str = ""
    server: str = ""
    waf_detected: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    body_hash_md5: str = ""
    body_hash_sha256: str = ""
    allowed_methods: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, any]:
        """Convert result object into a serializable dictionary."""
        return {
            "path": self.path,
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "word_count": self.word_count,
            "line_count": self.line_count,
            "response_time_ms": round(self.response_time_ms, 2),
            "title": self.title,
            "redirect_location": self.redirect_location,
            "content_type": self.content_type,
            "server": self.server,
            "waf_detected": self.waf_detected,
            "technologies": self.technologies,
            "body_hash_md5": self.body_hash_md5,
            "body_hash_sha256": self.body_hash_sha256,
            "allowed_methods": self.allowed_methods,
            "timestamp": self.timestamp,
            "author": __author__,
        }



class HTTPRequester:
    """
    Advanced HTTP Network Engine with heuristics, profiling, and filters.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._opener = self._build_opener()
        self.profiler = TechProfiler()
        self.soft404 = Soft404Detector()
        self.waf_detector = WAFDetector()
        self.discovered_techs: List[str] = []
        self.detected_waf: Optional[str] = None
        self.base_headers: Dict[str, str] = {}

        # Precompiled regex filters

        self._match_regex = re.compile(config.match_regex, re.I) if config.match_regex else None
        self._filter_regex = re.compile(config.filter_regex, re.I) if config.filter_regex else None

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """Construct configured urllib OpenerDirector with SSL and proxy support."""
        handlers: List[urllib.request.BaseHandler] = []

        if not self.config.verify_ssl:
            ssl_context = ssl._create_unverified_context()
            ssl_context.check_hostname = False
        else:
            ssl_context = ssl.create_default_context()

        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))

        if not self.config.follow_redirects:
            handlers.append(NoRedirectHandler())

        if self.config.proxy:
            handlers.append(
                urllib.request.ProxyHandler(
                    {"http": self.config.proxy, "https": self.config.proxy}
                )
            )

        return urllib.request.build_opener(*handlers)

    def _prepare_request(self, target_url: str) -> urllib.request.Request:
        """Create urllib Request with configured headers."""
        req = urllib.request.Request(target_url, method="GET")
        req.add_header("User-Agent", self.config.user_agent)
        req.add_header("Accept", "*/*")
        req.add_header("Connection", "close")

        if self.config.cookies:
            req.add_header("Cookie", self.config.cookies)

        for h_key, h_val in self.config.headers.items():
            req.add_header(h_key, h_val)

        return req

    def calibrate_heuristics(self) -> Dict[str, any]:
        """
        Calibrate soft-404 signatures and inspect target technologies.
        Authored by Ahmed Wael.
        """
        calib_data = {
            "soft404_active": False,
            "waf": None,
            "techs": [],
        }

        # 1. Baseline root connectivity & technology profiling
        base_res = self.probe_base_target()
        if base_res:
            calib_data["techs"] = self.discovered_techs
            calib_data["waf"] = self.detected_waf

        # 2. Multi-sample soft-404 calibration
        if self.config.wildcard_detection:
            rnd_paths = [
                f"/_wm_probe_{os.urandom(6).hex()}",
                f"/_wm_probe_{os.urandom(6).hex()}.html",
                f"/_wm_probe_{os.urandom(6).hex()}/",
            ]
            for rpath in rnd_paths:
                raw = self._raw_probe(rpath)
                if raw:
                    status, body, title = raw
                    self.soft404.add_baseline(status, body, title)
                    calib_data["soft404_active"] = True

        return calib_data

    def _raw_probe(self, path: str) -> Optional[Tuple[int, bytes, Optional[str]]]:
        """Raw probe without filters to establish baseline."""
        full_url = f"{self.config.target_url}{path}"
        req = self._prepare_request(full_url)
        try:
            with self._opener.open(req, timeout=self.config.timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 200))
                body = resp.read()
                title = self._extract_title(body)
                return (status, body, title)
        except urllib.error.HTTPError as err:
            try:
                body = err.read()
            except Exception:
                body = b""
            title = self._extract_title(body)
            return (err.code, body, title)
        except Exception:
            return None

    def _extract_title(self, body: bytes) -> Optional[str]:
        """Extract title text from HTML body."""
        if not body:
            return None
        try:
            sample = body[:16384].decode("utf-8", errors="ignore")
            match = TITLE_REGEX.search(sample)
            if match:
                return " ".join(match.group(1).split()).strip()
        except Exception:
            pass
        return None

    def probe_path(self, path: str) -> Optional[ScanResult]:
        """
        Probe a single endpoint against the target server with deep inspection.
        Authored by Ahmed Wael.
        """
        clean_path = "/" + path.lstrip("/")
        full_url = f"{self.config.target_url}{clean_path}"

        if self.config.delay > 0:
            time.sleep(self.config.delay)

        attempts = 0
        max_attempts = max(1, self.config.retries + 1)
        start_time = time.perf_counter()
        req = self._prepare_request(full_url)

        while attempts < max_attempts:
            attempts += 1
            try:
                with self._opener.open(req, timeout=self.config.timeout) as response:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    status_code = getattr(response, "status", getattr(response, "code", 200))
                    headers = dict(response.headers)
                    body = response.read()
                    return self._process_response(
                        clean_path, full_url, status_code, headers, body, elapsed_ms
                    )

            except urllib.error.HTTPError as err:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                status_code = err.code
                headers = dict(err.headers)
                try:
                    err_body = err.read()
                except Exception:
                    err_body = b""
                return self._process_response(
                    clean_path, full_url, status_code, headers, err_body, elapsed_ms
                )

            except (urllib.error.URLError, socket.timeout, TimeoutError, http.client.RemoteDisconnected):
                if attempts < max_attempts:
                    continue
                return None
            except Exception:
                return None

        return None

    def _process_response(
        self,
        path: str,
        full_url: str,
        status_code: int,
        headers: Dict[str, str],
        body: bytes,
        elapsed_ms: float,
    ) -> Optional[ScanResult]:
        """Process response, applying filters and heuristics."""
        content_length = len(body)
        if content_length == 0 and "Content-Length" in headers:
            try:
                content_length = int(headers["Content-Length"])
            except Exception:
                pass

        # Text calculations
        text = body.decode("utf-8", errors="ignore") if body else ""
        word_count, line_count = compute_words_and_lines(text)
        title = self._extract_title(body) if self.config.extract_title else None
        redirect_loc = headers.get("Location") or headers.get("location")
        content_type = headers.get("Content-Type", "").split(";")[0].strip()
        server = headers.get("Server", "").strip()

        # 1. Soft-404 / Wildcard Filtering
        if self.config.wildcard_detection:
            if self.soft404.is_soft_404(status_code, content_length, body, title):
                return None

        # 2. Status Code Matching & Filtering
        if status_code in self.config.filter_codes:
            return None
        if self.config.match_codes and status_code not in self.config.match_codes:
            return None

        # 3. Content Length Matching & Filtering
        if content_length in self.config.filter_sizes:
            return None
        if self.config.match_sizes and content_length not in self.config.match_sizes:
            return None

        # 4. Word Count Matching & Filtering
        if word_count in self.config.filter_words:
            return None
        if self.config.match_words and word_count not in self.config.match_words:
            return None

        # 5. Line Count Matching & Filtering
        if line_count in self.config.filter_lines:
            return None
        if self.config.match_lines and line_count not in self.config.match_lines:
            return None

        # 6. Text & Regex Matching & Filtering
        if self.config.filter_text and text and self.config.filter_text in text:
            return None
        if self._filter_regex and text and self._filter_regex.search(text):
            return None
        if self._match_regex and text and not self._match_regex.search(text):
            return None

        # 7. Fingerprint & WAF Check
        techs = []
        waf = self.waf_detector.check_headers(headers, status_code)
        if self.config.tech_detect:
            techs = self.profiler.analyze(headers, body[:4096])

        # Hashes & Methods
        md5_hash = hashlib.md5(body).hexdigest() if body else ""
        sha256_hash = hashlib.sha256(body).hexdigest() if body else ""
        allowed_methods = headers.get("Allow") or headers.get("allow")

        return ScanResult(
            path=path,
            url=full_url,
            status_code=status_code,
            content_length=content_length,
            response_time_ms=elapsed_ms,
            word_count=word_count,
            line_count=line_count,
            title=title,
            redirect_location=redirect_loc,
            content_type=content_type,
            server=server,
            waf_detected=waf,
            technologies=techs,
            body_hash_md5=md5_hash,
            body_hash_sha256=sha256_hash,
            allowed_methods=allowed_methods,
        )


    def probe_base_target(self) -> Optional[ScanResult]:
        """Verify target connectivity and initialize profiling."""
        clean_path = "/"
        full_url = f"{self.config.target_url}{clean_path}"
        start_time = time.perf_counter()
        req = self._prepare_request(full_url)

        try:
            with self._opener.open(req, timeout=self.config.timeout) as resp:
                elapsed = (time.perf_counter() - start_time) * 1000.0
                status = getattr(resp, "status", getattr(resp, "code", 200))
                headers = dict(resp.headers)
                body = resp.read()
        except urllib.error.HTTPError as err:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            status = err.code
            headers = dict(err.headers)
            try:
                body = err.read()
            except Exception:
                body = b""
        except Exception:
            return None

        title = self._extract_title(body)
        server = headers.get("Server", "").strip()
        redirect_loc = headers.get("Location") or headers.get("location")
        content_type = headers.get("Content-Type", "").split(";")[0].strip()

        # Profiling & headers capture
        self.base_headers = headers
        self.discovered_techs = self.profiler.analyze(headers, body[:8192])
        self.detected_waf = self.waf_detector.check_headers(headers, status)


        md5_hash = hashlib.md5(body).hexdigest() if body else ""
        sha256_hash = hashlib.sha256(body).hexdigest() if body else ""
        allowed_methods = headers.get("Allow") or headers.get("allow")

        return ScanResult(
            path=clean_path,
            url=full_url,
            status_code=status,
            content_length=len(body),
            response_time_ms=elapsed,
            word_count=len(body.split()),
            line_count=len(body.splitlines()),
            title=title,
            redirect_location=redirect_loc,
            content_type=content_type,
            server=server,
            waf_detected=self.detected_waf,
            technologies=self.discovered_techs,
            body_hash_md5=md5_hash,
            body_hash_sha256=sha256_hash,
            allowed_methods=allowed_methods,
        )

