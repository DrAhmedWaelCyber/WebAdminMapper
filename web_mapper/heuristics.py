"""
WebAdminMapper - Heuristics, Anomaly & Soft-404 Detection Module
================================================================
Advanced heuristic detection for dynamic soft-404 responses, WAF blocks,
similarity clustering, and adaptive rate limiting.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import hashlib
import re
from typing import Dict, List, Optional, Set, Tuple

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


def compute_words_and_lines(text: str) -> Tuple[int, int]:
    """Compute word count and line count for a given text string."""
    lines = text.splitlines()
    line_count = len(lines)
    word_count = len(text.split())
    return word_count, line_count


def compute_token_set(text: str) -> Set[str]:
    """Extract word tokens (alphanumeric 3+ chars) for Jaccard similarity."""
    tokens = set(re.findall(r"[a-zA-Z0-9_]{3,}", text.lower()))
    return tokens


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Calculate Jaccard similarity ratio between two token sets."""
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union else 0.0


class BaselineProfile:
    """Stores baseline characteristics of server error/wildcard responses."""

    def __init__(
        self,
        status_code: int,
        content_length: int,
        word_count: int,
        line_count: int,
        title: Optional[str],
        tokens: Set[str],
    ):
        self.status_code = status_code
        self.content_length = content_length
        self.word_count = word_count
        self.line_count = line_count
        self.title = (title or "").lower().strip()
        self.tokens = tokens


class Soft404Detector:
    """
    Intelligent soft-404 and wildcard detection engine.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self):
        self.baselines: List[BaselineProfile] = []
        self.wildcard_status_codes: Set[int] = set()

    def add_baseline(
        self,
        status_code: int,
        body: bytes,
        title: Optional[str] = None,
    ) -> BaselineProfile:
        """Record a baseline response signature from a known non-existent path."""
        decoded = body.decode("utf-8", errors="ignore")
        word_count, line_count = compute_words_and_lines(decoded)
        tokens = compute_token_set(decoded)
        content_length = len(body)

        profile = BaselineProfile(
            status_code=status_code,
            content_length=content_length,
            word_count=word_count,
            line_count=line_count,
            title=title,
            tokens=tokens,
        )
        self.baselines.append(profile)
        self.wildcard_status_codes.add(status_code)
        return profile

    def is_soft_404(
        self,
        status_code: int,
        content_length: int,
        body_sample: bytes,
        title: Optional[str] = None,
    ) -> bool:
        """
        Determine if an HTTP response is a disguised soft-404 / wildcard page.
        Uses multi-factor checks: exact size, word/line count, and token similarity.
        Authored by Ahmed Wael.
        """
        if not self.baselines:
            return False

        clean_title = (title or "").lower().strip()
        decoded = body_sample.decode("utf-8", errors="ignore") if body_sample else ""
        word_count, line_count = compute_words_and_lines(decoded)
        tokens = compute_token_set(decoded)

        for base in self.baselines:
            # Must match status code
            if base.status_code != status_code:
                continue

            # Check exact length or tiny deviation (e.g. timestamp or URL echo difference)
            size_diff = abs(base.content_length - content_length)
            if size_diff == 0:
                return True

            # If word count and line count match exactly, it's virtually guaranteed to be a template
            if base.word_count == word_count and base.line_count == line_count and word_count > 0:
                return True

            # Check title match if present
            if base.title and clean_title and base.title == clean_title and size_diff < 50:
                return True

            # Token similarity check for dynamic templates
            if tokens and base.tokens:
                similarity = jaccard_similarity(tokens, base.tokens)
                if similarity >= 0.94 and size_diff < 150:
                    return True

        return False


class WAFDetector:
    """
    Detects Web Application Firewall (WAF) interference and blocks.
    Authored and designed by Ahmed Wael.
    """

    WAF_SIGNATURES = [
        ("Cloudflare", ["cf-ray", "__cfduid", "cf-cache-status"]),
        ("AWS WAF", ["x-amzn-requestid", "x-amzn-errortype", "awswaf"]),
        ("Akamai", ["x-akamai-transformed", "akamai-origin-hop"]),
        ("Imperva / Incapsula", ["x-iinfo", "incap_ses", "visid_incap"]),
        ("F5 BIG-IP", ["bigipserver", "x-cnection", "f5_cspm"]),
        ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"]),
        ("ModSecurity", ["mod_security", "modsecurity"]),
    ]

    def check_headers(self, headers: Dict[str, str], status_code: int) -> Optional[str]:
        """Check if response indicates active WAF blocking."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for waf_name, indicators in self.WAF_SIGNATURES:
            for ind in indicators:
                if ind in headers_lower:
                    if status_code in (403, 406, 429, 503):
                        return f"{waf_name} (Active Block / Challenge Detected)"
                    return waf_name

        server_header = headers_lower.get("server", "").lower()
        if "cloudflare" in server_header:
            return "Cloudflare"

        return None
