"""
WebAdminMapper - Advanced Configuration Module
==============================================
Manages scan configurations, recursion depths, HTTP options, filters,
fuzzing permutations, and heuristic options with strict validation.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


DEFAULT_MATCH_CODES = {200, 204, 301, 302, 307, 308, 401, 403, 405, 500}
DEFAULT_FILTER_CODES = {404}
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)


@dataclass
class ScanConfig:
    """
    Holds all runtime configuration and options for WebAdminMapper.
    Authored and designed by Ahmed Wael.
    """

    target_url: str
    threads: int = 25
    timeout: float = 7.0
    delay: float = 0.0
    jitter: float = 0.0
    rate_limit: float = 0.0
    retries: int = 1
    user_agent: str = DEFAULT_USER_AGENT
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Optional[str] = None
    proxy: Optional[str] = None
    verify_ssl: bool = False
    follow_redirects: bool = False

    # Status Code Filtering
    match_codes: Set[int] = field(default_factory=lambda: set(DEFAULT_MATCH_CODES))
    filter_codes: Set[int] = field(default_factory=lambda: set(DEFAULT_FILTER_CODES))

    # Size Filtering
    match_sizes: Set[int] = field(default_factory=set)
    filter_sizes: Set[int] = field(default_factory=set)

    # Word & Line Count Filtering
    match_words: Set[int] = field(default_factory=set)
    filter_words: Set[int] = field(default_factory=set)
    match_lines: Set[int] = field(default_factory=set)
    filter_lines: Set[int] = field(default_factory=set)

    # Content & Regex Filtering
    filter_text: Optional[str] = None
    match_regex: Optional[str] = None
    filter_regex: Optional[str] = None

    # Path Generation & Wordlists
    extensions: List[str] = field(default_factory=list)
    prefix: str = ""
    suffix: str = ""
    wordlist_path: Optional[str] = None
    wordlist_type: str = "all"  # 'admin', 'common', 'sensitive', 'cloud', 'all'
    case_transform: Optional[str] = None  # 'lower', 'upper', 'title'

    # Recursion
    recursive: bool = False
    max_depth: int = 1

    # Output & Visualization
    output_file: Optional[str] = None
    output_format: str = "table"  # 'table', 'html', 'json', 'csv', 'markdown', 'txt'
    quiet: bool = False
    extract_title: bool = True
    show_tree: bool = True

    # Heuristics & Profiling
    wildcard_detection: bool = True
    tech_detect: bool = True
    adaptive_rate_limit: bool = False
    harvest_routes: bool = True
    security_audit: bool = True
    cert_inspect: bool = True
    network_diag: bool = True
    validate_vulns: bool = True
    compliance_check: bool = True
    compliance_benchmark: str = "all"  # 'all', 'owasp', 'cis', 'nist'
    checkpoint_file: Optional[str] = None
    resume_checkpoint: Optional[str] = None

    def __post_init__(self) -> None:

        """Validate and normalize configuration parameters."""
        self.target_url = self.normalize_url(self.target_url)
        self.validate()

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        """Normalize target URL, ensuring scheme and trimming trailing slash."""
        raw_url = raw_url.strip()
        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
        parsed = urlparse(raw_url)
        if not parsed.netloc:
            raise ValueError(f"Invalid target URL: '{raw_url}'")
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def validate(self) -> None:
        """Validate configuration sanity."""
        if self.threads < 1:
            raise ValueError("Thread count must be at least 1.")
        if self.threads > 200:
            raise ValueError("Thread count cannot exceed 200 for safety.")
        if self.timeout <= 0:
            raise ValueError("Timeout must be greater than 0.")
        if self.delay < 0:
            raise ValueError("Delay cannot be negative.")
        if self.jitter < 0:
            raise ValueError("Jitter cannot be negative.")
        if self.rate_limit < 0:
            raise ValueError("Rate limit cannot be negative.")
        if self.max_depth < 1:
            raise ValueError("Recursion depth must be at least 1.")

        if self.case_transform and self.case_transform not in ("lower", "upper", "title"):
            raise ValueError(f"Unsupported case transform: '{self.case_transform}' (Choices: lower, upper, title)")

        supported_formats = {"table", "html", "json", "csv", "markdown", "txt"}
        if self.output_format not in supported_formats:
            raise ValueError(f"Unsupported output format: '{self.output_format}' (Choices: {supported_formats})")

        supported_types = {"admin", "common", "sensitive", "cloud", "all"}
        if self.wordlist_type not in supported_types:
            raise ValueError(f"Unsupported wordlist type: '{self.wordlist_type}' (Choices: {supported_types})")

        supported_benchmarks = {"all", "owasp", "cis", "nist"}
        if self.compliance_benchmark not in supported_benchmarks:
            raise ValueError(f"Unsupported compliance benchmark: '{self.compliance_benchmark}' (Choices: {supported_benchmarks})")

    def to_dict(self) -> Dict[str, any]:
        """Convert configuration to serializable dictionary."""
        return {
            "target_url": self.target_url,
            "threads": self.threads,
            "timeout": self.timeout,
            "delay": self.delay,
            "jitter": self.jitter,
            "rate_limit": self.rate_limit,
            "retries": self.retries,
            "user_agent": self.user_agent,
            "headers": self.headers,
            "cookies": self.cookies,
            "proxy": self.proxy,
            "verify_ssl": self.verify_ssl,
            "follow_redirects": self.follow_redirects,
            "match_codes": sorted(list(self.match_codes)),
            "filter_codes": sorted(list(self.filter_codes)),
            "match_sizes": sorted(list(self.match_sizes)),
            "filter_sizes": sorted(list(self.filter_sizes)),
            "match_words": sorted(list(self.match_words)),
            "filter_words": sorted(list(self.filter_words)),
            "match_lines": sorted(list(self.match_lines)),
            "filter_lines": sorted(list(self.filter_lines)),
            "filter_text": self.filter_text,
            "match_regex": self.match_regex,
            "filter_regex": self.filter_regex,
            "extensions": self.extensions,
            "prefix": self.prefix,
            "suffix": self.suffix,
            "wordlist_path": self.wordlist_path,
            "wordlist_type": self.wordlist_type,
            "recursive": self.recursive,
            "max_depth": self.max_depth,
            "output_file": self.output_file,
            "output_format": self.output_format,
            "quiet": self.quiet,
            "extract_title": self.extract_title,
            "show_tree": self.show_tree,
            "wildcard_detection": self.wildcard_detection,
            "tech_detect": self.tech_detect,
            "adaptive_rate_limit": self.adaptive_rate_limit,
            "harvest_routes": self.harvest_routes,
            "security_audit": self.security_audit,
            "cert_inspect": self.cert_inspect,
            "network_diag": self.network_diag,
            "validate_vulns": self.validate_vulns,
            "compliance_check": self.compliance_check,
            "compliance_benchmark": self.compliance_benchmark,
            "checkpoint_file": self.checkpoint_file,
            "resume_checkpoint": self.resume_checkpoint,
            "author": __author__,
        }

    def save_profile(self, filepath: str) -> None:
        """Save configuration profile to a JSON file."""
        import json
        from pathlib import Path
        p = Path(filepath).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_profile(cls, filepath: str) -> "ScanConfig":
        """Instantiate ScanConfig from a JSON profile file."""
        import json
        from pathlib import Path
        p = Path(filepath).expanduser().resolve()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.pop("author", None)
        # Convert list fields back to sets
        if "match_codes" in data:
            data["match_codes"] = set(data["match_codes"])
        if "filter_codes" in data:
            data["filter_codes"] = set(data["filter_codes"])
        if "match_sizes" in data:
            data["match_sizes"] = set(data["match_sizes"])
        if "filter_sizes" in data:
            data["filter_sizes"] = set(data["filter_sizes"])
        if "match_words" in data:
            data["match_words"] = set(data["match_words"])
        if "filter_words" in data:
            data["filter_words"] = set(data["filter_words"])
        if "match_lines" in data:
            data["match_lines"] = set(data["match_lines"])
        if "filter_lines" in data:
            data["filter_lines"] = set(data["filter_lines"])
        return cls(**data)

