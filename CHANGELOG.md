# Changelog

All notable changes to **WebAdminMapper** are documented in this file.

The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standard.

**Author & Developer:** Ahmed Wael ([ahmedwael6143@gmail.com](mailto:ahmedwael6143@gmail.com))  
**Repository:** [https://github.com/DrAhmedWaelCyber/WebAdminMapper](https://github.com/DrAhmedWaelCyber/WebAdminMapper)

---

## [1.1.0] - 2026-09-08

### Added
- **Performance Benchmarking Suite (`benchmarks/benchmark_suite.py`):**
  - Standalone, zero-dependency benchmarking tool testing throughput across 1, 2, 4, 8, 16, 32, and 64 worker threads.
  - Measures requests per second (req/s), execution duration, error rate, and response latency percentiles (P50, P90, P99).
  - Automated system specifications capture (OS, kernel, CPU architecture, logical core count, Python runtime implementation and version).
  - JSON serialization of benchmark metrics saved to `benchmarks/benchmark_results.json`.
  - Comprehensive unit test suite in `tests/test_benchmarks.py`.
- **Comprehensive Integration Test Suite (`tests/test_integration.py`):**
  - Local controlled HTTP mock server testing full end-to-end scanner execution without network egress.
  - Verification of HTTP status handlers: `200 OK`, `301 Moved Permanently`, `302 Found`, `403 Forbidden`, `404 Not Found`, and `500 Internal Server Error`.
  - Soft-404 heuristic suppression validation on simulated wildcard catch-all endpoints.
  - Resilient handling of delayed and slow server responses (read timeouts).
  - Verification of connection failure handling on closed and unreachable ports.
  - Full recursive scanning and directory tree discovery verification.
- **GitHub Actions Multi-Platform CI/CD Pipeline (`.github/workflows/ci.yml`):**
  - Continuous integration workflow running across multiple operating systems (`ubuntu-latest`, `macos-latest`, `windows-latest`).
  - Cross-version Python matrix verification testing Python 3.8, 3.9, 3.10, 3.11, 3.12, and 3.13.
  - Automated steps for bytecode compilation check (`compileall`), test execution (`unittest discover`), benchmark smoke testing, and CLI entrypoint package installation (`pip install .`).
- **Defensive Compliance Engine Accuracy & Limitations Mapping:**
  - Added `limitations` attribute to `ComplianceRule` and `ComplianceFinding` to document verification boundaries for every evaluated standard.
  - Added `COMPLIANCE_DISCLAIMER` to `ComplianceReport` and serialized report outputs, clearly noting that automated indicator checks complement but do not substitute manual penetration testing or formal compliance audits.
  - Updated Markdown and HTML report templates in `reporter.py` to display the compliance disclaimer banner and limitations column.

### Changed
- **Exception Handling & Reliability Hardening (`engine.py`, `requester.py`):**
  - Eliminated broad `except Exception:` catches; implemented classified exception handling distinguishing `TimeoutError`, `SSLError`, `URLError`, `ConnectionError`, and `RemoteDisconnected`.
  - Introduced granular error statistics tracking in `HTTPRequester.error_counts` (`timeouts`, `ssl_errors`, `connection_errors`, `unexpected_errors`) exposed in `engine.error_stats`.
  - Logged structured warnings with error classification for unexpected exceptions during active scans.
  - Resolved Python 3.14 `ResourceWarning: Implicitly cleaning up <HTTPError>` by ensuring explicit `err.close()` invocation in all exception handlers across `_raw_probe`, `probe_path`, and `probe_base_target`.
- **Enqueue Tracking & Progress Calculation (`engine.py`):**
  - Implemented dynamic tracking of `self.total_enqueued` across initial path seeding, dynamic link crawling, and recursive directory discovery.
  - Fixed progress percentage calculation in recursive scans to guarantee strictly monotonic progress values bounded to 100%.
- **Heuristic Test Coverage (`tests/test_heuristics.py`):**
  - Added mathematical Jaccard distance verification tests, token sets extraction tests, dynamic soft-404 signature generation tests, and WAF signature detection tests.

---

## [1.0.0] - 2026-09-08

### Added
- **Core Architecture & Engine:**
  - High-concurrency multithreaded web application administrative mapper and path discovery engine.
  - 100% Python Standard Library implementation with zero third-party dependencies.
  - Adaptive rate limiting and concurrency controls.
  - Intelligent soft-404 detection using Jaccard text similarity and baseline calibration.
  - Route harvesting and dynamic crawler (`crawler.py`) extracting href and script endpoints.
  - Technology stack profiler and fingerprinting (`fingerprint.py`).
  - Heuristic WAF identification engine (`heuristics.py`).
  - Network diagnostic profiler (`network_diag.py`) measuring DNS resolution and TCP handshake latency.
  - SSL/TLS certificate inspector (`cert_inspector.py`) capturing SANs, expiry dates, and cipher suites.
  - Non-destructive automated security assertions engine (`security_assertions.py`).
  - Multi-standard defensive compliance validation engine (`compliance.py`) auditing against OWASP ASVS v4.0, CIS Web Benchmark, and NIST SP 800-53 Rev 5.
  - Interactive and command-line interfaces (`cli.py`).
  - Comprehensive multi-format reporting (`reporter.py`) outputting to HTML, JSON, Markdown, CSV, and plain text.
  - Session save and resume checkpointing (`checkpoint.py`).
