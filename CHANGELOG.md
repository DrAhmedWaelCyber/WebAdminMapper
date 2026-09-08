# Changelog

All notable changes to **WebAdminMapper** are documented in this file.

The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standard.

**Author & Developer:** Ahmed Wael ([ahmedwael6143@gmail.com](mailto:ahmedwael6143@gmail.com))  
**Repository:** [https://github.com/DrAhmedWaelCyber/WebAdminMapper](https://github.com/DrAhmedWaelCyber/WebAdminMapper)

---

## [1.1.0] - 2026-09-08

### Added
- **Token Bucket Rate Limiter (`web_mapper/rate_limiter.py`):**
  - Thread-safe Token Bucket rate limiter decoupling request frequency from thread worker concurrency (`--rate-limit <rps>`).
  - Zero-initial-burst design pacing requests evenly at deterministic intervals.
  - Configurable inter-request delay (`--delay`) and randomized timing jitter (`--jitter`).
  - Unit test suite in `tests/test_rate_limiter.py` verifying thread-safety and concurrency decoupling.
- **Statistical Soft-404 & Heuristic Confusion Matrix Suite (`tests/test_heuristic_validation.py`):**
  - Dedicated validation suite verifying soft-404 detection across normal 404, soft-404, wildcard, and legitimate pages.
  - Achieved 100% classification accuracy with 0 False Positives and 0 False Negatives.
  - Added `evaluate()` API to `Soft404Detector` returning `(is_soft_404, similarity_score, reason)`.
- **Security Assertion Classification Overhaul (`web_mapper/security_assertions.py`):**
  - Classified findings into four definitive categories: `Confirmed Observation`, `Potential Finding`, `Informational`, and `Requires Manual Verification`.
  - Added `confidence` ratings (`HIGH`, `MEDIUM`, `LOW`), `impact` descriptions, and `manual_verification_required` boolean gates.
  - Unit tests in `tests/test_security_assertions.py` verifying precision and classification rules.
- **Automated Security Baseline Assessment & Control Mapping (`web_mapper/compliance.py`):**
  - Repositioned Compliance Engine as an automated baseline indicator mapping tool.
  - Documented `detection_logic`, `evidence`, `limitations`, and `remediation` for every catalogued control across OWASP ASVS v4.0, CIS Web Benchmarks, and NIST SP 800-53 Rev 5.
  - Enforced compliance disclaimer clarifying that non-destructive indicator mapping complements but does not substitute manual penetration testing.
- **Reporting Enhancements & Companion CSV Exports (`web_mapper/reporter.py`):**
  - Updated JSON export metadata version to `1.1.0`.
  - Added companion CSV exporters for security assertions (`<stem>_assertions.csv`) and compliance controls (`<stem>_compliance.csv`) with full schema isolation.
  - Enhanced HTML and Markdown report generators with detection logic, classification badges, confidence ratings, and manual verification indicators.
- **Multi-Version GitHub Actions CI Pipeline (`.github/workflows/tests.yml`):**
  - Continuous integration testing across Python 3.10, 3.11, 3.12, and 3.13 on `ubuntu-latest`.
  - Quality gates for linting (`compileall`), unit tests, heuristic validation, integration tests, and package installation.
- **Dedicated Multi-Threaded Local Integration Test Server (`tests/local_test_server.py`):**
  - In-process test server serving controlled endpoints (`/test-200`, `/test-301`, `/test-302`, `/test-403`, `/test-404`, `/test-500`, `/soft-404`, `/wildcard`, `/slow`, `/admin`, `/.env`, `/.git/config`, `/redirect`).
  - Native fallback transport via `socket.socketpair()` for sandboxed environments where loopback TCP binding is restricted.
  - 11 end-to-end integration tests in `tests/test_integration.py` passing with 100% coverage.
- **Performance Benchmarking Suite (`benchmarks/benchmark_suite.py`):**
  - Measures raw throughput, latency percentiles (P50, P90, P99), and peak memory usage via `tracemalloc`.
  - Serializes empirical results to `benchmarks/benchmark_results.json`.
  - Benchmarked at ~1,700+ req/s with 0 errors across 5 to 100 threads on Apple M2 hardware.
- **Project Governance & Community Files:**
  - Added `LICENSE` (MIT License).
  - Added `CONTRIBUTING.md` and `SECURITY.md`.

### Changed
- **Granular Exception Handling & Zero Swallow Rule (`engine.py`, `requester.py`):**
  - Replaced broad catches with categorized handling: `timeouts`, `ssl_errors`, `connection_errors`, `network_errors`, `http_parsing_errors`, `invalid_input_errors`, `unexpected_errors`.
  - Never swallows unexpected programming errors; logs structured diagnostic traces to `sys.stderr` while ensuring individual probe failures do not crash active scans.
  - Explicit socket and connection cleanup resolving `ResourceWarning` on Python 3.14.
- **Cleaned Codebase Imports:**
  - Eliminated unused imports across `crawler.py`, `generator.py`, `checkpoint.py`, `cert_inspector.py`, `rate_limiter.py`, `heuristics.py`, `security_assertions.py`, and `reporter.py`.

---

## [1.0.0] - 2026-09-08

### Added
- Initial production release of WebAdminMapper suite.
- Zero-dependency architecture utilizing strictly Python Standard Library.
- Multithreaded path enumeration, recursive directory exploration, and sitemap generation.
- Technology profiling, WAF detection, and SSL/TLS certificate diagnostics.
- Security posture scoring and defensive header auditing.
