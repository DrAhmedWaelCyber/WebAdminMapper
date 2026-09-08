# ⚡ WebAdminMapper (Enterprise Edition)

> **High-Performance Web Administration, Recursive Directory Mapping, Infrastructure Intelligence, and Security Posture Auditing Suite.**

[![Developer](https://img.shields.io/badge/Developer-Ahmed%20Wael-blue.svg)](https://github.com/)
[![Version](https://img.shields.io/badge/Version-1.1.0--Enterprise-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-orange.svg)]()
[![Python](https://img.shields.io/badge/Python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Standard%20Library)-brightgreen.svg)]()
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Passing-brightgreen.svg)]()

**Developer & Author:** **Ahmed Wael**  
**Contact:** `ahmedwael6143@gmail.com`  


---

## 📑 Table of Contents

1. [Executive Summary & Core Philosophy](#-executive-summary--core-philosophy)
2. [High-Level Technical Architecture](#-high-level-technical-architecture)
3. [Modular System Breakdown](#-modular-system-breakdown)
4. [Enterprise Capabilities](#-enterprise-capabilities)
   - [Multithreaded Execution & Connection Pooling](#multithreaded-execution--connection-pooling)
   - [Recursive Directory Expansion](#recursive-directory-expansion)
   - [Intelligent Soft-404 & Heuristic Calibration](#intelligent-soft-404--heuristic-calibration)
   - [Technology Stack & CMS Fingerprinting](#technology-stack--cms-fingerprinting)
   - [Defensive Security Posture & Header Auditing](#defensive-security-posture--header-auditing)
   - [Native SSL/TLS Certificate Diagnostics](#native-ssltls-certificate-diagnostics)
   - [Route Harvesting (robots.txt & sitemap.xml)](#route-harvesting-robotstxt--sitemapxml)
   - [Interactive HTML Dashboard & Multi-Format Reporting](#interactive-html-dashboard--multi-format-reporting)
   - [Hierarchical Site Map Tree Visualizer](#hierarchical-site-map-tree-visualizer)
   - [Automated Security Assertions & Vulnerability Validations](#automated-security-assertions--vulnerability-validations)
   - [Defensive Security Assessment & Compliance Baseline Engine](#defensive-security-assessment--compliance-baseline-engine)
   - [Network Diagnostics & Latency Metrics](#network-diagnostics--latency-metrics)
   - [Session Checkpoints & State Resumption](#session-checkpoints--state-resumption)
5. [Installation & Requirements](#-installation--requirements)
6. [Comprehensive Command-Line Reference](#-comprehensive-command-line-reference)
7. [Wordlist Catalogs & Mutation Strategies](#-wordlist-catalogs--mutation-strategies)
8. [Step-by-Step Production Scenarios](#-step-by-step-production-scenarios)
9. [Programmatic Python SDK Guide](#-programmatic-python-sdk-guide)
10. [Performance Benchmarks & Empirical Validation](#-performance-benchmarks--empirical-validation)
11. [Known Limitations & Operational Scenarios](#-known-limitations--operational-scenarios)
12. [Automated Test Suite & CI/CD Pipeline](#-automated-test-suite--cicd-pipeline)
13. [Author Attribution & Legal Disclaimer](#-author-attribution--legal-disclaimer)

---

## 🚀 Executive Summary & Core Philosophy

**WebAdminMapper** is a modular, high-speed Python utility built for systems administrators, web engineers, and security auditors. Designed and developed by **Ahmed Wael**, it solves the common pitfalls of legacy directory fuzzers:

- **Zero External Dependencies**: Operates 100% natively on Python standard libraries (`urllib`, `http.client`, `ssl`, `socket`, `concurrent.futures`, `json`, `csv`). No `pip install` failures, virtual environment breakage, or third-party dependency drift.
- **Extreme Concurrency**: Powered by a non-blocking `ThreadPoolExecutor` capable of probing 1,000–3,500+ requests per second on local and low-latency networks.
- **Intelligent Heuristics**: Dynamic soft-404 suppression analyzes word counts, line counts, and token similarity to eliminate false positives from custom error pages.
- **Holistic Infrastructure Auditing**: Combines path resolution with TLS certificate analysis, defensive HTTP header evaluation, technology fingerprinting, network diagnostics, and latency percentiles.

---

## 📐 High-Level Technical Architecture

```
                               ┌────────────────────────────────────────┐
                               │   WebAdminMapper CLI / SDK (main.py)   │
                               └───────────────────┬────────────────────┘
                                                   │
                ┌──────────────────────────────────┼──────────────────────────────────┐
                ▼                                  ▼                                  ▼
   ┌──────────────────────────┐       ┌──────────────────────────┐       ┌──────────────────────────┐
   │ ScanConfig & Validation  │       │ Network Diagnostics & IP │       │  SSL/TLS Cert Inspector  │
   │  (web_mapper/config.py)  │       │(web_mapper/network_diag) │       │(web_mapper/cert_inspector│
   └────────────┬─────────────┘       └────────────┬─────────────┘       └────────────┬─────────────┘
                │                                  │                                  │
                └──────────────────────────────────┼──────────────────────────────────┘
                                                   ▼
                                      ┌──────────────────────────┐
                                      │ Route Harvester (Crawler)│
                                      │ (robots.txt, sitemap.xml)│
                                      └────────────┬─────────────┘
                                                   │
                ┌──────────────────────────────────┼──────────────────────────────────┐
                ▼                                  ▼                                  ▼
   ┌──────────────────────────┐       ┌──────────────────────────┐       ┌──────────────────────────┐
   │ PathGenerator & Mutator  │       │ Soft-404 & WAF Detector  │       │  Tech Stack Fingerprint  │
   │(web_mapper/generator.py) │       │(web_mapper/heuristics.py)│       │(web_mapper/fingerprint.py│
   └────────────┬─────────────┘       └────────────┬─────────────┘       └────────────┬─────────────┘
                │                                  │                                  │
                └──────────────────────────────────┼──────────────────────────────────┘
                                                   ▼
                                      ┌──────────────────────────┐
                                      │ ExecutionEngine (Threads)│
                                      │  (web_mapper/engine.py)  │
                                      └────────────┬─────────────┘
                                                   │
                                      ┌────────────┴─────────────┐
                                      ▼                          ▼
                       ┌──────────────────────────┐ ┌──────────────────────────┐
                       │ Security Posture Auditor │ │  SiteMap Tree Generator  │
                       │(web_mapper/security_audit│ │  (web_mapper/sitemap.py) │
                       └──────────────┬───────────┘ └────────────┬─────────────┘
                                      │                          │
                                      └────────────┬─────────────┘
                                                   ▼
                                      ┌──────────────────────────┐
                                      │ Multi-Format Reporting   │
                                      │ (HTML / JSON / CSV / MD) │
                                      └──────────────────────────┘
```

---

## 🧩 Modular System Breakdown

The codebase is organized into cleanly separated single-responsibility modules:

| Module | Source Path | Description |
| :--- | :--- | :--- |
| **CLI Controller** | [`web_mapper/cli.py`](web_mapper/cli.py) | Parses arguments, manages live terminal UI, displays ANSI status tables, and coordinates execution. |
| **Configuration** | [`web_mapper/config.py`](web_mapper/config.py) | Enforces strict validation, normalizes URLs, manages filters, and serializes/deserializes JSON scan profiles. |
| **Execution Engine** | [`web_mapper/engine.py`](web_mapper/engine.py) | Coordinates thread pools, batches requests, handles recursive directory queues, and updates progress counters. |
| **HTTP Requester** | [`web_mapper/requester.py`](web_mapper/requester.py) | Low-level network requester, custom redirect handlers, SSL bypass/enforcement, title extraction, and MD5/SHA-256 body hashing. |
| **Path Generator** | [`web_mapper/generator.py`](web_mapper/generator.py) | Compiles curated wordlists, processes STDIN pipelines, mutates prefixes/suffixes, transforms casing, and permutes extensions. |
| **Heuristics & Soft-404** | [`web_mapper/heuristics.py`](web_mapper/heuristics.py) | Multi-sample baseline probes, word/line count comparison, Jaccard token similarity clustering, and WAF identification. |
| **Tech Fingerprinting** | [`web_mapper/fingerprint.py`](web_mapper/fingerprint.py) | Identifies servers (Nginx, Apache, IIS, Caddy), frameworks (Laravel, Django, Spring Boot, Express), and CMS systems (WordPress, Drupal). |
| **Security Posture** | [`web_mapper/security_audit.py`](web_mapper/security_audit.py) | Evaluates defensive HTTP headers (HSTS, CSP, XFO, nosniff), cookie attributes, and information leaks, calculating a 0–100 score and letter grade. |
| **TLS Cert Inspector** | [`web_mapper/cert_inspector.py`](web_mapper/cert_inspector.py) | Inspects certificate authorities, validity dates, days until expiry, cipher suites, TLS version, and Subject Alternative Names (SANs). |
| **Route Harvester** | [`web_mapper/crawler.py`](web_mapper/crawler.py) | Extracts routes from `/robots.txt` (Disallow/Allow), `/sitemap.xml` (`<loc>`), and in-scope HTML links/scripts. |
| **Site Map Visualizer** | [`web_mapper/sitemap.py`](web_mapper/sitemap.py) | Constructs an in-memory N-ary tree from discovered paths and renders formatted ASCII directory trees. |
| **Reporter & Exporters** | [`web_mapper/reporter.py`](web_mapper/reporter.py) | Generates dark-themed interactive HTML reports, structured JSON data, CSV spreadsheets, Markdown documentation, and terminal tables. |
| **Compliance Engine** | [`web_mapper/compliance.py`](web_mapper/compliance.py) | Audits application endpoints against OWASP ASVS v4.0, CIS Web Benchmarks, and NIST SP 800-53 Rev 5 baselines with compliance scoring. |
| **Security Assertions** | [`web_mapper/security_assertions.py`](web_mapper/security_assertions.py) | Programmatically checks for improper access controls, backup leaks, dangerous verbs, and input injection surfaces. |
| **Session Checkpoint** | [`web_mapper/checkpoint.py`](web_mapper/checkpoint.py) | Serializes scan state to disk for checkpointing and resuming long-running audits. |
| **Network Diagnostics** | [`web_mapper/network_diag.py`](web_mapper/network_diag.py) | Resolves IPv4/IPv6 addresses, canonical CNAME records, reverse DNS hostnames, and measures TCP connect latency. |


---

## ⚡ Enterprise Capabilities

### Multithreaded Execution & Connection Pooling
WebAdminMapper uses Python's `ThreadPoolExecutor` to handle concurrent HTTP connections. Worker counts are configurable via `-t / --threads` (1 to 200). The engine streams candidate paths in memory-bounded batches, preventing memory exhaustion even when scanning dictionaries with hundreds of thousands of entries.

### Recursive Directory Expansion
When scanning with `-r / --recursive`, whenever an endpoint returns a directory status code (`200`, `301`, `302`, `401`, `403`), WebAdminMapper dynamically queues sub-paths for exploration up to `--depth N`. Built-in cycle detection and static file extension exclusions prevent recursion loops.

### Intelligent Soft-404 & Heuristic Calibration
Standard HTTP status filtering often fails against web servers configured to return `200 OK` or `302 Redirect` for non-existent routes (soft-404s). WebAdminMapper mitigates this by:
1. Probing pseudo-random seeds (`/_wm_probe_<hex>.html`, `/_wm_probe_<hex>/`) on startup.
2. Capturing status codes, body lengths, word counts, line counts, and word-token sets.
3. Performing **Jaccard Token Similarity** matching (>94% similarity threshold) against the baseline profile to filter out disguised error pages.

### Technology Stack & CMS Fingerprinting
Automated profiling parses response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`), cookie signatures (`PHPSESSID`, `JSESSIONID`, `laravel_session`, `csrftoken`), and HTML body markers (`/wp-content/`, Spring Whitelabel, Django CSRF, Next.js `__NEXT_DATA__`) to report the underlying infrastructure.

### Defensive Security Posture & Header Auditing
Audits target response headers against defensive security standards:
- **Strict-Transport-Security (HSTS)**: Validates max-age and `includeSubDomains`.
- **Content-Security-Policy (CSP)**: Checks for active content injection mitigation.
- **X-Frame-Options**: Checks for clickjacking defenses (`DENY` or `SAMEORIGIN`).
- **X-Content-Type-Options**: Enforces `nosniff` against MIME sniffing.
- **Referrer-Policy & Permissions-Policy**: Audits browser feature restrictions.
- **Cookie Security**: Verifies `Secure`, `HttpOnly`, and `SameSite` flags.
- **Grading Matrix**: Computes an automated score (0–100) and letter grade (**A+, A, B, C, D, F**) with remediation instructions.

### Native SSL/TLS Certificate Diagnostics
Without external OpenSSL or cryptography packages, WebAdminMapper connects via TLS and extracts:
- Certificate Authority (CA) & Issuer
- Expiration timestamp and **Days Remaining** (highlighted red if < 30 days)
- TLS Protocol (`TLSv1.2`, `TLSv1.3`) & Cipher Suite
- **Subject Alternative Names (SANs)**, revealing related subdomains and corporate infrastructure.

### Route Harvesting (robots.txt & sitemap.xml)
Automatically checks `/robots.txt` and `/sitemap.xml` on target hosts, extracting hidden directories and canonical paths to seed the candidate queue before fuzzing begins.

### Interactive HTML Dashboard & Multi-Format Reporting
Outputs professional, standalone HTML reports (`-f html`) featuring:
- Responsive dark-mode styling
- Dynamic client-side search bar for real-time path/status filtering
- Executive metrics cards (Target, Discovered Routes, Duration, WAF status)
- Security Posture Findings Table with severity badges
- Hierarchical ASCII site tree visualization

### Hierarchical Site Map Tree Visualizer
Constructs a directory tree of the discovered attack surface and renders it to the terminal:
```
https://example.com
├── .env [403] (30B)
├── actuator [200] (18B)
├── admin [301] (0B) -> /admin/login
│   └── login [200] (97B) "Admin Control Center"
└── api [200] (22B)
    └── v1 [200] (20B)
```

### Automated Security Assertions & Vulnerability Validations
WebAdminMapper includes an automated, non-destructive vulnerability assertion module ([`web_mapper/security_assertions.py`](web_mapper/security_assertions.py)) designed to inspect discovered endpoints for critical application vulnerabilities and configuration weaknesses:
- **Improper Access Control**: Flags unrestricted administrative portals, dashboards, and actuator endpoints returning `200 OK` without authentication gates.
- **Sensitive Data Exposure**: Identifies accessible backup archives (`.sql`, `.bak`, `.tar.gz`), environment configs (`.env`, `web.config`), and version control directories (`.git`).
- **Dangerous HTTP Verbs & Tampering**: Detects `TRACE`/`TRACK` methods (enabling Cross-Site Tracing) and unauthenticated `PUT`/`DELETE` modification verbs.
- **Verbose Banners & Information Leaks**: Inspects server version tokens, missing sensitive `Cache-Control: no-store` headers on APIs, and server-side stack traces.
- **Injection Surface Mapping**: Catalogs active query parameters and input endpoints to map the attack surface safely without generating disruptive payloads.

### Defensive Security Assessment & Compliance Baseline Engine
Architected and developed by **Ahmed Wael**, WebAdminMapper provides an enterprise-grade defensive compliance engine ([`web_mapper/compliance.py`](web_mapper/compliance.py)) that programmatically audits discovered application endpoints and server configurations against three globally recognized security standards:
1. **OWASP ASVS v4.0 (Application Security Verification Standard)**:
   - *V1 Architecture & Threat Modeling*: Suppression of architectural footprint and dangerous debug interfaces.
   - *V4 Access Control Verification*: Protection of privileged administrative routes, consoles, and actuator panels.
   - *V5 Input Validation & Sanitization*: Detection and inventorying of dynamic parameter injection surfaces.
   - *V8 Data Protection*: Identification of exposed environment variables (`.env`), database backups (`.sql`), private keys, and missing sensitive caching controls (`Cache-Control: no-store`).
   - *V14 Server Configuration*: Enforcement of strict HTTPS transport (HSTS), Content-Security-Policy (CSP), Clickjacking framing defenses (X-Frame-Options), MIME sniffing protection (X-Content-Type-Options), and Origin restriction (CORS).
2. **CIS Web Application & Server Configuration Benchmarks**:
   - Web server banner and technology version suppression (`ServerTokens Prod`, `server_tokens off`).
   - SCM repository access restriction (`.git`, `.svn`, `.hg`).
   - Transport Layer Security configuration baseline and encryption posture.
3. **NIST SP 800-53 Rev 5 (Security and Privacy Controls)**:
   - *AC-3 & AC-6*: Access Enforcement and Least Privilege on administrative control surfaces.
   - *SC-8 & SC-13*: Transmission Confidentiality and Cryptographic Protection over public networks.
   - *SC-28*: Protection of Information at Rest against unauthorized backup disclosure.
   - *SI-10*: Information Input Validation surface gating.
   - *SI-11*: Error Handling and suppression of verbose system stack traces.

The compliance engine computes a weighted compliance percentage (**0.0% – 100.0%**) and awards a normalized compliance letter grade (**A+ Compliant, A, B, C, D, or F Critical Non-Compliance**), breaking down passing and failing controls by standard. Every finding includes authoritative rule references, concrete endpoint evidence, and actionable defensive remediation instructions.

### Network Diagnostics & Latency Metrics
Measures DNS resolution, reverse DNS hostnames, TCP handshake time, and statistical response latency distributions (**Min, Max, Mean, p50, p90, p99**).

---

## 💻 Installation & Requirements

### Compatibility
- Python 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, and 3.14+
- macOS, Linux, and Windows

### Zero-Dependency Quickstart
```bash
cd ~/Desktop/WebAdminMapper
python3 main.py -u https://example.com
```

### Optional Global CLI Installation
```bash
cd ~/Desktop/WebAdminMapper
pip3 install -e .
webadminmapper -u https://example.com
```

---

## ⚙️ Comprehensive Command-Line Reference

| Flag | Long Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Target Options** | | | | |
| `-u` | `--url` | String | *Required* | Target host base URL (e.g. `https://example.com`). |
| | `--profile` | Path | `None` | Load complete scan configuration from a JSON profile file. |
| | `--resume` | Path | `None` | Resume discovery session from a saved JSON checkpoint file. |
| **Wordlists & Fuzzing** | | | | |
| `-w` | `--wordlist` | Path | `None` | Path to custom wordlist file, or `-` for STDIN pipe. |
| `-m` | `--mode` | Choice | `all` | Curated catalog: `admin`, `common`, `sensitive`, `cloud`, or `all`. |
| `-x` | `--extensions` | CSV | `""` | Comma-separated file extensions (e.g. `php,html,json,bak`). |
| | `--prefix` | String | `""` | Prefix to prepend to candidate words (e.g. `api/` or `v1_`). |
| | `--suffix` | String | `""` | Suffix to append to candidate words (e.g. `_backup` or `-dev`). |
| | `--case` | Choice | `None` | Wordlist casing: `lower`, `upper`, or `title`. |
| **Recursion** | | | | |
| `-r` | `--recursive` | Flag | `False` | Enable recursive exploration of discovered directories. |
| | `--depth` | Integer | `1` | Maximum recursion depth level. |
| **Performance & Network** | | | | |
| `-t` | `--threads` | Integer | `25` | Concurrent worker threads (1–200). |
| `-to` | `--timeout` | Float | `7.0` | HTTP request timeout in seconds. |
| `-d` | `--delay` | Float | `0.0` | Delay in seconds between requests per thread (rate limiting). |
| | `--retries` | Integer | `1` | Number of retries upon network timeout or connection reset. |
| **Filters & Matching** | | | | |
| `-mc` | `--match-codes` | CSV | `200,301,401...`| Comma-separated HTTP status codes to match. |
| `-fc` | `--filter-codes` | CSV | `404` | Comma-separated HTTP status codes to filter out. |
| `-ms` | `--match-size` | CSV | `""` | Response body sizes (bytes) to match. |
| `-fs` | `--filter-size` | CSV | `""` | Response body sizes (bytes) to filter out. |
| `-mw` | `--match-words` | CSV | `""` | Word counts to match. |
| `-fw` | `--filter-words` | CSV | `""` | Word counts to filter out. |
| `-ml` | `--match-lines` | CSV | `""` | Line counts to match. |
| `-fl` | `--filter-lines` | CSV | `""` | Line counts to filter out. |
| `-mr` | `--match-regex` | Regex | `None` | Regex pattern that response bodies must match. |
| `-fr` | `--filter-regex` | Regex | `None` | Regex pattern to filter out responses. |
| | `--filter-text` | String | `None` | Filter responses containing substring. |
| | `--no-wildcard` | Flag | `False` | Disable automatic soft-404 and wildcard calibration. |
| **Heuristics & Audits** | | | | |
| | `--no-tech` | Flag | `False` | Disable automatic technology & CMS profiling. |
| | `--no-audit` | Flag | `False` | Disable defensive security posture and header evaluation. |
| | `--no-cert` | Flag | `False` | Disable SSL/TLS certificate inspection. |
| | `--no-net-diag`| Flag | `False` | Disable network DNS resolution and TCP latency diagnostics. |
| | `--no-harvest` | Flag | `False` | Disable route harvesting from `robots.txt` and `sitemap.xml`. |
| | `--no-tree` | Flag | `False` | Disable rendering the ASCII directory tree. |
| | `--audit-vulns` | Flag | `True` | Automated non-destructive security assertions & vulnerability validations. |
| | `--no-vuln-validate` | Flag | `False` | Disable automated security assertions and vulnerability validation. |
| | `--compliance` | Flag | `True` | Automated defensive security assessment & compliance baseline validation. |
| | `--no-compliance` | Flag | `False` | Disable defensive compliance validation engine. |
| | `--benchmark` | Choice | `all` | Compliance benchmark baseline: `all`, `owasp`, `cis`, or `nist`. |
| | `--no-title` | Flag | `False` | Disable HTML page title extraction. |
| **HTTP Customization** | | | | |
| `-a` | `--user-agent` | String | *Default UA* | Custom HTTP User-Agent header. |
| `-H` | `--header` | String | `None` | Custom header in `'Key: Value'` format (repeatable). |
| `-b` | `--cookie` | String | `None` | HTTP Cookie string (e.g. `'session=123'`). |
| `-p` | `--proxy` | URL | `None` | Proxy URL (e.g. `http://127.0.0.1:8080`). |
| `-k` | `--insecure` | Flag | `False` | Explicitly disable SSL certificate validation (default behavior). |
| | `--verify-ssl` | Flag | `False` | Strictly enforce SSL certificate verification. |
| | `--follow-redirects`| Flag | `False` | Follow HTTP redirects automatically. |
| **Output & Profiles** | | | | |
| `-o` | `--output` | Path | `None` | Destination file to export findings. |
| `-f` | `--format` | Choice | `table` | Export format: `table`, `html`, `json`, `csv`, `markdown`, `txt`. |
| | `--save-profile` | Path | `None` | Save current scan configuration to a JSON profile. |
| | `--checkpoint` | Path | `None` | Save session state checkpoint file upon completion or interrupt. |
| `-q` | `--quiet` | Flag | `False` | Quiet mode: suppress banners, print findings only. |
| `-v` | `--version` | Flag | - | Display version and author information. |

---

## 📚 Wordlist Catalogs & Mutation Strategies

WebAdminMapper includes four curated catalogs in [`web_mapper/wordlists/`](web_mapper/wordlists):

1. **Administrative Portals ([`admin_paths.txt`](web_mapper/wordlists/admin_paths.txt))**: ~300 entries covering administrative control centers (`/admin`, `/cpanel`, `/dashboard`, `/backend`, `/administrator`, `/manager`, `/kibana`, `/grafana`, `/jenkins`).
2. **Common Directories ([`common_dirs.txt`](web_mapper/wordlists/common_dirs.txt))**: ~300 entries covering common directory structures, asset paths, API routes, and file repositories.
3. **Sensitive Files & Backups ([`sensitive_files.txt`](web_mapper/wordlists/sensitive_files.txt))**: ~250 entries targeting `.env`, `.git/HEAD`, database dumps (`.sql`), compressed archives (`.zip`, `.tar.gz`), and server configuration files.
4. **Cloud & DevOps ([`cloud_devops.txt`](web_mapper/wordlists/cloud_devops.txt))**: ~150 entries covering AWS metadata endpoints, Spring Boot Actuator (`/actuator/health`, `/actuator/env`), Kubernetes, Swagger/OpenAPI docs, and GraphQL schemas.


---

## 🛠️ Step-by-Step Production Scenarios

### Scenario 1: Comprehensive Infrastructure & Security Audit
```bash
python3 main.py -u https://example.com -o full_audit.html -f html
```
*Performs DNS diagnostics, TLS certificate analysis, robots.txt harvesting, technology fingerprinting, security header grading, and directory discovery, exporting an interactive HTML report.*

### Scenario 2: Deep Administrative Portal Hunt (Recursive)
```bash
python3 main.py -u https://example.com -m admin -x php,html,json -r --depth 2 -t 35
```
*Explores administrative endpoints and recurses 2 levels deep into any discovered portals.*

### Scenario 3: Cloud & API Microservices Audit
```bash
python3 main.py -u https://example.com -m cloud -x json,yaml -t 40
```
*Targets Spring Boot Actuator routes, Swagger/OpenAPI docs, Kubernetes metrics, and cloud metadata.*

### Scenario 4: Precision Filtering against Custom Soft-404 Pages
```bash
python3 main.py -u https://example.com -fc 404 -fw 24 --filter-text "temporarily unavailable"
```
*Filters out responses returning status code 404, responses with exactly 24 words, or responses containing specific maintenance text.*

### Scenario 5: Pipeline Mode (Integration with Recon Tools)
```bash
cat subdomains_and_paths.txt | python3 main.py -u https://example.com -w - -t 50
```
*Streams candidate paths directly from STDIN for integration with UNIX pipeline tools.*

### Scenario 6: Proxying Traffic through Burp Suite / OWASP ZAP
```bash
python3 main.py -u https://example.com -p http://127.0.0.1:8080 -k
```
*Routes all requests through an upstream HTTP proxy with SSL verification disabled for manual traffic inspection.*

### Scenario 7: Reusable Configuration Profiles
```bash
# Save configuration
python3 main.py -u https://example.com -m admin -t 40 -r --depth 2 --save-profile prod_audit.json

# Execute against new target using saved profile
python3 main.py --profile prod_audit.json -u https://staging.example.com
```

### Scenario 8: Defensive Security Assessment & Compliance Audit
```bash
# Validate against OWASP ASVS v4.0 baseline and export HTML dashboard
python3 main.py -u https://example.com --benchmark owasp -o owasp_report.html -f html

# Full cross-standard audit (OWASP + CIS + NIST) with JSON export
python3 main.py -u https://example.com --benchmark all -o enterprise_compliance.json -f json
```
*Evaluates administrative controls, sensitive file disclosures, transport encryption, and client header protections against industry baselines, computing a normalized compliance score and grade.*

---

## 🐍 Programmatic Python SDK Guide

WebAdminMapper is fully modular and can be integrated directly into custom Python automation:

```python
from web_mapper import (
    ScanConfig,
    ExecutionEngine,
    HTTPRequester,
    CertInspector,
    SecurityAuditor,
    SecurityAssertionValidator,
    ComplianceEngine,
    RouteHarvester,
)

# 1. Configure the audit with compliance checks enabled
config = ScanConfig(
    target_url="https://example.com",
    threads=30,
    wordlist_type="admin",
    recursive=True,
    max_depth=2,
    compliance_check=True,
    compliance_benchmark="all",  # 'all', 'owasp', 'cis', 'nist'
    output_file="audit_report.json",
    output_format="json",
)

# 2. Initialize components
requester = HTTPRequester(config)
engine = ExecutionEngine(config, requester)

# 3. Inspect TLS and harvest routes
cert_info = CertInspector.inspect(config.target_url)
harvester = RouteHarvester(config.target_url)
crawled_paths = harvester.harvest_robots_txt(requester)

# 4. Execute scan with live callback
def on_result(result):
    print(f"[{result.status_code}] {result.path} ({result.content_length}B) - Latency: {result.response_time_ms:.1f}ms")

results = engine.run(on_result=on_result, extra_seed_paths=crawled_paths)

# 5. Evaluate defensive compliance against OWASP ASVS, CIS, and NIST
comp_engine = ComplianceEngine(benchmark=config.compliance_benchmark)
comp_report = comp_engine.evaluate(
    results=results,
    base_headers=requester.base_headers,
    target_url=config.target_url,
)
print(f"Compliance Grade: {comp_report.compliance_grade} ({comp_report.compliance_score:.1f}%)")
for finding in comp_report.findings:
    print(f"[{finding.severity}] {finding.rule_id} ({finding.benchmark}): {finding.title} on {finding.endpoint}")
```

---

## 📊 Performance Benchmarks & Empirical Validation

WebAdminMapper features a dedicated, zero-dependency benchmarking suite in [`benchmarks/benchmark_suite.py`](benchmarks/benchmark_suite.py) designed to measure raw execution throughput, concurrency scaling, latency distribution, and stability across variable thread worker pools.

### System Specifications Under Test
- **Operating System:** Darwin 25.5.0 (macOS arm64)
- **CPU Architecture:** Apple Silicon (8 logical cores)
- **Python Runtime:** CPython 3.14.7 (Standard Library only)
- **Test Server:** Native threaded local loopback server (`http.server`)
- **Requests per Trial:** 500 requests per concurrency bracket

### Reproducible Benchmark Results

The following metrics reflect empirical measurements generated by `benchmarks/benchmark_suite.py` and serialized to [`benchmarks/benchmark_results.json`](benchmarks/benchmark_results.json):

| Worker Threads | Total Requests | Execution Time | Throughput (Req/Sec) | Error Rate | Latency P50 | Latency P90 | Latency P99 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **5 Threads** | 500 | 0.151s | **3,313.4 req/s** | **0.0%** | 1.22 ms | 1.61 ms | 2.68 ms |
| **10 Threads** | 500 | 0.432s | **1,156.7 req/s** | **0.0%** | 1.52 ms | 30.68 ms | 31.99 ms |
| **25 Threads** | 500 | 0.512s | **977.0 req/s** | **0.0%** | 1.74 ms | 33.33 ms | 124.59 ms |
| **50 Threads** | 500 | 1.523s | **328.3 req/s** | **0.0%** | 2.02 ms | 99.02 ms | 1,060.52 ms |

### Running the Benchmarks Locally
To execute the benchmark suite and reproduce these metrics on your local hardware:
```bash
python3 benchmarks/benchmark_suite.py --requests 500 --output benchmarks/benchmark_results.json
```

---

## ⚠️ Known Limitations & Operational Scenarios

WebAdminMapper is optimized for automated defensive inventorying and structural mapping. Users should consider the following environmental factors during scans:

1. **Single-Page Applications (SPAs):**  
   Modern frontend frameworks (React, Vue, Angular) routing all HTTP requests to `/index.html` with status code `200 OK` can trigger widespread false positives. WebAdminMapper automatically engages its **Jaccard Token Similarity** heuristics to distinguish identical SPA index documents from genuine server-side routes. If all endpoints return the same SPA shell, review the soft-404 calibration threshold or configure path exclusion rules.
2. **Dynamic Error Pages & Timestamp Injection:**  
   Applications that inject variable CSRF tokens, session IDs, or rendering timestamps into error pages can reduce token overlap with static baselines. WebAdminMapper normalizes responses by stripping token variations and evaluating structural word and line counts.
3. **Web Application Firewalls (WAFs) & Rate Limiting:**  
   Aggressive multithreading (`-t 50+`) against protected endpoints may trigger rate-limiting controls (HTTP `429 Too Many Requests`), temporary IP bans, or Cloudflare/Akamai challenge pages. Use `--rate-limit` (e.g. `--rate-limit 10`) and moderate thread counts (`-t 5` to `-t 15`) to ensure consistent discovery without tripping firewall thresholds.
4. **Compliance Baseline Scope & Disclaimer:**  
   The **Defensive Security Assessment & Compliance Engine** performs non-destructive heuristic checks mapping observable HTTP indicators against OWASP ASVS v4.0, CIS Web Benchmarks, and NIST SP 800-53 Rev 5 baselines. While it reliably flags exposed administrative surfaces, missing defensive headers, unhandled 5xx states, and accessible sensitive file extensions, **it is an automated indicator mapping tool and does not replace comprehensive manual penetration testing, code review, or formal regulatory compliance audits.**

---

## 🧪 Automated Test Suite & CI/CD Pipeline

WebAdminMapper maintains an extensive, zero-dependency testing architecture consisting of 56 native unit and integration tests.

### What the Test Suite Verifies
- **Unit Tests:** Configuration validation, path mutation, Jaccard distance calculation, soft-404 baseline calibration, technology fingerprint regexes, WAF signatures, certificate inspection, and compliance scoring.
- **Integration Tests (`tests/test_integration.py`):** An automated local HTTP server tests status code routing (`200`, `301`, `302`, `403`, `404`, `500`), soft-404 suppression, slow endpoint read timeouts, connection failure recovery on closed ports, and multi-level recursive expansion.
- **Benchmark Tests (`tests/test_benchmarks.py`):** Validates system hardware profile discovery and benchmark trial metrics.

### Executing Tests Locally
```bash
python3 -m unittest discover tests
```

Output:
```
........................................................
----------------------------------------------------------------------
Ran 56 tests in 1.133s

OK
```

### GitHub Actions CI/CD Pipeline
WebAdminMapper automatically runs continuous integration checks on every push and pull request via [`.github/workflows/ci.yml`](.github/workflows/ci.yml):
- **Cross-Platform Matrix:** Tests across **Ubuntu**, **macOS**, and **Windows**.
- **Python Compatibility:** Verifies runtime compatibility across Python **3.8, 3.9, 3.10, 3.11, 3.12, and 3.13**.
- **Quality Gates:** Bytecode compilation check (`compileall`), test execution (`unittest`), benchmark smoke testing, and CLI entrypoint package installation (`pip install .`).

---

## 👤 Author Attribution & Legal Disclaimer

- **Lead Developer & Author:** **Ahmed Wael**
- **Email:** `ahmedwael6143@gmail.com`
- **Copyright:** (c) 2026, Ahmed Wael. All rights reserved.


### Legal Disclaimer
**WebAdminMapper** is authored by **Ahmed Wael** strictly for authorized administrative discovery, educational research, defensive infrastructure evaluation, and legitimate security assessments. Scanning targets without prior written authorization from the system owner is illegal. The author assumes no liability for misuse of this software.
