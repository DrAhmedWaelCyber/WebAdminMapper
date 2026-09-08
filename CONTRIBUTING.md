# Contributing to WebAdminMapper

Thank you for your interest in contributing to **WebAdminMapper**! We welcome bug reports, feature suggestions, and code contributions that adhere to the project principles.

## Core Architectural Principles

1. **Zero External Runtime Dependencies**:
   - WebAdminMapper must remain 100% executable on any clean installation of Python >= 3.8 using **only the Python Standard Library**.
   - Do NOT introduce dependencies such as `requests`, `urllib3`, `aiohttp`, `rich`, `click`, etc.
   - Any feature, network request, parsing logic, or UI rendering must be implemented using standard library modules (`http.client`, `urllib`, `ssl`, `socket`, `concurrent.futures`, `json`, `csv`, `re`).

2. **Reliability & Granular Error Handling**:
   - Never use broad `except Exception:` catches without categorizing or logging the error.
   - Always differentiate between network errors, timeouts, connection refusals, SSL/TLS handshake failures, and invalid input.
   - Individual probe failures must never crash an active scan job.
   - Unexpected programming exceptions must be tracked and logged for diagnostics.

3. **Accuracy & Low False Positive Rates**:
   - Security assertions and heuristics must be statistically validated.
   - Assertions must be classified accurately:
     - `Confirmed Observation`: Directly observed, unambiguous facts (e.g. exposed `.env` file containing secrets, HTTP 500 stack trace).
     - `Potential Finding`: Indicators requiring contextual review.
     - `Informational`: Discovery surface mapping (e.g. query parameters).
     - `Requires Manual Verification`: When manual triage is necessary.

4. **Thread Safety & Resource Boundedness**:
   - All shared state must use appropriate synchronization primitives (`threading.Lock`).
   - Rate limiters, token buckets, and request pacing must remain deterministic across variable thread counts.
   - Generators and iterators must stream in bounded batches to keep peak memory minimal.

---

## Development Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/DrAhmedWaelCyber/WebAdminMapper.git
   cd WebAdminMapper
   ```

2. **Create a Virtual Environment (Optional, for running pytest):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install pytest
   ```

3. **Verify Everything Runs:**
   ```bash
   python3 main.py -u https://example.com -q
   ```

---

## Running Tests

Before submitting any Pull Request, ensure that the entire test suite passes without errors:

```bash
# Run all unit, integration, and heuristic validation tests
pytest tests/

# Or run using standard library unittest without any virtualenv:
python3 -m unittest discover tests

# Check bytecode compilation and syntax across all modules:
python3 -m compileall web_mapper tests benchmarks setup.py
```

---

## Pull Request Guidelines

- Create a feature branch from `main`: `git checkout -b feature/my-feature`
- Write unit tests for new functionality under `tests/test_<module>.py`.
- Maintain docstrings and PEP 8 formatting.
- Update `CHANGELOG.md` following the [Keep a Changelog](https://keepachangelog.com/) format.
- Open a Pull Request with a clear explanation of changes and verification steps.

---

## Code of Conduct

Please treat all contributors with respect and professionalism. WebAdminMapper is developed for authorized administrative auditing and defensive security assessments.
