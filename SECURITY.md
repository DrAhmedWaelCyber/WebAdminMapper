# Security Policy

## Supported Versions

The following versions of **WebAdminMapper** are currently supported with security and stability updates:

| Version | Supported          |
| :------ | :----------------- |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |

---

## Reporting a Vulnerability

We take the security of WebAdminMapper seriously. If you discover a security vulnerability or critical bug, please follow these disclosure guidelines:

1. **Do NOT open a public GitHub issue.**
2. Send an email directly to the author and lead maintainer:
   - **Ahmed Wael**: [ahmedwael6143@gmail.com](mailto:ahmedwael6143@gmail.com)
3. Include the following details in your report:
   - Description of the vulnerability or flaw.
   - Minimal steps or proof-of-concept to reproduce the behavior.
   - Potential impact and affected components.
   - Any suggested remediations or patches.

### Response Timeline
- **Initial Acknowledgement:** Within 48 hours.
- **Triage & Reproduction:** Within 5 business days.
- **Patch & Advisory Release:** Timely release following coordinated disclosure.

---

## Defensive & Non-Destructive Scanning Guidance

WebAdminMapper is engineered specifically for non-destructive administrative discovery, directory mapping, and defensive security posture baseline evaluation.

- Always ensure you have **explicit, written permission** from the system owner before performing scans on any network or infrastructure you do not own.
- When scanning production targets, configure appropriate rate limits (`--rate-limit 10`, `--delay 0.1`) to prevent resource exhaustion or service degradation on remote hosts.
