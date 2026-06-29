# Security Policy

## Disclaimer (Read First)

This tool is for **AUTHORIZED USE ONLY**.

Only analyze files and systems you own or have explicit written permission to test. Misuse may violate laws including CFAA, the Computer Misuse Act, and local regulations.

---

## Supported Versions

- **Python 3.12+** (actively supported)
- Python 3.10, 3.11 (best effort)
- **Python 3.15 alpha (NOT supported — known crashes)**

---

## Reporting a Vulnerability

Do **NOT** open a public GitHub issue for security vulnerabilities.

Report via GitHub private security advisory:

https://github.com/reactivheat/reverse-forensic-tools/security/advisories/new

When reporting, include:

- a clear description of the issue
- steps to reproduce (as precise as possible)
- impact assessment (what could be affected)
- any mitigation/workarounds you discovered

Response time: **best effort within 7 days**.

---

## Safe Use Guidelines

- Only analyze files you own or have permission to analyze
- Do not use against production systems without written authorization
- Be aware of local laws regarding reverse engineering and malware analysis
- Use in isolated environments (VMs, sandboxes) when analyzing malware
- Do not submit real malware samples to public repositories

---

## Known Limitations

- The tool does not guarantee detection of all malware or packed binaries
- YARA integration (planned) will require separate rule validation
- Memory forensics module (planned) requires elevated privileges

---

## Security of the Codebase Itself

- Bandit static analysis runs on every CI push
- Dependency security checks via `pip audit` (planned)
- No network calls made by default
- All file operations are **read-only** (no modification of analyzed files)

---

## Contact

For security inquiries, use the GitHub private advisory link above.

