# Architecture Overview

## Goals
- Provide a stable DFIR/reverse-forensics platform foundation.
- Ensure uniform guardrails, evidence integrity, and standardized reporting.
- Enable third-party extensions through a plugin contract.

## High-Level Components
- **CLI layer**: Parses user input and dispatches to commands.
- **Platform core**: Hosts plugin registry, models, report generation pipeline, and security services.
- **Plugins**: Domain-specific analyzers (reverse engineering, DFIR).
- **Reporting**: JSON/Markdown formatters with schema versioning.
- **Security**: Guardrails, path policy, and redaction services applied consistently.

## Data Flow
1. CLI accepts inputs + configuration profile.
2. Guardrails validate resource limits.
3. Evidence is created (hashes, size, metadata).
4. Plugins analyze evidence to produce structured findings.
5. Reporters format findings into versioned output artifacts.
6. Evidence/report manifests are written to results/.

## Non-Goals (for now)
- Full DFIR feature parity with Autopsy/Plaso/Sleuth Kit.
- Advanced UI/TUI frameworks.


