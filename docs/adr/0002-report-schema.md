# ADR 0002: Report Schema Versioning

## Status
Proposed/Accepted

## Context
Multiple outputs (JSON/Markdown) must remain stable across releases.

## Decision
Adopt `report_version` in every report artifact and test golden snapshots.

## Consequences
- Backward compatibility policy becomes enforceable.
- Tooling can safely upgrade schema versions.


