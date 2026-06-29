# ADR 0003: Security Guardrails

## Status
Proposed/Accepted

## Context
Forensic tools must be resilient to malicious inputs and prevent accidental data leakage.

## Decision
Centralize guardrails and path policy into platform services and enforce them at analyzer boundaries.

## Consequences
- Security posture becomes consistent.
- Plugins rely on platform enforcement.


