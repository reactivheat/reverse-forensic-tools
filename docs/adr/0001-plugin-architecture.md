# ADR 0001: Plugin Architecture

## Status
Proposed/Accepted

## Context
We need extensibility for DFIR/reverse modules without modifying core.

## Decision
Use a plugin contract with runtime discovery via `importlib.metadata.entry_points`.

## Consequences
- Plugins can be added/removed without changing core CLI.
- We must enforce API versioning and compatibility checks.


