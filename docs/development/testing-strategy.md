# Testing Strategy

## Principles
- Prefer fixture-based tests.
- Golden snapshots for JSON/Markdown report schemas.
- Malformed corpus tests for parsers.
- Path-policy tests for export restriction.

## Levels
### Unit Tests
- Pure functions.
- Guardrails validators.
- Schema serialization.

### Integration Tests
- CLI commands against temporary files.
- Verify exit codes.
- Verify outputs under `data/output/` and `results/`.

### Regression Tests
- Golden report fixtures.
- Truncation metadata checks.

## Mocking External Libraries
- Use lightweight fixtures and mock parsers where external formats are unavailable.


