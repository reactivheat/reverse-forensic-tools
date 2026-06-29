# Release Process

## Overview
Releases are produced via CI and must pass:
- lint
- unit/integration tests
- type checks
- security scanning (pip-audit/safety/bandit)

## Versioning
- Use semantic versioning.
- Plugin API changes require explicit plugin API version bump.

## Artifacts
- Attach build artifacts.
- Generate SBOM.
- Publish changelog and release notes.

## Security
- CI includes dependency scanning.
- Releases should be signed where feasible.


