# Data Flow

## Overview
This document describes how data moves through Reverse Forensic Tools.

## Pipeline
### 1) Input
- User provides file paths and command arguments.
- CLI loads `config/config.yaml` and applies the selected profile.

### 2) Guardrails & Validation
- Platform validates file size limits, read limits, and structural constraints.

### 3) Evidence Creation
- EvidenceStore computes required hashes (at minimum SHA-256) and metadata.
- Evidence artifacts are tracked with manifests.

### 4) Detection / Parsing
- Detector identifies likely format.
- Format-specific plugin parsers produce findings and structured metadata.

### 5) Reporting
- Report versioned schema is populated.
- Reporters export artifacts to allowed output directories.

### 6) Manifests & Integrity
- Artifact manifests are written to `results/`.
- Optional redaction affects user-facing output while preserving integrity internally.

## Determinism
- Reports include truncation metadata when outputs are capped.
- Hashes and evidence metadata make runs reproducible.


