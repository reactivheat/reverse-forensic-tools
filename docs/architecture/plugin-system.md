# Plugin System

## Why a Plugin System
- Avoid tight coupling between the CLI and every forensic/reverse module.
- Allow third parties to ship new capabilities without changing core code.
- Maintain stable interfaces and versioned compatibility.

## Contract (Conceptual)
- Plugins register implementations for:
  - **Detector** (optional; identifies evidence type/format)
  - **Analyzer** (extracts findings)
  - **Reporter** (formats findings)

## Discovery
- Use Python `importlib.metadata.entry_points`.
- Plugin registry loads declared entry points at runtime.

## Versioning
- Plugins declare a **plugin API version**.
- Core validates compatibility before activation.

## Security Model
- Plugins run under platform services:
  - Guardrails validation
  - Path policy enforcement
  - Redaction-aware reporting

## Stability Rules
- Public plugin interfaces must be treated as stable API.
- Breaking changes require version bump and explicit migration notes.


