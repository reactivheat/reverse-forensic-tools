# Security Model

## Threat Model (Pragmatic)
- Path traversal via output filenames.
- Symlink/reparse-point abuse.
- Oversized input causing memory/CPU exhaustion.
- Accidental leakage of evidence paths/hashes.
- Non-deterministic outputs and missing provenance.

## Security Services
### GuardrailsService
- Validate max file sizes.
- Validate maximum read bytes.
- Validate maximum section counts and string extraction limits.

### PathPolicy
- Resolve and enforce output destinations inside allowed base dirs.
- Defend against symlink/reparse-point writes.
- Write via safe temp files + atomic rename where applicable.

### RedactionService
- Enable `--redact` to suppress sensitive fields in user-facing output.
- Preserve sensitive values internally for manifest integrity (configurable).

### Evidence integrity
- Always compute hashes for inputs and exported artifacts.
- Generate manifests listing hashes and tool versions.

## Enforcement Strategy
- Platform boundary enforces services; plugins should not bypass them.


