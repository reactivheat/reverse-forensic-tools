# CLI Design

## Command Contract
- Each command returns a structured result that can be reported.
- CLI handles exit codes and error rendering.

## Redaction
- `--redact` switches reporter output mode.

## Output Restrictions
- User exports must be constrained under `data/output/`.
- Integrity artifacts and JSON reports must be under `results/`.

## Batch/Repeatability
- CLI operations should produce deterministic JSON given the same inputs.


