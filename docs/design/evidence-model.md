# Evidence Model

## Evidence
Represents inputs and derived artifacts.

Required fields (conceptual):
- `evidence_id`
- `path` (optional/redacted)
- `size_bytes`
- `hashes` (at least sha256)
- `timestamp`
- `tool_versions`

## Manifests
- `artifact_manifest.json` listing generated outputs and their hashes.
- `report_manifest.json` listing report artifacts.

## Immutability
- Evidence models are treated as immutable during a run.


