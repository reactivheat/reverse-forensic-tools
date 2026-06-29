# Reporting Format

## Report Schema Versioning
- Every report includes `report_version`.
- Schema changes require a new report version.

## JSON
- Stable, machine-readable structure.
- Always includes evidence manifest reference.

## Markdown
- Human-readable summary with redaction-aware formatting.
- Must preserve truncation metadata.

## Future Formats
- SARIF, CSV, XML can be added via reporter plugins.


