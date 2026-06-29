# Coding Standard

## Language and Style
- Python 3.10+
- Type hints everywhere.
- Google-style docstrings.
- `pathlib.Path` for all paths.
- No `os.system()`.
- No unrestricted file writes.

## Formatting
- Black compatible formatting.
- Import order via isort.

## Error Handling
- Exceptions must be domain-mapped (ToolInputError, EvidenceError, ParserError, GuardrailError).
- Error messages must be actionable and must not leak secrets when redaction is enabled.

## Security & IO
- Use platform safe IO helpers.
- Validate and cap all potentially unbounded operations.


