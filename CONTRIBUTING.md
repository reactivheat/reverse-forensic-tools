# Contributing to reverse-forensic-tools

Thank you for your interest in improving **reverse-forensic-tools** by Operator Cedra. Contributions are welcome—whether they are bug reports, new features, documentation improvements, tests, or refactors.

> This project focuses on quality and maintainability for a production-grade forensic/RE CLI. Please read the guidelines below before opening a PR.

## 1) Welcome & Philosophy

- **Open source, community-driven**
- Focus on **security tooling quality**, not on feature quantity
- Prefer clarity, robust error handling, and predictable outputs for DFIR/SOC workflows

## 2) Code of Conduct

Be respectful and professional in discussions and pull requests.

- Assume good intent
- Avoid harassment or discriminatory language
- Provide actionable feedback (what/why/how)
- Maintain a constructive tone even during technical debates

## 3) Development Setup

```bash
git clone https://github.com/reactivheat/reverse-forensic-tools.git
cd reverse-forensic-tools

python -m venv .venv

# Linux / Parrot OS:
source .venv/bin/activate

# Windows:
# .venv\Scripts\activate

pip install -e .
pip install -r requirements-dev.txt
```

## 4) Branch Naming Convention

- `feature/module-name` (new features)
- `fix/issue-description` (bug fixes)
- `docs/what-you-changed` (documentation)
- `test/what-you-tested` (tests)

## 5) Commit Message Format (Conventional Commits)

Use the conventional format:

- `feat: add ELF analyzer module`
- `fix: handle corrupt PE headers gracefully`
- `docs: update README installation steps`
- `test: add unit tests for hash_calculator`
- `refactor: split PE parser into submodules`
- `ci: update GitHub Actions Python version`

## 6) How to Add a New Forensic Module (Step-by-step)

1. Create a folder under `src/forensic/` or `src/reverse_engineering/`
2. Add `__init__.py` with a module docstring
3. Create the main class (e.g. `ELFAnalyzer`)
4. Create a Click command module (e.g. `cli_xxx.py`) that:
   - parses CLI options
   - calls your analyzer class
   - renders user-facing output via Rich
5. Wire the command in `src/core/cli.py` using `cli.add_command()`
6. Add unit tests under `src/tests/unit/`
7. Update `README.md` features table and module status

## 7) Code Standards

- **PEP8 compliant** (enforced via `ruff`)
- **Type hints mandatory** on all public methods
- **Docstrings mandatory** (Google style)
- Error handling:
  - never expose raw Python tracebacks to end users
  - handle corrupt/invalid inputs gracefully
- All user-facing output must use **Rich** (`Panel`, `Table`, `console.print`)
- No hardcoded file paths or credentials

## 8) PR Checklist

- [ ] Tests pass (`pytest src/tests/`)
- [ ] Ruff lint passes (`ruff check src/`)
- [ ] Docstrings added/updated
- [ ] README updated if adding new functionality
- [ ] No hardcoded paths/credentials
- [ ] Error handling implemented

## 9) Running Tests Locally

```bash
pytest src/tests/ -v
ruff check src/

# Smoke test (requires your CLI entrypoint to be installed)
rft --help
```

