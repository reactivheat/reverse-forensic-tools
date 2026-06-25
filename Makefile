# Makefile for Reverse Engineering & Digital Forensic Tools

.PHONY: help install dev test lint format clean build

# Default target
help:
    @echo "Available targets:"
    @echo "  install     - Install the package in development mode"
    @echo "  dev         - Install development dependencies"
    @echo "  test        - Run all tests"
    @echo "  lint        - Run linting and type checking"
    @echo "  format      - Format code with black and isort"
    @echo "  clean       - Clean build artifacts"
    @echo "  build       - Build distribution packages"

VENV ?= .venv
PYTHON ?= python3

install:
    $(PYTHON) -m pip install -e .

dev:
    $(PYTHON) -m pip install -r requirements-dev.txt

test:
    $(PYTHON) -m pytest tests/ -v

lint:
    $(PYTHON) -m flake8 src/ tests/
    $(PYTHON) -m mypy src/

format:
    $(PYTHON) -m black src/ tests/
    $(PYTHON) -m isort src/ tests/

clean:
    rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ __pycache__/ htmlcov/
    find . -type d -name \"__pycache__\" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name \"*.pyc\" -delete 2>/dev/null || true

build:
    $(PYTHON) -m build