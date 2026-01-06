.PHONY: help install install-dev test lint format type-check coverage clean pre-commit-install pre-commit-run all

help:
	@echo "Available commands:"
	@echo "  make install          - Install production dependencies"
	@echo "  make install-dev      - Install development dependencies"
	@echo "  make test             - Run tests with coverage"
	@echo "  make lint             - Run all linters (flake8)"
	@echo "  make format           - Format code with black and isort"
	@echo "  make format-check     - Check code formatting without changes"
	@echo "  make type-check       - Run type checking with mypy"
	@echo "  make coverage         - Generate coverage report"
	@echo "  make pre-commit-install - Install pre-commit hooks"
	@echo "  make pre-commit-run   - Run pre-commit on all files"
	@echo "  make clean            - Clean generated files"
	@echo "  make all              - Run format, lint, type-check, and test"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest

lint:
	flake8 src tests examples

format:
	isort src tests examples
	black src tests examples

format-check:
	isort --check-only src tests examples
	black --check src tests examples

type-check:
	mypy src

coverage:
	pytest --cov=src/trust --cov-report=html --cov-report=term-missing
	@echo "Coverage report generated in htmlcov/index.html"

pre-commit-install:
	pre-commit install

pre-commit-run:
	pre-commit run --all-files

clean:
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

all: format lint type-check test
	@echo "✓ All checks passed!"
