# Contributing to Threat Detection System

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to this project.

## Development Setup

### Prerequisites
- Python 3.11+
- pip or uv package manager

### Getting Started

1. Clone the repository:
```bash
git clone <repository-url>
cd threat-detection-system
```

2. Install development dependencies:
```bash
make install-dev
```

3. Install pre-commit hooks:
```bash
make pre-commit-install
```

## Code Quality Standards

We maintain high code quality standards using automated tools:

### Formatting
- **Black**: Code formatter with 100 character line length
- **isort**: Import statement organizer

Run formatting:
```bash
make format
```

Check formatting without changes:
```bash
make format-check
```

### Linting
- **Flake8**: Style guide enforcement
- **flake8-docstrings**: Docstring conventions (Google style)
- **flake8-bugbear**: Additional bug and design problems

Run linting:
```bash
make lint
```

### Type Checking
- **mypy**: Static type checking

Run type checking:
```bash
make type-check
```

### Testing
- **pytest**: Test framework
- **pytest-cov**: Coverage reporting
- Target: 75%+ code coverage (aim for 95%+)

Run tests:
```bash
make test
```

Generate coverage report:
```bash
make coverage
```

## Pre-commit Hooks

Pre-commit hooks automatically run before each commit to ensure code quality:

- Trailing whitespace removal
- End-of-file fixer
- YAML/JSON/TOML validation
- Large file check
- Merge conflict detection
- Debug statement detection
- Black formatting
- isort import sorting
- Flake8 linting
- mypy type checking

Install hooks:
```bash
make pre-commit-install
```

Run manually:
```bash
make pre-commit-run
```

## Workflow

### Before Committing

Run all checks:
```bash
make all
```

This will run:
1. Code formatting (black, isort)
2. Linting (flake8)
3. Type checking (mypy)
4. Tests with coverage

### Pull Request Guidelines

1. **Branch naming**: Use descriptive names
   - `feature/add-new-validator`
   - `fix/cache-memory-leak`
   - `docs/update-readme`

2. **Commit messages**: Follow conventional commits
   - `feat: add rate limiting middleware`
   - `fix: resolve cache invalidation bug`
   - `docs: update API documentation`
   - `test: add integration tests for detector`
   - `refactor: simplify guard validation logic`

3. **Code requirements**:
   - All tests must pass
   - Code coverage should not decrease
   - All linting checks must pass
   - Type hints for public APIs
   - Docstrings for public functions/classes (Google style)

4. **PR description**:
   - Clear description of changes
   - Related issue numbers
   - Breaking changes highlighted
   - Testing performed

## Project Structure

```
src/trust/              # Main package
├── core/              # Core detection logic
├── guards/            # Guard implementations
├── validators/        # Threat validators
├── production/        # Production utilities (cache, metrics)
├── pipeline/          # Adaptive pipeline
└── api/               # API server

tests/                 # Test suite
├── guards/           # Guard tests
└── ...

examples/             # Usage examples
docs/                 # Documentation
```

## Testing Guidelines

### Test Organization
- Mirror source structure in tests/
- One test file per source file
- Group related tests in classes

### Test Naming
```python
def test_<function_name>_<scenario>_<expected_result>():
    pass

class TestCacheSystem:
    def test_get_returns_cached_value_when_exists(self):
        pass
    
    def test_get_returns_none_when_cache_miss(self):
        pass
```

### Coverage Guidelines
- Aim for 95%+ coverage
- Test edge cases and error conditions
- Use fixtures for common setup
- Mock external dependencies

## Code Style

### Docstring Format (Google Style)
```python
def function_name(param1: str, param2: int) -> bool:
    """Brief description of function.

    Longer description if needed, explaining the purpose
    and behavior of the function.

    Args:
        param1: Description of param1.
        param2: Description of param2.

    Returns:
        Description of return value.

    Raises:
        ValueError: When param2 is negative.
    """
    pass
```

### Type Hints
```python
from typing import Optional, List, Dict, Any

def process_data(
    data: List[Dict[str, Any]],
    threshold: float = 0.8
) -> Optional[str]:
    """Process data with type hints."""
    pass
```

## Getting Help

- Check existing issues and PRs
- Read the documentation in docs/
- Review examples in examples/
- Ask questions in issue comments

## Code of Conduct

- Be respectful and constructive
- Welcome newcomers
- Focus on the code, not the person
- Assume good intentions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
