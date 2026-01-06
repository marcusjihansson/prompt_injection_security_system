# Examples

This directory contains example scripts demonstrating how to use the Threat Detection System.

## Available Examples

### 1. Simple Demo (`demo.py`)
Basic demonstration of the threat detection system with common attack patterns.

**Usage:**
```bash
python examples/demo.py
```

**What it demonstrates:**
- Basic threat detection
- System prompt usage
- Simple threat categorization

### 2. Advanced Demo (`advanced_demo.py`)
Comprehensive demonstration with complex attack scenarios and edge cases.

**Usage:**
```bash
python examples/advanced_demo.py
```

**What it demonstrates:**
- Advanced threat patterns
- Complex jailbreak attempts
- Sophisticated prompt injection techniques
- Multi-layered attack scenarios

### 3. Main Entry Point (`../main.py`)
Production-ready example using the Chain of Trust wrapper.

**Usage:**
```bash
python main.py
```

**What it demonstrates:**
- Using `dspy.Trust` wrapper for one-line security
- Integration with DSPy ChainOfThought
- Production configuration

## Configuration

All examples require:
- `OPENROUTER_API_KEY` environment variable set
- Optional: `SYSTEM_PROMPT_PATH` for custom system prompts
- Optional: `ADVANCED_QUERIES_PATH` for custom test queries

See `.env.example` in the project root for all available configuration options.

## Quick Start

1. Copy `.env.example` to `.env` and add your API keys:
   ```bash
   cp .env.example .env
   # Edit .env and add your OPENROUTER_API_KEY
   ```

2. Run the simple demo:
   ```bash
   python examples/demo.py
   ```

3. Try the advanced demo:
   ```bash
   python examples/advanced_demo.py
   ```

## See Also

- [Main README](../README.md) - Project overview and architecture
- [Chain of Trust Documentation](../chain_of_trust/README.md) - Security framework details
- [Production Deployment](../production/README.md) - Production usage guide
- [TypeScript Integration](../cross_language_integrations/ts-integration/README.md) - TypeScript implementation
- [Go Integration](../cross_language_integrations/go-integration/README.md) - Go implementation
- [Cross-Language Integration](../docs/cross-language-integration/README.md) - Full deployment guides
