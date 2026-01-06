# dspy.Trust Security System

A hybrid threat detection system combining regex patterns and DSPy LLM-based detection with multi-layered Chain of Trust security framework.

> **🛍️ Visiting from Shopify?**
>
> Please see the **[Shopify Showcase](Shopify_showcase/SHOWCASE.md)** for a portfolio overview specifically tailored to Engineering at Shopify.

## Quick Start

For Docker deployment, see [deployment/README.md](deployment/README.md)

## Features

- **Input Guard**: DSPy GEPA-optimized detectors for prompt injection detection
- **Output Guard**: Enhanced Llama-Guard-3-1B-INT4 for output safety validation  
- **Multi-layer Detection**: Regex + ML + optimized DSPy detectors
- **Performance Optimized**: LRU cache + semantic cache + request deduplication
- **Comprehensive Security**: 25+ security patterns for comprehensive protection

## Installation

```bash
# Clone the repository
git clone https://github.com/marcusjihansson/prompt_injection_security_system.git
cd dspy-trust

# Install dependencies
pip install -e .

# Run the system
python main.py
```

## Documentation

- [Deployment Guide](deployment/README.md)
- [Quick Start](deployment/QUICKSTART.md)
- [Architecture](deployment/ARCHITECTURE.md)
- [Cross-language Integration](cross_language_integrations/README.md)

## Security

This system provides comprehensive security for LLM applications:
- Prompt injection detection
- Output validation
- Rate limiting
- Authentication
- Input sanitization

## Performance

- 8-15ms average latency
- 95%+ detection accuracy
- Scalable architecture

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for contribution guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.