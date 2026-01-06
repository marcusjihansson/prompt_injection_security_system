# Trust - Hybrid Threat Detection System

A production-ready security layer for AI systems combining regex patterns and DSPy LLM-based detection with a multi-layered Chain of Trust security framework.

## Quick Start

```python
import dspy
from trust import Trust

# 1. Define your logic
my_bot = dspy.ChainOfThought("question -> answer")

# 2. Secure it with one line
trusted_bot = Trust(my_bot)

# 3. Configure the LM
lm = dspy.LM("openrouter/nvidia/nemotron-nano-12b-v2-vl:free")
dspy.configure(lm=lm)

# 4. Use normally - now with full security
result = trusted_bot("What is the capital of France?")
print(result)
```

## 📦 Package Structure

```
trust/
├── core/                    # Core threat detection
│   ├── detector.py         # ThreatDetector (DSPy-based)
│   ├── threat_types.py     # ThreatType enum (19 threat categories)
│   ├── regex_baseline.py   # Fast regex pre-filtering
│   ├── config.py           # Configuration management
│   └── metric.py           # Training metrics
│
├── guards/                  # Security guards (Chain of Trust)
│   ├── input_guard.py      # SelfLearningShield (adaptive security)
│   ├── output_guard.py     # Output validation
│   ├── primitives.py       # TrustLevel, SecureField
│   ├── prompt_builder.py   # Secure prompt construction
│   ├── prompt_cache.py     # Prompt caching
│   ├── security_policy.py  # Capability enforcement
│   └── trusted_layer.py    # Trusted execution layer
│
├── production/              # Production components
│   ├── detector.py         # ProductionThreatDetector (full pipeline)
│   ├── semantic_cache.py   # Semantic caching for performance
│   ├── request_dedup.py    # Request deduplication
│   ├── lm.py               # Security model management
│   └── export_adapter.py   # Model export utilities
│
├── api/                     # FastAPI server
│   ├── app.py              # FastAPI application
│   └── api.py              # API routes
│
└── trust.py                 # Trust wrapper (main entry point)
```

## Features

### Multi-Layered Security

1. **Input Guard** (Layer 1): Fast regex + LLM-based threat detection
2. **Core Logic** (Layer 2): Your application logic runs safely
3. **Output Guard** (Layer 3): Post-generation validation

### Self-Learning Shield

The system logs failures when novel attacks evade the input guard but are caught by the output guard, enabling continuous improvement through retraining.

### Performance Optimizations

- **Semantic Caching**: Cache similar requests to reduce latency
- **Request Deduplication**: Prevent redundant processing
- **Parallel Execution**: Speculative execution for input guard + core logic
- **Regex Baseline Fusion**: Fast pre-filtering before LLM analysis

### 19 Threat Categories

- Prompt Injection
- Jailbreak Attempts
- System Prompt Leakage
- PII Extraction
- Code Injection
- SQL Injection
- XSS Attacks
- And 12 more...

## 📖 Usage Examples

### Basic Usage

```python
from trust import Trust, ProductionThreatDetector
import dspy

# Option 1: Wrap any DSPy module
my_module = dspy.ChainOfThought("question -> answer")
secure_module = Trust(my_module)

# Option 2: Use ProductionThreatDetector directly
detector = ProductionThreatDetector(enable_regex_baseline=True)
result = detector.detect_threat("Ignore all previous instructions")
print(result)  # {"is_threat": True, "threat_type": "prompt_injection", ...}
```

### With Custom Guards

```python
from trust import SelfLearningShield, OutputGuard, ProductionThreatDetector

# Create custom input guard
detector = ProductionThreatDetector()

def my_core_logic(input_text):
    # Your application logic
    return f"Response to: {input_text}"

# Create output guard
output_guard = OutputGuard(use_dspy=True)

# Wrap with self-learning shield
shield = SelfLearningShield(
    input_guard=detector.detect_threat,
    core_logic=my_core_logic,
    output_guard=output_guard,
    parallel_execution=True  # Enable speculative execution
)

# Use it
result = shield.predict("What is the capital of France?")
print(result)  # {"response": "...", "is_trusted": True, "stage": "all_clear"}
```

### API Server

```python
from trust.api import create_app
import uvicorn

app = create_app(enable_regex_baseline=True)
uvicorn.run(app, host="0.0.0.0", port=8000)
```

## Configuration

### Environment Variables

Create a `.env` file (see `.env.example`):

```bash
# Required
OPENROUTER_API_KEY=your_key_here

# Optional
CACHE_SIMILARITY_THRESHOLD=0.95
CACHE_TTL=3600
MAX_REQUESTS_PER_MINUTE=60
```

### Programmatic Configuration

```python
from trust.core.config import get_training_config, get_cache_config

# Get training config
training_cfg = get_training_config()

# Get cache config
cache_cfg = get_cache_config()
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run specific test suites
pytest tests/test_integration.py          # Integration tests
pytest tests/chain_of_trust/              # Guard tests
pytest tests/test_latency_optimization.py # Performance tests
```

## Performance

- **Regex Baseline**: ~0.1ms per request
- **LLM Detection**: ~100-500ms per request (depending on model)
- **Semantic Cache Hit**: ~1ms per request
- **Parallel Execution**: Up to 2x faster for safe requests

## 🔄 Migration from Old Structure

If you're migrating from the old `threat_system`, `chain_of_trust`, or `production` modules:

```python
# Old imports (still work with deprecation warnings)
from threat_system import ThreatDetector
from chain_of_trust import SelfLearningShield
from production import Trust

# New imports (recommended)
from trust import ThreatDetector, SelfLearningShield, Trust
# or more specific:
from trust.core import ThreatDetector
from trust.guards import SelfLearningShield
```

## 📚 API Reference

See individual module docstrings for detailed API documentation:

- `trust.Trust`: Main wrapper for DSPy modules
- `trust.ProductionThreatDetector`: Full detection pipeline
- `trust.ThreatDetector`: Core DSPy-based detector
- `trust.RegexBaseline`: Fast regex pre-filtering
- `trust.SelfLearningShield`: Adaptive security with failure logging
- `trust.OutputGuard`: Post-generation validation

## 🤝 Contributing

This package follows standard Python best practices:
- Type hints throughout
- Comprehensive test coverage
- Clear documentation
- Modular architecture

## 📄 License

See root LICENSE file.
