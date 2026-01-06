# Architecture Overview

This document describes the overall architecture of the dspy.Trust security system. For Docker-specific deployment architecture, see [deployment/ARCHITECTURE.md](deployment/ARCHITECTURE.md).

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER APPLICATION                               │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                     dspy.Trust(module)                          │  │
│  │              (One-line security wrapper)                         │  │
│  └──────────────────────┬───────────────────────────────────────────┘  │
└─────────────────────────┼───────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   PRODUCTION LAYER (production/)                        │
│                                                                         │
│  ┌─────────────────┐    ┌──────────────────┐   ┌──────────────────┐  │
│  │ Trust Wrapper   │───▶│  Production      │   │  FastAPI         │  │
│  │ (trust_wrapper) │    │  ThreatDetector  │◀──│  API Endpoints   │  │
│  └─────────────────┘    └────────┬─────────┘   └──────────────────┘  │
│                                   │                                     │
│                          ┌────────┼────────┐                           │
│                          ▼        ▼        ▼                           │
│              ┌─────────────┐ ┌─────────┐ ┌─────────────────┐         │
│              │  Semantic   │ │ Request │ │  Security       │         │
│              │  Cache      │ │ Dedup   │ │  Model (Local)  │         │
│              └─────────────┘ └─────────┘ └─────────────────┘         │
└────────────────────────────────┬────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│               CHAIN OF TRUST LAYER (chain_of_trust/)                    │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    Self Learning Shield                        │   │
│  │              (Parallel Execution Coordinator)                   │   │
│  └──────┬────────────────────────────────────────┬─────────────────┘   │
│         │                                        │                     │
│    INPUT GUARD                              OUTPUT GUARD               │
│         │                                        │                     │
│         ▼                                        ▼                     │
│  ┌─────────────┐                         ┌─────────────┐             │
│  │   Prompt    │                         │   Output    │             │
│  │   Builder   │                         │   Guard     │             │
│  └─────────────┘                         └─────────────┘             │
│         │                                        │                     │
│         │                                        │                     │
│  ┌─────────────┐                         ┌─────────────┐             │
│  │   Prompt    │                         │  Security   │             │
│  │   Cache     │                         │  Policy     │             │
│  └─────────────┘                         └─────────────┘             │
│         │                                        │                     │
│         └────────────────┬───────────────────────┘                     │
│                          │                                             │
│                          ▼                                             │
│                 ┌─────────────────┐                                    │
│                 │ Trusted Layer   │                                    │
│                 │ (Core Logic)    │                                    │
│                 └────────┬────────┘                                    │
└──────────────────────────┼──────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                 THREAT SYSTEM LAYER (threat_system/)                    │
│                                                                         │
│  ┌──────────────────┐         ┌────────────────────┐                  │
│  │  Regex Baseline  │────────▶│  Threat Detector   │                  │
│  │  (Fast Filter)   │ Fusion  │  (DSPy/LLM)        │                  │
│  └──────────────────┘         └────────┬───────────┘                  │
│          │                              │                              │
│          │                              │                              │
│          ▼                              ▼                              │
│  ┌──────────────────┐         ┌────────────────────┐                  │
│  │  Regex Patterns  │         │   Threat Types     │                  │
│  │  (JSON Config)   │         │   Enumeration      │                  │
│  └──────────────────┘         └────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  OPTIMIZER LAYER (optimizer/)                           │
│                                                                         │
│  ┌──────────────────┐         ┌────────────────────┐                  │
│  │  GEPA Training   │────────▶│  Model Export      │                  │
│  │  (train_gepa)    │         │  (Optimized)       │                  │
│  └──────────────────┘         └────────────────────┘                  │
│          │                              │                              │
│          ▼                              ▼                              │
│  ┌──────────────────┐         ┌────────────────────┐                  │
│  │  Dataset Loader  │         │  Compiled Models   │                  │
│  │  (threat_types)  │         │  (threat_detector  │                  │
│  │                  │         │   _optimized/)     │                  │
│  └──────────────────┘         └────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Module Dependencies                            │
└─────────────────────────────────────────────────────────────────────────┘

    production/
        ├── depends on: chain_of_trust/
        ├── depends on: threat_system/
        └── provides: Trust, ProductionThreatDetector, API

    chain_of_trust/
        ├── depends on: threat_system/ (for RegexBaseline, ThreatDetector)
        └── provides: Security framework, Guards, Shields

    threat_system/
        ├── depends on: External (dspy, transformers)
        └── provides: Core detection logic

    optimizer/
        ├── depends on: threat_system/
        ├── depends on: threat_types/
        └── provides: Training utilities

    threat_types/
        ├── depends on: threat_system/ (for ThreatType enum)
        └── provides: Dataset loading utilities
```

## Data Flow

### Request Processing Flow

```
1. User Input
   │
   ├─▶ [Trust Wrapper] (production/trust_wrapper.py)
   │
   ├─▶ [Request Deduplication] (production/request_dedup.py)
   │    └─▶ Check if request is duplicate ──▶ Return cached if duplicate
   │
   ├─▶ [Semantic Cache Check] (production/semantic_cache.py)
   │    └─▶ Check similarity ──▶ Return cached if similar
   │
   ├─▶ [Self Learning Shield] (chain_of_trust/self_learning_shield.py)
   │    │
   │    ├─▶ [Parallel Execution]
   │    │    │
   │    │    ├─▶ [Regex Baseline] (threat_system/regex_baseline.py)
   │    │    │    └─▶ Fast pattern matching
   │    │    │
   │    │    └─▶ [Threat Detector] (threat_system/threat_detector.py)
   │    │         └─▶ LLM-based analysis
   │    │
   │    └─▶ [Result Fusion]
   │         └─▶ Combine regex + LLM results
   │
   ├─▶ [Core Logic Execution] (user's DSPy module)
   │
   ├─▶ [Output Guard] (chain_of_trust/output_guard.py)
   │    └─▶ Validate output safety
   │
   └─▶ [Return Result to User]
```

### Training Flow

```
1. Dataset Loading (threat_types/utility.py)
   │
   ├─▶ Load from HuggingFace datasets
   │
   ├─▶ [Create Examples] (threat_types/utility.py)
   │    └─▶ Convert to DSPy format
   │
   ├─▶ [GEPA Training] (optimizer/train_gepa.py)
   │    │
   │    ├─▶ Initialize ThreatDetector
   │    ├─▶ Configure optimizer (GEPA)
   │    └─▶ Train with examples
   │
   └─▶ [Export Model] (threat_detector_optimized/)
        └─▶ Save compiled program
```

## Component Responsibilities

### Production Layer (`production/`)
- **Purpose**: Production-ready deployment and optimization
- **Key Components**:
  - `trust_wrapper.py`: Main API entry point (`dspy.Trust`)
  - `deploy.py`: Production threat detector with caching
  - `semantic_cache.py`: Semantic similarity-based caching
  - `request_dedup.py`: Deduplication to prevent redundant processing
  - `lm.py`: Local security model (Llama-Prompt-Guard)
  - `app/api.py`: FastAPI REST endpoints

### Chain of Trust Layer (`chain_of_trust/`)
- **Purpose**: Multi-layered security framework
- **Key Components**:
  - `trusted_layer.py`: Core trust wrapper with retry logic
  - `self_learning_shield.py`: Adaptive security with parallel execution
  - `output_guard.py`: Output validation and sanitization
  - `prompt_builder.py`: Secure prompt construction
  - `security_policy.py`: Policy enforcement
  - `primitives.py`: Trust levels and secure fields

### Threat System Layer (`threat_system/`)
- **Purpose**: Core threat detection logic
- **Key Components**:
  - `threat_detector.py`: DSPy-based LLM threat detector
  - `regex_baseline.py`: Fast regex pattern matching
  - `threat_types.py`: Threat taxonomy (19 types)
  - `config.py`: Centralized configuration
  - `regex_patterns.json`: Externalized regex patterns

### Optimizer Layer (`optimizer/`)
- **Purpose**: Training and optimization
- **Key Components**:
  - `train_gepa.py`: GEPA training pipeline
  - Dataset loading from `threat_types/`

### Threat Types Layer (`threat_types/`)
- **Purpose**: Dataset management utilities
- **Key Components**:
  - `utility.py`: Dataset loading and example creation

## Performance Optimizations

### Implemented ✅
1. **Semantic Caching**: Cache similar requests
2. **Request Deduplication**: Skip duplicate requests
3. **Parallel Execution**: Run regex + LLM in parallel
4. **Regex Pre-filtering**: Fast pattern matching before LLM
5. **Model Compilation**: DSPy GEPA optimization
6. **Lazy Loading**: Models loaded on-demand

### Planned 🔄
1. Multi-tier caching (memory + Redis)
2. Batch processing for API
3. Model quantization
4. Streaming responses
5. CDN integration

## Security Layers

### Defense in Depth
1. **Input Layer**: Regex baseline + prompt injection detection
2. **Processing Layer**: LLM-based threat analysis
3. **Output Layer**: Output guard validation
4. **Logging Layer**: Failure tracking for retraining

### Threat Coverage
- ✅ Prompt Injection
- ✅ Jailbreak Attempts
- ✅ SQL Injection
- ✅ XSS (Cross-Site Scripting)
- ✅ Code Injection
- ✅ Path Traversal
- ✅ Command Injection
- ✅ Data Exfiltration
- ✅ PII Leakage
- ✅ And 10 more threat types...

## Integration Points

### DSPy Integration
```python
import dspy
from production import Trust

# Wrap any DSPy module
my_bot = dspy.ChainOfThought("question -> answer")
trusted_bot = dspy.Trust(my_bot)
```

### REST API Integration
```bash
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "Test input"}'
```

### Python Library Integration
```python
from threat_system import ThreatDetector, RegexBaseline
from chain_of_trust import SelfLearningShield

# Direct usage
detector = ThreatDetector()
result = detector.forward(text="Test input")
```

## Configuration Management

### Environment Variables
All configuration via `.env` file:
- API keys (OPENROUTER_API_KEY)
- Training parameters (MAX_PROMPT_INJECTION, etc.)
- System paths (SYSTEM_PROMPT_PATH, etc.)

### Runtime Configuration
Centralized in `threat_system/config.py`:
- Model configuration
- Security settings
- Training parameters
- Dataset configuration

## Testing Strategy

### Test Layers
1. **Unit Tests**: Individual component testing (`tests/`)
2. **Integration Tests**: End-to-end pipeline testing (`tests/test_integration.py`)
3. **Performance Tests**: Latency benchmarks (`tests/test_latency*.py`)
4. **Demo Scripts**: Manual validation (`examples/`)

### CI/CD Pipeline
GitHub Actions workflow (`.github/workflows/ci.yml`):
- Lint checks
- Unit tests
- Integration tests
- Type checking

## Docker Deployment Architecture

For detailed Docker deployment architecture including:
- Container architecture diagram
- Detection flow within containers
- Performance characteristics
- Scaling strategies
- Monitoring and observability

**See**: [deployment/ARCHITECTURE.md](deployment/ARCHITECTURE.md)

### Quick Docker Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                        User Applications                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Python     │  │ JavaScript/  │  │     Go       │           │
│  │   Client     │  │  TypeScript  │  │   Client     │  ...      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
└─────────┼──────────────────┼──────────────────┼────────────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Load Balancer  │ (optional)
                    │     (Nginx)     │
                    └────────┬────────┘
                             │
           ┌──────────────────┴──────────────────┐
           │                                     │
   ┌─────────▼─────────┐              ┌─────────▼─────────┐
   │ dspy-trust-1      │              │ dspy-trust-2      │
   │ (Docker Container)│              │ (Docker Container)│
   └───────────────────┘              └───────────────────┘
```

## Deployment Options

### Docker Deployment
```bash
docker build -t threat-detection .
docker run -p 8000:8000 threat-detection
```

**See**: [deployment/README.md](deployment/README.md) for full Docker deployment guide.

### API Server
```bash
uvicorn production.app.api:app --host 0.0.0.0 --port 8000
```

### Library Usage
```bash
pip install -e .
```

## Monitoring and Observability

### Logging
- Structured logging with `structlog`
- Failure tracking in `SelfLearningShield`
- Production failure logs in `failures_production.json`

### Metrics (Planned)
- Request latency
- Cache hit rates
- Threat detection accuracy
- False positive/negative rates

## Future Enhancements

1. **Real-time Retraining**: Automatic model updates from logged failures
2. **Multi-model Ensemble**: Combine multiple detection models
3. **Active Learning**: User feedback loop for improved accuracy
4. **Distributed Deployment**: Horizontal scaling support
5. **Advanced Analytics**: Threat trend analysis and reporting
